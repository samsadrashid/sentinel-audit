"""Bounded decoder for Android binary XML (AXML), stdlib only.

Used inside the B2 container to turn a compiled `AndroidManifest.xml` (or a compiled `res/xml/*.xml`)
back into text XML so that the existing Android analyzer rules apply. It is a structural parser: it
never evaluates anything, and every offset and count is bounds-checked. Malformed input raises
`ValueError`.
"""

from __future__ import annotations

import struct
from xml.sax.saxutils import escape, quoteattr

RES_XML = 0x0003
STRING_POOL = 0x0001
RESOURCE_MAP = 0x0180
NS_START = 0x0100
NS_END = 0x0101
ELEM_START = 0x0102
ELEM_END = 0x0103
CDATA = 0x0104
UTF8_FLAG = 0x100
ANDROID_NS = "http://schemas.android.com/apk/res/android"
MAX_STRINGS = 200_000
MAX_ELEMENTS = 200_000
MAX_DEPTH = 64
#: Well-known framework attribute resource IDs, used only when an attribute's name string is empty.
ATTR_IDS = {
    0x01010003: "name",
    0x01010006: "permission",
    0x0101000F: "debuggable",
    0x01010010: "exported",
    0x0101020C: "minSdkVersion",
    0x01010280: "allowBackup",
    0x010104EC: "usesCleartextTraffic",
}


def _u(fmt: str, b: bytes, off: int) -> tuple[int, ...]:
    if off < 0 or off + struct.calcsize(fmt) > len(b):
        raise ValueError("AXML truncated")
    return struct.unpack_from(fmt, b, off)


def _len8(b: bytes, p: int) -> tuple[int, int]:
    (n,) = _u("<B", b, p)
    if n & 0x80:
        (n2,) = _u("<B", b, p + 1)
        return ((n & 0x7F) << 8) | n2, p + 2
    return n, p + 1


def _len16(b: bytes, p: int) -> tuple[int, int]:
    (n,) = _u("<H", b, p)
    if n & 0x8000:
        (n2,) = _u("<H", b, p + 2)
        return ((n & 0x7FFF) << 16) | n2, p + 4
    return n, p + 2


def string_pool(b: bytes, off: int, size: int) -> list[str]:
    _t, hsz, _s = _u("<HHI", b, off)
    count, _styles, flags, strings_start, _styles_start = _u("<IIIII", b, off + 8)
    if count > MAX_STRINGS:
        raise ValueError("AXML string pool too large")
    end = off + size
    offsets = _u(f"<{count}I", b, off + hsz) if count else ()
    base = off + strings_start
    out = []
    for o in offsets:
        p = base + o
        if p >= end:
            raise ValueError("AXML string offset outside pool")
        if flags & UTF8_FLAG:
            _chars, p = _len8(b, p)
            n, p = _len8(b, p)
            if p + n > end:
                raise ValueError("AXML string outside pool")
            out.append(b[p : p + n].decode("utf-8", "replace"))
        else:
            n, p = _len16(b, p)
            if p + 2 * n > end:
                raise ValueError("AXML string outside pool")
            out.append(b[p : p + 2 * n].decode("utf-16-le", "replace"))
    return out


def _value(strings: list[str], raw: int, dtype: int, data: int) -> str:
    if dtype == 0x03 and 0 <= raw < len(strings):
        return strings[raw]
    if dtype == 0x03 and 0 <= data < len(strings):
        return strings[data]
    if dtype == 0x12:
        return "true" if data else "false"
    if dtype == 0x10:
        return str(data - (1 << 32) if data & 0x80000000 else data)
    if dtype == 0x11:
        return f"0x{data:08x}"
    if dtype in (0x01, 0x02):
        return f"@0x{data:08x}"
    if 0 <= raw < len(strings):
        return strings[raw]
    return str(data)


def decode(b: bytes) -> str:
    """Return text XML for an AXML document. Raises ValueError for anything malformed."""
    t, hsz, size = _u("<HHI", b, 0)
    if t != RES_XML or hsz < 8 or size > len(b) or size < 8:
        raise ValueError("not an AXML document")
    strings: list[str] = []
    resmap: tuple[int, ...] = ()
    prefixes: dict[str, str] = {}
    out: list[str] = []
    depth = elements = 0
    off = hsz
    while off + 8 <= size:
        ctype, chsz, csize = _u("<HHI", b, off)
        if csize < 8 or chsz < 8 or off + csize > size:
            raise ValueError("AXML chunk outside document")
        if ctype == STRING_POOL:
            strings = string_pool(b, off, csize)
        elif ctype == RESOURCE_MAP:
            resmap = _u(f"<{(csize - chsz) // 4}I", b, off + chsz)
        elif ctype == NS_START:
            prefix_i, uri_i = _u("<ii", b, off + chsz)
            if 0 <= uri_i < len(strings) and 0 <= prefix_i < len(strings):
                prefixes[strings[uri_i]] = strings[prefix_i]
        elif ctype == ELEM_START:
            elements += 1
            depth += 1
            if elements > MAX_ELEMENTS or depth > MAX_DEPTH:
                raise ValueError("AXML element limit")
            _ns, name, astart, asize, acount = _u("<iiHHH", b, off + chsz)
            if not 0 <= name < len(strings) or asize < 20:
                raise ValueError("AXML element name or attribute size invalid")
            attrs = []
            for i in range(acount):
                a = off + chsz + astart + i * asize
                if a + 20 > off + csize:
                    raise ValueError("AXML attribute outside chunk")
                ans, aname, araw = _u("<iii", b, a)
                _vsize, _res0, dtype, data = _u("<HBBI", b, a + 12)
                key = strings[aname] if 0 <= aname < len(strings) else ""
                if not key and 0 <= aname < len(resmap):
                    key = ATTR_IDS.get(resmap[aname], f"attr_{resmap[aname]:08x}")
                if not key:
                    continue
                uri = strings[ans] if 0 <= ans < len(strings) else ""
                if uri:
                    key = f"{prefixes.get(uri, 'android' if uri == ANDROID_NS else 'ns')}:{key}"
                attrs.append(f" {key}={quoteattr(_value(strings, araw, dtype, data))}")
            if elements == 1:
                attrs.insert(0, f' xmlns:android="{ANDROID_NS}"')
            out.append(f"<{strings[name]}{''.join(attrs)}>")
        elif ctype == ELEM_END:
            _ns, name = _u("<ii", b, off + chsz)
            if not 0 <= name < len(strings) or depth == 0:
                raise ValueError("AXML unbalanced element")
            depth -= 1
            out.append(f"</{strings[name]}>")
        elif ctype == CDATA:
            (idx,) = _u("<i", b, off + chsz)
            if 0 <= idx < len(strings):
                out.append(escape(strings[idx]))
        off += csize
    if depth != 0 or elements == 0:
        raise ValueError("AXML document incomplete")
    return '<?xml version="1.0" encoding="utf-8"?>' + "".join(out)
