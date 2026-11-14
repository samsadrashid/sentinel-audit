// Design A feasibility probe (TEST ONLY). Tries to create a Secure Enclave key as a data-protection
// keychain item in an access group, from whatever code identity this binary has. Creation needs no
// user presence. If creation unexpectedly succeeds, the item is deleted immediately.
// Usage: dp_probe <access-group> <tag>
import Foundation
import Security

let a = CommandLine.arguments
guard a.count == 3 else { print("{\"error\":\"usage\"}"); exit(2) }
let group = a[1], tag = a[2].data(using: .utf8)!
var e: Unmanaged<CFError>?
let ac = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                         [.privateKeyUsage, .biometryCurrentSet], &e)!
let attrs: [String: Any] = [
    kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
    kSecAttrKeySizeInBits as String: 256,
    kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
    kSecUseDataProtectionKeychain as String: true,
    kSecPrivateKeyAttrs as String: [
        kSecAttrIsPermanent as String: true,
        kSecAttrApplicationTag as String: tag,
        kSecAttrAccessGroup as String: group,
        kSecAttrAccessControl as String: ac,
    ] as [String: Any],
]
var err: Unmanaged<CFError>?
let key = SecKeyCreateRandomKey(attrs as CFDictionary, &err)
var res: [String: Any] = ["group": group, "created": key != nil]
if let er = err?.takeRetainedValue() {
    res["error_domain"] = CFErrorGetDomain(er) as String
    res["error_code"] = CFErrorGetCode(er)
    res["error"] = CFErrorCopyDescription(er) as String
}
if key != nil {
    let q: [String: Any] = [kSecClass as String: kSecClassKey, kSecAttrApplicationTag as String: tag,
                            kSecUseDataProtectionKeychain as String: true, kSecAttrAccessGroup as String: group]
    res["cleanup_status"] = SecItemDelete(q as CFDictionary)
}
// Also try a lookup in the group (expected: nothing visible to an unentitled caller).
let q2: [String: Any] = [kSecClass as String: kSecClassKey, kSecAttrApplicationTag as String: tag,
                         kSecUseDataProtectionKeychain as String: true, kSecAttrAccessGroup as String: group,
                         kSecReturnRef as String: true]
var item: CFTypeRef?
res["lookup_status"] = SecItemCopyMatching(q2 as CFDictionary, &item)
let d = try! JSONSerialization.data(withJSONObject: res, options: [.sortedKeys])
print(String(data: d, encoding: .utf8)!)
