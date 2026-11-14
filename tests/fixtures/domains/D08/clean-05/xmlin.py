import lxml.etree

def parse(b):
    return lxml.etree.fromstring(b, lxml.etree.XMLParser(resolve_entities=False, no_network=True))
