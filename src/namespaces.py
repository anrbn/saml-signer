from xml.etree import ElementTree as ET

NSMAP = {
    'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
    'saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
    'ds': 'http://www.w3.org/2000/09/xmldsig#'
}

for prefix, uri in NSMAP.items():
    ET.register_namespace(prefix, uri)