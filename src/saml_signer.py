import base64
import hashlib
import urllib.parse
from xml.etree import ElementTree as ET
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
from .namespaces import NSMAP

class SAMLSigner:
    def __init__(self, key_path, cert_path):
        self.private_key = self._load_private_key(key_path)
        self.cert = self._load_certificate(cert_path)

    def _load_private_key(self, key_path):
        with open(key_path, 'rb') as key_file:
            return load_pem_private_key(key_file.read(), password=None, backend=default_backend())

    def _load_certificate(self, cert_path):
        with open(cert_path, 'rb') as cert_file:
            return base64.b64encode(cert_file.read()).decode('utf-8')

    def c14n(self, element):
        return ET.canonicalize(ET.tostring(element, encoding='utf-8'), strip_text=True)

    def sign_xml_element(self, element):
        signature = ET.Element(f"{{{NSMAP['ds']}}}Signature")
        signed_info = ET.SubElement(signature, f"{{{NSMAP['ds']}}}SignedInfo")
        ET.SubElement(signed_info, f"{{{NSMAP['ds']}}}CanonicalizationMethod", Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#")
        ET.SubElement(signed_info, f"{{{NSMAP['ds']}}}SignatureMethod", Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
        reference = ET.SubElement(signed_info, f"{{{NSMAP['ds']}}}Reference", URI=f"#{element.get('ID')}")
        transforms = ET.SubElement(reference, f"{{{NSMAP['ds']}}}Transforms")
        ET.SubElement(transforms, f"{{{NSMAP['ds']}}}Transform", Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature")
        ET.SubElement(transforms, f"{{{NSMAP['ds']}}}Transform", Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#")
        ET.SubElement(reference, f"{{{NSMAP['ds']}}}DigestMethod", Algorithm="http://www.w3.org/2001/04/xmlenc#sha256")
        digest_value = ET.SubElement(reference, f"{{{NSMAP['ds']}}}DigestValue")

        canonical_element = self.c14n(element)
        digest = hashlib.sha256(canonical_element.encode('utf-8')).digest()
        digest_value.text = base64.b64encode(digest).decode('utf-8')

        canonical_signed_info = self.c14n(signed_info)
        signature_value = self.private_key.sign(
            canonical_signed_info.encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        ET.SubElement(signature, f"{{{NSMAP['ds']}}}SignatureValue").text = base64.b64encode(signature_value).decode('utf-8')

        key_info = ET.SubElement(signature, f"{{{NSMAP['ds']}}}KeyInfo")
        x509_data = ET.SubElement(key_info, f"{{{NSMAP['ds']}}}X509Data")
        ET.SubElement(x509_data, f"{{{NSMAP['ds']}}}X509Certificate").text = self.cert

        return signature

    def decode_input_string(self, input_string):
        url_decoded = urllib.parse.unquote(input_string)
        return base64.b64decode(url_decoded).decode('utf-8')

    def encode_output_string(self, xml_string):
        base64_encoded = base64.b64encode(xml_string.encode('utf-8')).decode('utf-8')
        return urllib.parse.quote(base64_encoded)

    def update_fields_in_xml(self, xml_string, field_values):
        root = ET.fromstring(xml_string)
        
        name_id = root.find(f".//{{{NSMAP['saml']}}}Subject/{{{NSMAP['saml']}}}NameID")
        if name_id is not None:
            name_id.text = field_values['UserPrincipalName']
        
        attribute_map = {
            'http://schemas.microsoft.com/identity/claims/tenantid': 'TenantID',
            'http://schemas.microsoft.com/identity/claims/objectidentifier': 'ObjectID',
            'http://schemas.microsoft.com/identity/claims/displayname': 'DisplayName',
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname': 'FirstName',
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname': 'LastName',
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress': 'Email',
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name': 'UserPrincipalName'
        }
        
        for attribute in root.findall(f".//{{{NSMAP['saml']}}}Attribute"):
            name = attribute.get('Name')
            if name in attribute_map:
                field_name = attribute_map[name]
                attribute_value = attribute.find(f"{{{NSMAP['saml']}}}AttributeValue")
                if attribute_value is not None:
                    attribute_value.text = field_values[field_name]
        
        return ET.tostring(root, encoding='unicode')

    def sign_saml_response(self, xml_string, sign_message=False):
        try:
            root = ET.fromstring(xml_string)

            for signature in root.findall(f".//{{{NSMAP['ds']}}}Signature"):
                parent = root.find(f".//{{{NSMAP['saml']}}}Issuer/..")
                if parent is not None:
                    parent.remove(signature)

            if sign_message:
                signature = self.sign_xml_element(root)
                issuer = root.find(f".//{{{NSMAP['saml']}}}Issuer")
                if issuer is not None:
                    root.insert(list(root).index(issuer) + 1, signature)
                else:
                    root.insert(0, signature)

            return ET.tostring(root, encoding='unicode')

        except Exception as e:
            print(f"Error: {e}")
            return None