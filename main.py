import argparse
from src.saml_signer import SAMLSigner
from src.utils import get_field_values_from_file, get_field_values_from_user

def main():
    parser = argparse.ArgumentParser(description="Sign a SAML Response XML")
    parser.add_argument("key_path", help="Path to the private key file")
    parser.add_argument("cert_path", help="Path to the X.509 certificate file")
    parser.add_argument("--sign-message", action="store_true", help="Sign the entire SAML Response")
    parser.add_argument("--input-file", help="Path to JSON file containing input values")

    args = parser.parse_args()

    signer = SAMLSigner(args.key_path, args.cert_path)

    input_string = input("[+] Input Encoded String: ")
    print("---------------------------")

    xml_string = signer.decode_input_string(input_string)

    if args.input_file:
        field_values = get_field_values_from_file(args.input_file)
    else:
        field_values = get_field_values_from_user()

    print("---------------------------")

    updated_xml = signer.update_fields_in_xml(xml_string, field_values)
    signed_xml = signer.sign_saml_response(updated_xml, sign_message=args.sign_message)

    if signed_xml:
        output_string = signer.encode_output_string(signed_xml)
        print("[+] Output Encoded String: ")
        print(output_string)
    else:
        print("Failed to sign and encode the SAML response.")

if __name__ == "__main__":
    main()