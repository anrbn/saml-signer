import json

def get_field_values_from_file(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

def get_field_values_from_user():
    print("[+] Fields to change")
    return {
        'UserPrincipalName': input("UserPrincipalName (modifies <saml:Subject><saml:NameID>): "),
        'TenantID': input("TenantID: "),
        'ObjectID': input("ObjectID: "),
        'DisplayName': input("DisplayName: "),
        'FirstName': input("FirstName: "),
        'LastName': input("LastName: "),
        'Email': input("Email: ")
    }