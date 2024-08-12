# SAML Signer

This project provides functionality to sign SAML responses, offering options to sign the assertion, the message, or both.

## Installation

1. Clone this repository:
   ```
   git clone git@github.com:anrbn/saml-signer.git
   cd saml-signer
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

Run the main script with the following syntax:

```
python main.py <key_path> <cert_path> [--sign-message] [--input-file <input_file_path>]
```

Arguments:
- `key_path`: Path to the private key file
- `cert_path`: Path to the X.509 certificate file
- `--sign-message`: Sign the entire SAML Response
- `--input-file`: (Optional) Path to JSON file containing input values

### Using the --input-file Option

Instead of manually inputting field values, you can provide a JSON file with the required information. Use the `values.json` file:

```json
{
    "UserPrincipalName": "user@example.com",
    "TenantID": "your-tenant-id",
    "ObjectID": "user-object-id",
    "DisplayName": "John Doe",
    "FirstName": "John",
    "LastName": "Doe",
    "Email": "john.doe@example.com"
}
```

Then, run the script with the `--input-file` option:

```
python main.py key.pem cert.pem --sign-message --input-file values.json
```

This will use the values from the JSON file instead of prompting for user input.

## Examples

1. Sign the message:
   ```
   python main.py key.pem cert.pem --sign-message
   ```

2. Use an input file:
   ```
   python main.py key.pem cert.pem --sign-message --input-file values.json
   ```

## License

This project is licensed under the MIT License - see the LICENSE file for details.
