# Certificate Creation

The `appviewx_create_certificate` resource follows a structured flow to create and manage certificates using the AppViewX platform. 

## Process Overview

1. **Input Parameters**:
   - The resource accepts various input parameters such as `common_name`, `organization`, `organizational_unit`, `country`, `state`, `locality`, `validity_unit`, `key_algorithm`, and more. These parameters define the attributes of the certificate to be created.

2. **Certificate Creation**:
   - When the resource is applied, the certificate creation process is initiated. The resource sends a request to the AppViewX API with the provided parameters to generate the certificate.

3. **Synchronous vs Asynchronous Mode**:
   - If `is_sync` is set to `true`, the certificate is created in synchronous mode, and the certificate is downloaded immediately after creation.
   - If `is_sync` is set to `false`, the certificate is created in asynchronous mode, and the resource ID is returned for later use in downloading the certificate.

4. **Certificate Download**:
   - The certificate can be downloaded to a specified path using the `certificate_download_path` attribute. The format of the downloaded certificate is defined by `certificate_download_format` (e.g., `P12`, `PEM`).
   - If `certificate_chain_required` is set to `true`, the certificate chain is included in the download.

5. **Private Key Download**:
   - If `key_download_path` is specified, the private key associated with the certificate is downloaded to the given path. The key can be password-protected using the `key_download_password` attribute.

6. **Custom and Vendor-Specific Fields**:
   - The resource supports adding custom fields (`custom_fields`) and vendor-specific fields (`vendor_specific_fields`) to include additional metadata or configurations required by the Certificate Authority.

7. **Certificate Grouping**:
   - Certificates can be grouped using the `certificate_group_name` attribute, where the certificates will be placed in AppViewX Certificate Inventory.


## Attributes

The `appviewx_create_certificate` resource supports the following attributes:

### Required Attributes

- **`common_name`** (string): The domain name or identifier for the certificate.
- **`organization`** (string): The name of the organization requesting the certificate.
- **`organizational_unit`** (string): The organizational unit or department.
- **`country`** (string): The two-letter country code.
- **`state`** (string): The state or province name.
- **`locality`** (string): The city or locality name.
- **`validity_unit`** (string): The unit of validity for the certificate.
- **`validity_unit_value`** (integer): The value for the validity unit.
- **`key_algorithm`** (string): The cryptographic algorithm for the key.
- **`key_size`** (integer): The size of the key in bits.
- **`certificate_authority`** (string): The name of the Certificate Authority (CA) to issue the certificate.
- **`ca_setting_name`** (string): The specific CA setting to use for certificate issuance.

### Optional Attributes

- **`certificate_type`** (string): The type of certificate based on the Certificate Authorit.
- **`dns_names`** (list of strings): Additional DNS names to include in the certificate.
- **`custom_fields`** (map): Custom fields to include in the certificate request.
- **`vendor_specific_fields`** (map): Vendor-specific fields for additional configurations.
- **`certificate_group_name`** (string): The name of the group to which the certificate belongs in AppViewX, deafults to **Default** certificate group in AppViewX.
- **`is_sync`** (boolean): Whether the certificate creation is synchronous (`true`) or asynchronous (`false`).
- **`certificate_download_path`** (string): The file path to download the certificate.
- **`certificate_download_format`** (string): The format of the downloaded certificate.
- **`certificate_download_password`** (string): The password for the downloaded certificate file.
- **`certificate_chain_required`** (boolean): Whether to include the certificate chain in the download.
- **`key_download_path`** (string): The file path to download the private key.
- **`key_download_password`** (string): The password for the downloaded private key.
- **`download_password_protected_key`** (boolean): Whether the private key should be password-protected.

## Example Usage

### Certificate Creation In Synchronous Mode
```hcl
resource "appviewx_create_certificate" "createcert" {
   common_name                = "sampe.example.com"
   hash_function              = "SHA256"
   key_type                   = "RSA"
   bit_length                 = "2048"
   certificate_authority      = "Certificate Authority"
   ca_setting_name            = "Appviewx CA Setting Name"
   certificate_type           = "EliteSSL Certificate"
   dns_names                  = ["example.com", "example123.com"]
   custom_fields              = { "field_name" = "value" }
   vendor_specific_fields     = { "field_name" = "value" }
   validity_unit              = "years"
   validity_unit_value        = 2
   certificate_group_name     = "AppViewX Certificate Group Name"
   certificate_download_path  = "/path/to/directory"
   certificate_download_format = "P12"
   certificate_download_password = "password"
   certificate_chain_required = true
   key_download_path          = "/path/to/directory"
   key_download_password      = "password"
   download_password_protected_key = false
   is_sync                    = true
}
```

### Certificate Creation In Asynchronous Mode
```hcl
resource "appviewx_create_certificate" "createcert" {
   common_name                = "sampe.example.com"
   hash_function              = "SHA256"
   key_type                   = "RSA"
   bit_length                 = "2048"
   certificate_authority      = "Certificate Authority"
   ca_setting_name            = "Appviewx CA Setting Name"
   certificate_type           = "EliteSSL Certificate"
   dns_names                  = ["example.com", "example123.com"]
   custom_fields              = { "field_name" = "value" }
   vendor_specific_fields     = { "field_name" = "value" }
   validity_unit              = "years"
   validity_unit_value        = 2
   certificate_group_name     = "AppViewX Certificate Group Name"
   is_sync                    = false
}

resource "time_sleep" "wait" {
   depends_on      = [appviewx_create_certificate.createcert]
   create_duration = "10s"
}

resource "appviewx_download_certificate" "downloadcert" {
   depends_on                  = [time_sleep.wait]
   resource_id                 = appviewx_create_certificate.createcert.resource_id
   certificate_download_path   = "/path/to/directory"
   certificate_download_format = "P12"
   certificate_download_password = "password"
   certificate_chain_required  = true
   key_download_path           = "/path/to/directory"
   key_download_password       = "password"
   download_password_protected_key = false
}
```

## Import

To import an existing certificate into the Terraform state, use the following command:

```bash
terraform import appviewx_create_certificate.createcert <resource_id>
```
Replace `<resource_id>` with the actual resource ID of the certificate you want to import.