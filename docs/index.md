# AppViewX Terraform Provider

[AppViewX](https://appviewx.com) protects many of the world’s brands with the industry’s most advanced cloud-native Certificate Lifecycle Management (CLM) and Public Key Infrastructure (PKI) platform. Our solutions safeguard customers and enable digital transformation in the largest and most security-conscious enterprise organizations globally.

**AVX ONE** is the industry’s most advanced and fastest growing cloud-native Certificate Lifecycle Management (CLM) platform. It provides a suite of market leading capabilities including Smart Discovery, Crypto Resilience Scorecard, Closed-looped Automation and Infrastructure Context Awareness.

Powered by the market’s only out-of-the-box workflow engine, AVX ONE allows customers to realize immediate value from complete certificate lifecycle management, enterprise-wide Kubernetes TLS automation, scalable PKI-as-a-Service, secure code signing, easy Microsoft CA migration, IoT security, SSH and key management, and PQC-forward controls in even the most complex multi-cloud, hybrid, and edge environments.

Seamlessly enforce enterprise policies and strict access controls, ensure cryptographic agility, and prevent attacks that exploit expired, rogue, and non-compliant digital certificate identities.

AppViewX Terraform Provider allows you to manage certificates using the AppViewX platform. This provider enables certificate creation and download through Terraform configurations.

## Requirements

- Terraform 1.0 or later
- AppViewX Service Account Credentials
- Configurations in AppViewX like Certificate Authority, Certificate Group, and Policy.

## Installation

1. Download the `terraform-provider-appviewx` binary.
2. Place the binary in your Terraform plugins directory.
3. Configure the provider in your Terraform configuration file.

## Provider Configuration

```hcl
provider "appviewx" {
    appviewx_client_id="clientid"
    appviewx_client_secret="clientsecret"
    appviewx_environment_is_https=true
    appviewx_environment_ip="appviewx_environment_ip/fqdn"
    appviewx_environment_port="appviewx_port"
}
```

## Atrributes

- `appviewx_client_id`: The client ID used to authenticate with the AppViewX API. This is provided by your AppViewX administrator.
- `appviewx_client_secret`: The client secret associated with the client ID. This is used for secure authentication and must be kept confidential.
- `appviewx_environment_is_https`: A boolean value indicating whether the AppViewX environment uses HTTPS. Set this to `true` if your environment is secured with HTTPS.
- `appviewx_environment_ip`: The IP address or fully qualified domain name (FQDN) of the AppViewX environment. This specifies the endpoint for API communication.
- `appviewx_environment_port`: The port number used to connect to the AppViewX environment. Ensure this matches the port configured for API access.

## Support
For support, please contact [AppViewX Support](https://www.appviewx.com/support).

## Certificate Management

The AppViewX Terraform Provider simplifies certificate management by enabling seamless integration with the AppViewX platform. Using this provider, you can automate the creation and retrieval of certificates, ensuring secure and efficient workflows for your infrastructure.

Below are the available certificate management operations:
- [Create Certificate](./Create_Certificate/index.md)
- [Download Certificate](./Download_Certificate/index.md)