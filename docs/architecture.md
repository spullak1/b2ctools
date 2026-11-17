# Architecture

## Purpose

The B2C Tools repository provides administrative and operational support for Microsoft Entra External ID (Azure AD B2C).

## High-Level Architecture

```text
Application
    │
    ▼
Entra External ID (B2C)
    │
    ▼
Identity Providers
    ├── Entra ID
    ├── Social Accounts
    └── Federated IdPs
```

## Components

### Claims Viewer

Used to inspect claims issued by user flows and custom policies.

### App Registration Audit

Reviews:

- Redirect URIs
- Logout URLs
- API Permissions
- Secrets & Certificates

### Token Decoder

Decodes:

- ID Tokens
- Access Tokens
- Refresh Tokens (metadata only)

### Policy Validator

Verifies:

- XML schema compliance
- Claims transformations
- Technical profiles

## Security Considerations

- Never commit secrets
- Use certificate credentials whenever possible
- Store sensitive values in Key Vault
