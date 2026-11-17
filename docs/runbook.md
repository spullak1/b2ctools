# Operational Runbook

## Common Tasks

### Verify App Registration

Check:

- Redirect URIs
- Post Logout URLs
- API Permissions

Portal:

```text
Entra Admin Center
→ App Registrations
→ Authentication
```

---

### Validate User Flow

Verify:

- Sign In
- Sign Up
- Password Reset

---

### Decode Token

Use:

```text
tools/token-decoder
```

Review:

- issuer
- audience
- policy
- objectId
- groups

---

### Troubleshooting Login Issues

Check:

1. Redirect URI configured
2. App registration enabled
3. User flow assigned
4. Identity provider available
5. Browser network trace

---

### Emergency Contact

| Service | Contact |
|----------|----------|
| Entra ID Team | B2C Support |
| Application Team | Application Owner |
