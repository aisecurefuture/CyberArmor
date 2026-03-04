# AIShields Identity Provider Service

Pluggable identity provider integration for enterprise SSO and access management.

## Supported Providers

| Provider | Module | Protocols |
|----------|--------|-----------|
| Microsoft Entra ID | `entra.py` | OAuth 2.0 / OIDC |
| Okta | `okta.py` | OAuth 2.0 / OIDC |
| Ping Identity | `ping.py` | OAuth 2.0 / OIDC |
| AWS IAM | `aws_iam.py` | STS / SigV4 |

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/auth/login` | Initiate SSO login flow |
| POST | `/auth/callback` | Handle OAuth callback |
| POST | `/auth/token/validate` | Validate access token |
| GET | `/auth/userinfo` | Get current user info |
| POST | `/auth/logout` | Terminate session |
| GET | `/providers` | List configured providers |
| POST | `/providers/{name}/configure` | Configure a provider |
| GET | `/health` | Health check |

## Setup

### Microsoft Entra ID

See [Azure App Registration Guide](../../docs/azure-app-registration.md) for detailed setup.

```env
IDENTITY_PROVIDER=entra
ENTRA_TENANT_ID=your-tenant-id
ENTRA_CLIENT_ID=your-client-id
ENTRA_CLIENT_SECRET=your-client-secret
```

### Okta

```env
IDENTITY_PROVIDER=okta
OKTA_DOMAIN=your-domain.okta.com
OKTA_CLIENT_ID=your-client-id
OKTA_CLIENT_SECRET=your-client-secret
```

### Ping Identity

```env
IDENTITY_PROVIDER=ping
PING_ISSUER=https://auth.pingone.com/environment-id/as
PING_CLIENT_ID=your-client-id
PING_CLIENT_SECRET=your-client-secret
```

### AWS IAM

```env
IDENTITY_PROVIDER=aws_iam
AWS_REGION=us-east-1
AWS_ROLE_ARN=arn:aws:iam::123456789012:role/AIShieldsRole
```

## Running

```bash
pip install fastapi uvicorn httpx
uvicorn main:app --host 0.0.0.0 --port 8004
```

## Adding Custom Providers

Extend the `IdentityProvider` base class:

```python
from providers.base import IdentityProvider

class CustomProvider(IdentityProvider):
    name = "custom"

    async def authenticate(self, credentials: dict) -> dict:
        # Return user info dict
        pass

    async def validate_token(self, token: str) -> dict:
        # Validate and return claims
        pass

    async def get_user_groups(self, user_id: str) -> list:
        # Return group memberships
        pass
```
