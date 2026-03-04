# Azure App Registration Setup for CyberArmor.ai Protect

This guide walks through configuring Microsoft Entra ID (formerly Azure AD) as an identity provider for CyberArmor.ai Protect.

## Prerequisites

- Azure subscription with Global Administrator or Application Administrator role
- CyberArmor.ai Protect control plane deployed and accessible
- TLS certificate configured for your CyberArmor.ai domain

## Step 1: Register the Application

1. Navigate to [Azure Portal](https://portal.azure.com) > **Microsoft Entra ID** > **App registrations**
2. Click **New registration**
3. Configure:
   - **Name**: `CyberArmor.ai Protect`
   - **Supported account types**: Accounts in this organizational directory only (Single tenant)
   - **Redirect URI**: Select **Web** and enter:
     ```
     https://your-aishields-domain.com/auth/callback
     ```
4. Click **Register**
5. Note the **Application (client) ID** and **Directory (tenant) ID**

## Step 2: Configure Client Secret

1. In the app registration, go to **Certificates & secrets**
2. Click **New client secret**
3. Configure:
   - **Description**: `CyberArmor.ai Protect Production`
   - **Expires**: 24 months (recommended)
4. Click **Add**
5. **Immediately copy the secret value** (it won't be shown again)

## Step 3: Configure API Permissions

1. Go to **API permissions** > **Add a permission**
2. Select **Microsoft Graph**
3. Choose **Delegated permissions** and add:
   - `openid` — Sign users in
   - `profile` — View users' basic profile
   - `email` — View users' email address
   - `User.Read` — Read signed-in user's profile
   - `GroupMember.Read.All` — Read group memberships (for RBAC mapping)
   - `Directory.Read.All` — Read directory data (for org structure)
4. Click **Add permissions**
5. Click **Grant admin consent for [Your Organization]**

## Step 4: Configure Token Claims

1. Go to **Token configuration**
2. Click **Add optional claim**
3. Select **ID** token type and add:
   - `email`
   - `preferred_username`
   - `groups` (for group-based access control)
4. Click **Add**
5. When prompted about Microsoft Graph permissions, click **Turn on the Microsoft Graph email, profile permission**

## Step 5: Configure App Roles (for CyberArmor.ai RBAC)

1. Go to **App roles** > **Create app role**
2. Create the following roles:

| Display Name | Value | Description | Allowed Members |
|-------------|-------|-------------|-----------------|
| CyberArmor.ai Admin | `aishields.admin` | Full administrative access to CyberArmor.ai Protect | Users/Groups |
| CyberArmor.ai Analyst | `aishields.analyst` | View incidents, telemetry, and compliance reports | Users/Groups |
| CyberArmor.ai Policy Manager | `aishields.policy_manager` | Create and manage security policies | Users/Groups |
| CyberArmor.ai Viewer | `aishields.viewer` | Read-only access to dashboards | Users/Groups |
| CyberArmor.ai API Client | `aishields.api_client` | Programmatic API access for service accounts | Applications |

## Step 6: Assign Users and Groups

1. Go to **Enterprise applications** > **CyberArmor.ai Protect**
2. Click **Users and groups** > **Add user/group**
3. Assign users or security groups to the appropriate app roles
4. Recommended group structure:
   - `SG-CyberArmor.ai-Admins` → `aishields.admin`
   - `SG-CyberArmor.ai-Analysts` → `aishields.analyst`
   - `SG-CyberArmor.ai-PolicyMgrs` → `aishields.policy_manager`
   - `SG-CyberArmor.ai-Viewers` → `aishields.viewer`

## Step 7: Configure Conditional Access (Recommended)

1. Go to **Microsoft Entra ID** > **Security** > **Conditional Access**
2. Create a new policy:
   - **Name**: `CyberArmor.ai Protect - Require MFA`
   - **Assignments**: Target the CyberArmor.ai Protect application
   - **Conditions**: All client apps
   - **Grant**: Require multifactor authentication
   - **Session**: Sign-in frequency = 12 hours
3. Enable the policy

## Step 8: Configure CyberArmor.ai Identity Service

Update your CyberArmor.ai deployment configuration:

### Docker Compose (.env)

```env
IDENTITY_PROVIDER=entra
ENTRA_TENANT_ID=your-tenant-id-here
ENTRA_CLIENT_ID=your-client-id-here
ENTRA_CLIENT_SECRET=your-client-secret-here
ENTRA_REDIRECT_URI=https://your-aishields-domain.com/auth/callback
ENTRA_SCOPES=openid profile email User.Read GroupMember.Read.All
```

### Kubernetes (Helm values.yaml)

```yaml
identity:
  provider: entra
  env:
    - name: ENTRA_TENANT_ID
      valueFrom:
        secretKeyRef:
          name: aishields-identity-secrets
          key: entra-tenant-id
    - name: ENTRA_CLIENT_ID
      valueFrom:
        secretKeyRef:
          name: aishields-identity-secrets
          key: entra-client-id
    - name: ENTRA_CLIENT_SECRET
      valueFrom:
        secretKeyRef:
          name: aishields-identity-secrets
          key: entra-client-secret
```

Create the Kubernetes secret:

```bash
kubectl create secret generic aishields-identity-secrets \
  --from-literal=entra-tenant-id=YOUR_TENANT_ID \
  --from-literal=entra-client-id=YOUR_CLIENT_ID \
  --from-literal=entra-client-secret=YOUR_CLIENT_SECRET \
  -n aishields
```

## Step 9: Verify Integration

1. Navigate to your CyberArmor.ai dashboard
2. Click **Sign in with Microsoft**
3. Authenticate with your Entra ID credentials
4. Verify the correct role is mapped in the CyberArmor.ai admin panel under **Identity** > **Sessions**

### Test API Authentication

```bash
# Get an access token
TOKEN=$(curl -s -X POST \
  "https://login.microsoftonline.com/$TENANT_ID/oauth2/v2.0/token" \
  -d "client_id=$CLIENT_ID" \
  -d "scope=api://$CLIENT_ID/.default" \
  -d "client_secret=$CLIENT_SECRET" \
  -d "grant_type=client_credentials" | jq -r '.access_token')

# Call CyberArmor.ai API with the token
curl -H "Authorization: Bearer $TOKEN" \
  https://your-aishields-domain.com/api/v1/health
```

## Step 10: Configure Token Lifetime (Optional)

For enhanced security, configure shorter token lifetimes:

1. In Azure Portal, go to **Microsoft Entra ID** > **Token lifetime policies**
2. Create a policy using Microsoft Graph or PowerShell:

```powershell
# PowerShell example
$policy = New-AzureADPolicy -Definition @(
  '{"TokenLifetimePolicy":{"Version":1,"AccessTokenLifetime":"01:00:00","MaxInactiveTime":"00:30:00"}}'
) -DisplayName "CyberArmor.ai Token Policy" -Type "TokenLifetimePolicy"

# Assign to the service principal
Add-AzureADServicePrincipalPolicy -Id $spObjectId -RefObjectId $policy.Id
```

## Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| `AADSTS50011` redirect URI mismatch | Verify the redirect URI in app registration matches exactly |
| `AADSTS65001` consent not granted | Grant admin consent for the required API permissions |
| `AADSTS700016` app not found | Verify the client ID and tenant ID are correct |
| Groups claim missing | Ensure "groups" optional claim is configured for ID tokens |
| Role claims missing | Verify users/groups are assigned to app roles in Enterprise Apps |

### Enable Debug Logging

```env
IDENTITY_LOG_LEVEL=DEBUG
ENTRA_TOKEN_DEBUG=true
```

### Verify Token Claims

Decode the JWT token at [jwt.ms](https://jwt.ms) and verify it contains:
- `aud`: Your application's client ID
- `iss`: `https://login.microsoftonline.com/{tenant-id}/v2.0`
- `roles`: Array of assigned app roles
- `groups`: Array of group object IDs (if configured)

## Security Recommendations

1. **Rotate client secrets** at least every 12 months
2. **Use certificates** instead of client secrets for production (Certificates & secrets > Certificates)
3. **Enable Conditional Access** with MFA requirement
4. **Monitor sign-in logs** in Entra ID > Sign-in logs
5. **Configure risk-based policies** using Entra ID Protection
6. **Restrict token audience** to prevent token reuse across applications
7. **Enable continuous access evaluation (CAE)** for near real-time token revocation
8. **Use Managed Identity** when running on Azure (eliminates client secrets)

## Multi-Tenant Configuration

For SaaS deployments where multiple organizations use CyberArmor.ai:

1. Change the app registration to **Multitenant** (Accounts in any organizational directory)
2. Implement tenant allow-listing in the CyberArmor.ai Identity service
3. Configure per-tenant policy mappings
4. Enable tenant isolation in the CyberArmor.ai control plane

```env
ENTRA_MULTI_TENANT=true
ENTRA_ALLOWED_TENANTS=tenant-id-1,tenant-id-2,tenant-id-3
```
