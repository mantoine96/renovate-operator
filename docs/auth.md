# UI Authentication

The operator's web UI can be protected with an authentication provider. Two providers are supported: **OIDC** (OpenID Connect) and **GitHub OAuth**. If neither is configured, the UI is publicly accessible.

Only one provider can be active at a time. OIDC takes precedence over GitHub OAuth.

---

## OIDC

Compatible with any OIDC-compliant identity provider (Keycloak, Dex, Google, Azure AD, Okta, etc.).

### Helm Configuration

```yaml
auth:
  oidc:
    enabled: true
    issuerUrl: "https://accounts.google.com"   # OIDC provider issuer URL
    clientId: "your-client-id"
    existingSecret: "oidc-secret"              # Kubernetes secret name
    secretKey: "client-secret"                 # Key inside the secret
    sessionSecretKey: ""                       # Optional: key for session encryption secret
    redirectUrl: ""                            # Optional: auto-detected from ingress
    insecureSkipVerify: false                  # Do not use in production
    logoutUrl: ""                              # Optional: auto-discovered via OIDC metadata
    allowedGroupPrefix: ""                     # Optional: only accept groups with this prefix
    allowedGroupPattern: ""                    # Optional: only accept groups matching this regex
    additionalScopes: []                        # Optional: extra OIDC scopes (e.g., ["groups"])
```

### Secret

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: oidc-secret
stringData:
  client-secret: "<your-oidc-client-secret>"
```

### OIDC Provider Setup

Register a confidential OAuth client with your identity provider and set the callback URL to:

```
https://<your-operator-host>/auth/callback
```

Required scopes: `openid`, `email`, `profile`

#### Additional Scopes

By default, only the standard OIDC scopes (`openid`, `email`, `profile`) are requested. Some providers support additional custom scopes — for example, Keycloak supports a `groups` scope to include group membership in the ID token.

To request extra scopes, set `additionalScopes`:

```yaml
auth:
  oidc:
    additionalScopes:
      - groups
```

**Azure AD / Entra ID**: Do **not** add `groups` here. Azure AD does not support `groups` as an OIDC scope and will reject the request with `AADSTS650053`. Instead, configure the `groups` claim in **App Registration → Token Configuration → Add groups claim**. The operator will read groups from the ID token regardless of whether the scope is requested.

---

## GitHub OAuth

Authenticates users via a GitHub OAuth App.

### Helm Configuration

```yaml
auth:
  github:
    enabled: true
    clientId: "your-github-client-id"
    existingSecret: "github-oauth-secret"     # Kubernetes secret name
    secretKey: "client-secret"                # Key inside the secret
    sessionSecretKey: ""                      # Optional session encryption key
    redirectUrl: ""                           # Optional: auto-detected from ingress
```

### Secret

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: github-oauth-secret
stringData:
  client-secret: "<your-github-client-secret>"
```

### GitHub OAuth App Setup

Create an OAuth App at **GitHub → Settings → Developer settings → OAuth Apps** with the callback URL:

```
https://<your-operator-host>/auth/callback
```

The operator requests the `read:user`, `user:email`, and `read:org` scopes. The `read:org` scope is required to fetch team memberships for group-based authorization. On logout, the OAuth token is automatically revoked.

### Team-Based Authorization

GitHub team memberships are fetched via the GitHub API (`/user/teams`) and mapped to groups in `org-login/team-slug` format (e.g., `myorg/backend-team`). These groups work identically to OIDC groups for authorization purposes.

You can filter which teams are accepted using the same prefix/pattern mechanism as OIDC:

```yaml
auth:
  github:
    # ... other GitHub settings ...
    allowedGroupPrefix: "myorg/"                   # Only accept teams from "myorg"
    allowedGroupPattern: "^myorg/(team-|platform-)" # Only accept teams matching regex
```

**Note**: The `read:org` scope requires the user to grant access to their organization memberships during the OAuth consent flow. For GitHub organizations with OAuth App access restrictions, the OAuth App must be approved by an organization admin.

---

## Session Security

Sessions are stored as AES-256-GCM encrypted cookies and expire after **24 hours**.

If you run multiple operator replicas, you **must** set a static session secret. Otherwise each pod generates its own key and users will be logged out when requests hit a different replica.

Set the session secret via `sessionSecretKey` pointing to a key in your existing secret, or the operator will auto-generate one per startup.

---

## Group-Based Authorization

When authentication is enabled, you can control which users can view and manage specific RenovateJobs based on their group membership.

### How It Works

- **Auth disabled**: All RenovateJobs are visible to everyone
- **Auth enabled**: Jobs are filtered based on user groups
  - Jobs without `allowedGroups` use the global `defaultAllowedGroups`
  - If neither are set, the job is hidden (secure by default)
  - Users can only see jobs where they have at least one matching group

### Configuration

#### Default Allowed Groups

Set default groups for all RenovateJobs without explicit `allowedGroups`:

```yaml
auth:
  defaultAllowedGroups: "team-platform,team-infra"
```

#### Per-Job Authorization

Add `allowedGroups` to individual RenovateJob resources:

```yaml
apiVersion: renovate-operator.mogenius.com/v1alpha1
kind: RenovateJob
metadata:
  name: my-renovate-job
spec:
  schedule: "0 2 * * *"
  allowedGroups:
    - team-platform
    - team-devops
  # ... other fields
```

#### Group Filtering

Filter which groups from your authentication provider are accepted. This works with both OIDC and GitHub OAuth:

**OIDC:**
```yaml
auth:
  oidc:
    allowedGroupPrefix: "renovate-"              # Only accept groups starting with "renovate-"
    allowedGroupPattern: "^(team-|platform-).*"  # Only accept groups matching regex
```

**GitHub OAuth:**
```yaml
auth:
  github:
    allowedGroupPrefix: "myorg/"                 # Only accept teams from "myorg"
    allowedGroupPattern: "^myorg/team-.*"        # Only accept teams matching regex
```

This is useful when your identity provider returns many groups but you only want to use certain ones for authorization.

### Security Considerations

- **Secure by default**: Jobs without any groups configured (neither explicit nor default) are hidden when auth is enabled
- **Group validation**: Groups are normalized (lowercased, trimmed) and validated for security
- **Audit logging**: All authorization decisions are logged for security auditing

---

## Notes

- Auth protects the **web UI only**. The webhook endpoints are unaffected.
