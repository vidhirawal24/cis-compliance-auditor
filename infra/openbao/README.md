# Worker-only OpenBao integration

Deploy OpenBao on a private HTTPS origin with trusted CA verification. No dev-mode root token belongs in API settings or Compose. Enable KV v2 at `device-secrets` through an administrator and provision secrets out of band at `ORG_UUID/REFERENCE_UUID`. The API only creates opaque references and reports provisioning required; it never writes or reads the credential value.

Render `worker-policy.hcl.template` for the exact dispatched reference. Use a separate AppRole per worker/security scope with short token TTL (five minutes or less), explicit max TTL, CIDR restrictions, and single-use SecretIDs delivered via response wrapping. A trusted dispatcher validates tenant/job/asset authorization before provisioning a scoped worker token. Do not share a global read token among workers. Use token expiry/revocation after job completion. OpenBao's own audit devices must be enabled without recording raw secrets.

`cisguard_api.bao.OpenBao` accepts a fixed HTTPS origin and a `WorkerGrant` containing only the exact tenant/reference and a redacted token. It refuses mismatched scope, redirects and provider failures. The return value uses SecretStr and remains worker-local; it has no browser route or database persistence path. The OpenBao policy is the enforcement boundary even if worker application code is compromised. Avoid retaining returned values beyond one authorized operation; Python does not guarantee memory zeroization.

No OpenBao server address, CA or worker bootstrap credentials were supplied. Connector behavior is tested with HTTP fixtures, not claimed as a live vault deployment. Provisioning and rotation must be exercised against the actual service before production device access.

References: [AppRole](https://openbao.org/docs/auth/approle/), [policies and response wrapping](https://openbao.org/docs/concepts/policies/).
