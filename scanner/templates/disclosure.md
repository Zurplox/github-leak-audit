# Private credential exposure notification

Hello repository maintainer,

I found a **potentially exposed {provider} credential** in `{path}`.

- Repository: `{repository}`
- Commit: `{commit_sha}`
- Line: `{line_number}`
- Masked preview: `{masked_preview}`
- Confidence: {confidence}
- Evidence: {evidence}
- [Open exact GitHub source]({permalink})

This is **publicly exposed; validity not tested**. Please treat it as compromised:

1. Revoke the credential immediately and rotate it for every affected service.
2. Remove the value from the current file and clean it from repository history.
3. Review access logs and deploy a replacement through a private secret store.

This is a private notification draft for human review. No public issue or automated
credential validation was performed.
