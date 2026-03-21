# CyberArmor distribution build

This repo builds a single branded distribution from this codebase:

- **CyberArmor.ai (Commercial)**

## Build

```bash
make dist-commercial
```

Outputs:
- `dist/CyberArmor-commercial.zip`

## What gets branded

- HTTP headers (`x-cyberarmor-*`)
- Helm chart name + directory (`infra/helm/cyberarmor`)
- Canonical env var prefixes (`CYBERARMOR_*`) in `.env.example` and Helm values/templates
- Human-readable names in docs/service titles

The services are expected to remain backward compatible with legacy unprefixed env vars.
