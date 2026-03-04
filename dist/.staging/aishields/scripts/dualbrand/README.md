# Dual-brand build

This repo supports generating two branded distributions from a single codebase:

- **AIShields (OSS)**
- **CyberArmor.ai (Commercial)**

## Build

```bash
make dist-oss
make dist-commercial
```

Outputs:
- `dist/AIShields-oss.zip`
- `dist/CyberArmor-commercial.zip`

## What gets branded

- HTTP headers (`x-aishields-*` vs `x-cyberarmor-*`)
- Helm chart name + directory (`infra/helm/aishields` vs `infra/helm/cyberarmor`)
- Canonical env var prefixes (`AISHIELDS_*` vs `CYBERARMOR_*`) in `.env.example` and Helm values/templates
- Human-readable names in docs/service titles

The services are expected to remain backward compatible with legacy unprefixed env vars.
