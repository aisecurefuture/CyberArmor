# CyberArmor Compatibility Migration (CyberArmor Legacy)

Superseded by hard-rename release notes:

- `docs/branding-hard-rename-breaking-changes-2026-03-12.md`

This repository now uses **CyberArmor** as the canonical brand while preserving legacy CyberArmor integration points for backward compatibility.

## Canonical naming introduced

- Python: `cyberarmor_rasp` (legacy `cyberarmor_rasp` still supported)
- Node.js: `cyberarmor-rasp` canonical package and export
- Go: `rasp/go/cyberarmor` alias package over legacy module path
- PHP: `CyberArmor\RASP\*` class aliases over legacy `CyberArmor\RASP\*`
- Ruby: `CyberArmor::RASP` alias over legacy `CyberArmor::RASP`
- .NET: `AddCyberArmorRasp` / `UseCyberArmorRasp` extension methods over legacy implementation

## Environment variable compatibility

RASP runtimes now prefer `CYBERARMOR_*` variables and fall back to `CYBERARMOR_*`:

- `CYBERARMOR_URL` -> `CYBERARMOR_URL`
- `CYBERARMOR_API_KEY` -> `CYBERARMOR_API_KEY`
- `CYBERARMOR_TENANT` -> `CYBERARMOR_TENANT`
- `CYBERARMOR_MODE` -> `CYBERARMOR_MODE`

## Intentionally retained legacy identifiers

The following remain unchanged in this pass to avoid breaking existing deployments:

- Maven coordinates: `ai.cyberarmor:cyberarmor-rasp`
- NuGet package id: `CyberArmor.RASP`
- Go module path: `github.com/cyberarmor/rasp-go`
- Core kernel/RASP file names and many language namespaces

These can be migrated in a later major-version cut with explicit deprecation notices and package redirects.
