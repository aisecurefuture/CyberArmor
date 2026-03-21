# CyberArmor Hard Rename - Breaking Changes (2026-03-12)

This release switches canonical product and package identity from `CyberArmor` to `CyberArmor`.

## Breaking changes

1. Policy ext-authz headers:
- Removed: `x-cyberarmor-*`
- Canonical: `x-cyberarmor-*`

1. Go RASP module/package:
- Old module: `github.com/cyberarmor/rasp-go`
- New module: `github.com/cyberarmor/rasp-go`
- Root package renamed to `cyberarmor`

1. Node RASP package:
- Old package name: `cyberarmor-rasp`
- New package name: `cyberarmor-rasp`
- Legacy export moved to `cyberarmor-rasp/legacy`

1. Python RASP package metadata:
- Old package name: `cyberarmor-rasp`
- New package name: `cyberarmor-rasp`

1. PHP Composer package:
- Old package name: `cyberarmor/rasp`
- New package name: `cyberarmor/rasp`

1. Ruby gem:
- Old gem name: `cyberarmor-rasp`
- New gem name: `cyberarmor-rasp`

1. Rust crate:
- Old crate name: `cyberarmor-rasp`
- New crate name: `cyberarmor-rasp`

1. Java Maven coordinates:
- Old: `ai.cyberarmor:cyberarmor-rasp`
- New: `ai.cyberarmor:cyberarmor-rasp`

1. .NET NuGet package id:
- Old: `CyberArmor.RASP`
- New: `CyberArmor.RASP`

1. macOS Endpoint Security system extension identifiers:
- Old bundle id: `ai.cyberarmor.endpoint-security`
- New bundle id: `ai.cyberarmor.endpoint-security`
- Executable/name switched to `CyberArmorEndpointSecurity`

## Compatibility and migration notes

1. PHP and Ruby still include namespace/class aliases for legacy callers during transition.
1. Python still ships both `cyberarmor_rasp` and `cyberarmor_rasp` modules.
1. Node includes a legacy export path (`/legacy`) for code that has not migrated.

## Recommended migration order

1. Update policy/proxy integrations to consume `x-cyberarmor-*` headers.
1. Migrate package managers and import paths by language.
1. Rotate environment variables from `CYBERARMOR_*` to `CYBERARMOR_*`.
1. Remove legacy aliases after one release cycle.
