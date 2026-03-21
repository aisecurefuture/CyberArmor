# Phase 2 Line-by-Line Checklist Mapping

- Date: 2026-03-08
- Source checklist: `AI-Identity-Control-Plane-Build-Prompt.md` lines 1513-1532
- Repo root: `<repo-root>`

## Checklist Mapping

1. `- [ ] /services/agent-identity/ — Agent Identity Service`
   - Status: `Implemented`
   - Evidence: path exists; register/list/issue/validate/revoke covered in smoke flow.
1. `- [ ] /services/ai-router/ — AI Provider Router with all 8 provider connectors`
   - Status: `Implemented`
   - Evidence: path exists; connectors present for `openai, anthropic, google, amazon, microsoft, xai, meta, perplexity`; health + router flow covered in smoke.
1. `- [ ] /services/audit/ — Dedicated Audit & Action Graph service`
   - Status: `Implemented`
   - Evidence: path exists; append-only + signature integrity flow validated in smoke.
1. `- [ ] /services/policy/ — Enhanced Policy Engine (Cedar DSL + new decision types)`
   - Status: `Implemented`
   - Evidence: required policy endpoints present; all decision modes validated in smoke assertions.
1. `- [ ] /sdks/python/ — Python SDK (full, with all providers + frameworks)`
   - Status: `Partial`
   - Evidence: path exists; full provider/framework parity audit still pending.
1. `- [ ] /sdks/java/ — Java SDK (Maven multi-module, Spring Boot, LangChain4j)`
   - Status: `Partial`
   - Evidence: path exists; build/test previously fixed and passing in-session; framework surface expanded with generic LlamaIndex/Vercel-AI adapters and new adapter tests.
1. `- [ ] /sdks/go/ — Go SDK (Go module, gin/echo/chi/http middleware)`
   - Status: `Partial`
   - Evidence: path exists; build/test previously fixed and passing in-session; framework adapters expanded (LangChain/LlamaIndex/Vercel-AI) and native OpenAI/Anthropic provider clients added.
1. `- [ ] /sdks/nodejs/ — TypeScript SDK (npm, ESM+CJS, all providers + Vercel AI)`
   - Status: `Partial`
   - Evidence: path exists; TypeScript build fixed in-session; full provider/framework parity audit pending.
1. `- [ ] /sdks/dotnet/ — .NET SDK (NuGet, ASP.NET Core, Semantic Kernel)`
   - Status: `Partial`
   - Evidence: path exists; build fixed in-session; Semantic-Kernel/LlamaIndex/Vercel-AI adapter surface added in `CyberArmor.Core/Frameworks`; broader package/depth parity still pending.
1. `- [ ] /sdks/ruby/ — Ruby SDK (gem, Rack, Rails, Faraday)`
   - Status: `Partial`
   - Evidence: path exists; parity/integration verification pending.
1. `- [ ] /sdks/php/ — PHP SDK (Composer, Laravel, Symfony)`
   - Status: `Partial`
   - Evidence: path exists; parity/integration verification pending.
1. `- [ ] /sdks/rust/ — Rust SDK (crate, Tower/Axum middleware)`
   - Status: `Partial`
   - Evidence: path exists; parity/integration verification pending.
1. `- [ ] /sdks/c_cpp/ — C/C++ SDK (CMake, LD_PRELOAD, libcurl, C++ wrapper)`
   - Status: `Partial`
   - Evidence: path exists; parity/integration verification pending.
1. `- [ ] /cli/ — CLI tool`
   - Status: `Partial`
   - Evidence: path exists; end-to-end CLI DX coverage not yet fully validated.
1. `- [ ] /docs/api/openapi.yaml — Complete OpenAPI 3.1 spec`
   - Status: `Partial`
   - Evidence: file exists; drift check added, but complete spec parity review across all endpoints pending.
1. `- [ ] /infra/helm/cyberarmor/ — Production Helm chart`
   - Status: `Partial`
   - Evidence: path exists; production-hardening verification pending.
1. `- [ ] /infra/terraform/ — Terraform modules (AWS/Azure/GCP)`
   - Status: `Partial`
   - Evidence: path exists; full cloud module completeness verification pending.
1. `- [ ] /admin-dashboard/ — Enhanced dashboard with all 7 new views`
   - Status: `Implemented (AI Identity 7-view scope)` / `Partial (full dashboard breadth)`
   - Evidence: `scripts/dashboard-behavioral-acceptance.sh` passes for `agents/providers/policy-studio/graph/risk/delegations/onboarding`; broader non-AI-identity view acceptance still pending.
1. `- [ ] All existing /rasp/ agents remain functional (backwards compatibility)`
   - Status: `Partial`
   - Evidence: path exists; Java RASP pass observed in-session; full matrix validation pending.
1. `- [ ] All existing /services/ remain functional and enhanced (not replaced)`
   - Status: `Implemented (core smoke path)` / `Partial (full matrix)`
   - Evidence: full core service smoke pass; deeper regression matrix still pending.

## What is still remaining to fully close this checklist

1. Complete SDK parity verification and runtime tests for all language/framework claims.
1. Complete dashboard acceptance validation for all requested views.
1. Complete OpenAPI full-coverage parity audit (not only drift checks).
1. Complete infra production-readiness validation for Helm and Terraform modules.
1. Complete full RASP/service backward-compat regression matrix.
