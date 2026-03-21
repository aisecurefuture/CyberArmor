# SDK / Framework Parity Matrix

- Date: 2026-03-08
- Scope baseline:
  - Providers: `openai`, `anthropic`, `google`, `amazon`, `microsoft`, `xai`, `meta`, `perplexity`
  - Frameworks: `LangChain`, `LlamaIndex`, `Vercel AI`, `OpenAI native`, `Anthropic native`

## Current Status

1. Python SDK (`sdks/python`): `High`
   - Providers present: 8/8
   - Framework adapters present: LangChain, LlamaIndex
   - Gap: Vercel AI adapter not present.
1. Node SDK (`sdks/nodejs`): `High`
   - Providers present: 8/8 (expanded in this pass)
   - Framework adapters present: LangChain, Vercel AI, LlamaIndex
   - Build: `npm run build` passed after updates.
1. Java SDK (`sdks/java`): `High`
   - Provider wrappers present in `cyberarmor-providers`: OpenAI, Anthropic, Google, Amazon, Microsoft, xAI, Meta, Perplexity
   - Framework adapters present: LangChain4j + generic LlamaIndex/Vercel-AI adapters in `cyberarmor-core`
   - Gap: wrappers for non-OpenAI-native providers currently reuse OpenAI-compatible transport pattern.
1. Go SDK (`sdks/go`): `Medium`
   - Core SDK present; provider adapters now present for Google, Amazon, Microsoft(Azure), xAI, Meta, Perplexity via OpenAI-compatible wrapper.
   - Framework adapters present: LangChain, LlamaIndex, Vercel-AI guard wrappers.
   - Native provider clients added: OpenAI + Anthropic.
   - Gap: richer provider-specific request/response schema helpers and streaming support.
1. .NET SDK (`sdks/dotnet`): `Medium`
   - Core provider wrappers present: OpenAI, Anthropic, Google, Amazon, Microsoft, xAI, Meta, Perplexity (in `CyberArmor.Core/Providers`).
   - Framework adapters present: Semantic Kernel + generic LlamaIndex/Vercel-AI adapters in `CyberArmor.Core/Frameworks`.
   - Gap: broader package split (`CyberArmor.Providers`, `CyberArmor.AspNetCore`) and deeper first-party integrations.
1. Ruby SDK (`sdks/ruby`): `Medium`
   - Providers present: OpenAI, Anthropic, Google, Amazon, Microsoft, xAI, Meta, Perplexity
   - Gap: wrappers beyond OpenAI/Anthropic currently use shared OpenAI-compatible transport pattern.
1. PHP SDK (`sdks/php`): `Medium`
   - Providers present: OpenAI, Anthropic, Google, Amazon, Microsoft, xAI, Meta, Perplexity
   - Gap: wrappers beyond OpenAI/Anthropic currently use shared OpenAI-compatible transport pattern.
1. Rust SDK (`sdks/rust`): `Medium`
   - Provider modules present: OpenAI + OpenAI-compatible wrappers for Google, Amazon, Microsoft, xAI, Meta, Perplexity
   - Gap: dedicated Anthropic-native wrapper still separate future work.
1. C/C++ SDK (`sdks/c_cpp`): `Medium`
   - Core client and examples present.
   - Gap: multi-provider parity and framework-specific integration layer is limited.

## Changes completed in this pass

1. Node provider parity expansion:
   - Added: `google`, `amazon`, `microsoft`, `xai`, `meta`, `perplexity`
   - Added shared adapter base: `openaiCompatible`
1. Node framework parity:
   - Added `frameworks/llamaindex.ts`
1. Node package/export surface:
   - Updated exports in `package.json`
   - Updated top-level exports in `src/index.ts`
1. Build verification:
   - `npm run build` passed in `sdks/nodejs`
1. Java provider parity expansion:
   - Added wrappers for Google, Amazon, Microsoft, xAI, Meta, Perplexity in `cyberarmor-providers`.
   - Validation: `mvn -Dmaven.repo.local=/tmp/m2repo -B test` passed for `sdks/java` reactor.
1. .NET provider parity expansion:
   - Added wrappers for Google, Amazon, Microsoft, xAI, Meta, Perplexity in `CyberArmor.Core/Providers`.
   - Validation: `/usr/local/share/dotnet/dotnet build` passed in `sdks/dotnet` (warnings only).
1. Go provider parity expansion:
   - Added generic OpenAI-compatible provider base + adapters for Google, Amazon, Microsoft(Azure), xAI, Meta, Perplexity.
   - Validation: `/usr/local/go/bin/go test ./...` passed in `sdks/go`.
1. Ruby/PHP/Rust provider parity expansion:
   - Added wrappers/modules for Google, Amazon, Microsoft, xAI, Meta, Perplexity.
   - Validation:
     - Rust: `~/.cargo/bin/cargo test` passed.
     - Ruby: `ruby -c` syntax checks passed on provider files.
     - PHP: syntax validation command skipped when `php` runtime is unavailable in environment.
1. Provider contract tests added:
   - Go: `sdks/go/providers/providers_parity_test.go` validates provider IDs + default endpoint mapping.
   - Go: `sdks/go/providers/native_providers_test.go` validates OpenAI/Anthropic native wrapper defaults.
   - Go: `sdks/go/providers/native_more_providers_test.go` validates Google/Amazon/Microsoft/xAI/Meta/Perplexity native wrapper defaults.
   - Go: `sdks/go/providers/native_runtime_contract_test.go` validates mocked runtime contract flow (policy + upstream call path + deny path) for native providers.
   - Go: `sdks/go/frameworks/frameworks_parity_test.go` validates framework guard wrappers invoke delegates.
   - Rust: `sdks/rust/tests/providers_parity.rs` validates provider IDs + default base URLs.
   - Ruby: `sdks/ruby/spec/providers/openai_compatible_test.rb` validates policy provider routing, redaction pass-through, and audit emission on chat path.
   - PHP: `sdks/php/tests/Providers/OpenAICompatibleTest.php` validates policy provider routing, redaction pass-through, and audit emission on chat path.
   - Java: `sdks/java/cyberarmor-core/src/test/java/ai/cyberarmor/frameworks/CyberArmorAdaptersTest.java` validates adapter allow/block behavior and audit emission call path.
   - Validation:
     - Go: `/usr/local/go/bin/go test ./...` passed.
     - Rust: `~/.cargo/bin/cargo test` passed.
     - Java/Ruby/PHP: tests added; runtime execution still pending in this pass.

1. Framework adapter expansion:
   - Go: added `frameworks/langchain`, `frameworks/llamaindex`, `frameworks/vercelai`.
   - .NET: added `CyberArmorSemanticKernel`, `CyberArmorLlamaIndex`, `CyberArmorVercelAI`.
   - Java: added `CyberArmorLlamaIndexAdapter`, `CyberArmorVercelAIAdapter`.
1. Provider-native expansion:
   - Go: added native `providers/openai`, `providers/anthropic`, `providers/google`, `providers/amazon`, `providers/azure`, `providers/xai`, `providers/meta`, and `providers/perplexity` clients (policy + audit integrated).

## Priority remaining work

1. Deepen framework integrations from generic wrappers to framework-native first-party APIs (especially .NET Semantic Kernel and Java ecosystems).
1. Expand runtime contract tests from defaults/guard behavior into full mocked upstream request/response flows across Java/.NET/Go/Ruby/PHP.
1. Continue provider-native implementations for wrappers still routed through OpenAI-compatible transport (Google/Amazon/Microsoft/xAI/Meta/Perplexity in multiple SDKs).
