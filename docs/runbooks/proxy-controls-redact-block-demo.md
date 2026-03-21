# Proxy Controls Demo: PII Redaction Signal + Prompt-Injection Block

## Goal

Show cached proxy policy controls in action:
1. PII content triggers `warn` (redaction workflow signal).
1. Prompt-injection content triggers `block`.

## Run

```bash
bash scripts/demo/run_proxy_controls_demo.sh
```

Optional tenant override:

```bash
TENANT_ID=default bash scripts/demo/run_proxy_controls_demo.sh
```

## What the script does

1. Creates two tenant policies in Policy Service:
   - `warn` policy for PII-like patterns in `content.text`
   - `block` policy for prompt-injection phrases targeting OpenAI chat endpoint
1. Refreshes proxy-agent cache (`POST /policy/refresh-all`).
1. Verifies the policies appear in cached proxy controls (`GET /policies/cached/{tenant}`).
1. Sends three test decisions through proxy-agent `/decision`:
   - benign prompt -> `allow`
   - PII prompt -> `warn`
   - prompt-injection prompt -> `block`

## Dashboard walkthrough

1. Open [http://localhost:3000/#/proxy](http://localhost:3000/#/proxy) and show cached proxy policies.
1. Open [http://localhost:3000/#/policies](http://localhost:3000/#/policies) and show policy definitions.

## Important implementation note

Current proxy behavior supports enforceable outcomes (`allow`, `warn`, `block`).
`warn` is the redaction signal used for downstream handling and audit evidence.
Full in-transit payload rewriting/redaction is not enabled in this implementation.
