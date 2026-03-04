# AIShields / AIShields Platform Architecture

## The platform in one view (Mermaid)

```mermaid
graph TD
  subgraph Endpoints
    E1[AI Tool Detector Agent]
    E2[IDE/Browser Controls]
    E3[Proxy Agent]
  end

  subgraph Apps
    A1[RASP SDKs: Java/.NET/Python/Node/Go/Rust/Ruby/PHP/C++]
    A2[Service Mesh / Envoy Filter]
  end

  subgraph Network
    N1[Transparent Proxy]
  end

  subgraph Runtime
    R1[AISR Runtime API]
    R2[Detection Service]
    R3[Policy Service]
    R4[Response Orchestrator]
  end

  subgraph ControlPlane
    C1[Control Plane API]
    C2[(Postgres)]
    C3[Audit Logs]
    C4[Compliance Evidence]
  end

  subgraph Telemetry
    T1[eBPF Sensor (Linux)]
    T2[OTLP / JSON Ingest]
  end

  E1 --> R1
  E3 --> N1 --> R1
  A1 --> R1
  A2 --> R1
  T1 --> T2 --> C1

  R1 --> R2
  R1 --> R3
  R1 --> R4
  R1 --> C1
  C1 --> C2
  C1 --> C3
  C1 --> C4
```

## Product narrative (investor + buyer)
AIShields is an **AI Security Runtime** that enforces policy at the point where AI is actually used:
- on the endpoint
- inside the application
- on the network path
- and at the kernel (telemetry)

Unlike single-layer “prompt filters,” AIShields provides a **closed-loop runtime**:
1) observe, 2) decide, 3) act, 4) prove.

## “Kernel to Cloud” proof points
- **Linux**: eBPF sensor for process + network telemetry
- **macOS**: Endpoint Security framework (agent roadmap)
- **Windows**: minifilter/ETW roadmap

## What to demo in 60 seconds
1. Send a prompt injection payload through the proxy
2. Detection fires
3. Response blocks via proxy-agent
4. Control plane shows incident + audit record
5. Generate compliance evidence snapshot
