# Pinned NuGet metadata worker

This optional worker uses Mono.Cecil `0.11.6` to read managed assembly metadata from a quarantined `.nupkg`. It extracts assembly identity, target runtime, types, methods, assembly references, and P/Invoke declarations without loading the assembly into an execution context.

Build and run it in a disposable container:

```bash
docker build -t secopsai-nuget-analyzer workers/nuget-analyzer
docker run --rm --network none --read-only \
  --cap-drop ALL --security-opt no-new-privileges \
  -v /absolute/path/to/quarantine:/work:ro \
  secopsai-nuget-analyzer /work/<sha256>.nupkg
```

The Core host must treat the JSON as normalized evidence, preserve the package hash, and keep the raw artifact in quarantine. Do not mount customer source trees, writable host paths, credentials, or a network interface. The worker is an optional deep-analysis provider; Core’s bounded byte-level inspector remains the deterministic fallback when it is not configured.
