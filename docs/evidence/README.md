# Evidence

Each directory contains one executed end-to-end run against a real Windows guest
VM, driven by `scripts/e2e.ps1` through `bvmenv`:

```
<YYYYMMDD>-e2e/
  summary.json        host-side summary (bvmenv exec exit code, state, guest result)
  state.json          host-side VM state observation after the run
  state.png           screenshot taken by bvmenv after the run
  guest-out/
    result.json       guest-side suite result (per-check pass/fail + details)
    ntoskrnl-dump.bin dumped kernel image header used by the dump-driver check
    helper.json       marker process output used by the process-memory check
  guest-exec.log      guest runner stdout (head/tail kept; large logs summarized)
  bundle/             exactly what was pushed into the VM
  bvmenv.out.log      bvmenv stdout (head/tail)
  bvmenv.err.log      bvmenv stderr (head/tail)
```

Rules:

- `result.json`/`summary.json` are the primary evidence: every check has an
  explicit pass/fail and a detail string.
- Screenshots are kept only when they add information (failure/BSOD/hang); a
  clean run keeps the final state screenshot as proof of a healthy VM.
- Large raw logs are reduced to head+tail plus SHA256; binaries are not
  committed.
- A run is only considered evidence if `summary.json.ok == true`, which requires
  the guest runner to exit 0 and every check in `result.json` to pass.
