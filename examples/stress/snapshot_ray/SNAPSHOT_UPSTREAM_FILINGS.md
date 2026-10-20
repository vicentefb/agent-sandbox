# Upstream filings — GKE Pod Snapshots suspend/resume campaign (2026-08-29 → 08-31)

Evidence base: ~30,000 suspend/resume ops across `sandbox-snapshot-demo` (vicenteferrara-gke-dev) and
`m2-density-c` (gke-ai-eco-dev), GKE 1.36.3-gke.1537000, agent-sandbox v1.0.0, SDK k8s-agent-sandbox==1.0.0.
Full data: `SNAPSHOT_STRESS_RESULTS.md`. Repro harnesses: `snapshotStress` branch of vicentefb/kuberay.

---

## A. k8s-agent-sandbox SDK (`gke_extensions.snapshots`) — file at kubernetes-sigs/agent-sandbox

### SDK-1 · One-shot `PodRestored` check races the condition write → false "cold start" reports
- **Where:** `utils.check_pod_restored_from_snapshot()`, called once immediately after pod-Ready in
  `_restore_internal()`.
- **Symptom:** `resume()` returns failure "Pod was started as a fresh instance" for pods that WERE
  restored. Bursty; rate grows with concurrency and with snapshot size/dwell (1/150-way → 9/cycle at
  250-way; 3/20 in a 1GB run).
- **Evidence it's false:** state-digest adjudication in-line (validation run: EVERY such report false —
  2,497/2,497 state intact) and next-cycle digest verification in earlier runs.
- **Impact:** orchestrators discard healthy sandboxes / abandon rollouts.
- **NEW (2026-09-08): the false-alarm rate SCALES WITH SNAPSHOT SIZE — 29% (14/48) at 4GB restores
  vs ~0.7% at ~35MB (RESULTS Part 11; all 14 false, digest-proven). Larger restores delay the
  PodRestored condition write past the one-shot check more often. Any workload with real in-memory
  state hits this constantly.**
- **Fix:** bounded poll (few seconds) for the PodRestored condition before concluding fresh-instance;
  distinguish "condition absent yet" from "condition present, wrong UID" in the error reason.

### SDK-2 · Reconnect-after-resume falls back to unresolvable service DNS → guaranteed failure window
- **Where:** connector fallback when pod IP is not yet in `status.podIPs` post-resume: builds
  `<sandbox>.<ns>.svc.cluster.local` and burns 5 urllib3 retries.
- **Symptom:** "Failed to communicate with the sandbox at http://<name>.default.svc.cluster.local:8888/
  {execute,upload}" — the persistent 0.5-6% failure floor in every unmitigated run.
- **Tested and disproven mitigation:** `service: true` does NOT help — headless-Service endpoint DNS
  lags in exactly the same propagation window as podIPs.
- **Validated mitigation (client-side):** simple retry (4×3s) absorbs the class completely (160→3 total
  errors in the 500-way validation run).
- **Fix:** poll `status.podIPs` briefly before/instead of the DNS fallback; make the fallback
  conditional on the Service actually existing.

### SDK-3 · `snapshots.create()` completion wait hardcoded to 180s
- **Where:** `snapshot_engine.create()` → `wait_for_snapshot_to_be_completed` (no timeout parameter).
- **Symptom:** at trigger-queue depth, client gives up while the controller is still processing;
  contributed to the 250-way collapse cascade.
- **Fix:** expose the timeout; suspend() should plumb it through.

### SDK-4 · Timed-out triggers are abandoned, not deleted → poisons subsequent suspends
- **Symptom:** next suspend on the same pod rejected with "Another PodSnapshotManualTrigger ... is
  already targeting Pod ... not yet completed" (observed: trigger from 01:45 still blocking at 01:58+).
  This converts a slow cluster into a progressive death spiral (cycle success 32→24→…→0 in the
  high-density collapse). A 429-failed CREATE is clean (no orphan); only the timeout path poisons.
- **Fix:** delete own trigger on client-side timeout (best-effort), and/or controller-side TTL.

### SDK-5 · No 429/`Retry-After` handling on trigger create (or any snapshot-path call)
- **Symptom:** single-shot POST; apiserver 429s (which carry Retry-After: 1..30) surface as hard
  suspend failures. Accounted for ~all stock-APF failures at 250-way (26/wave) and lane-saturation
  failures at 1,000-way.
- **Fix:** honor Retry-After with bounded backoff on create/patch calls in the suspend/resume path.

### SDK-note · Diagnosability: errors are logged even when the operation ultimately succeeds
Transient failures log at ERROR before caller-level retries can succeed; also `resume()` on a
never-suspended sandbox returns fast success (no-op) which contaminates naive latency stats. Document;
consider log-level demotion for retryable classes.

---

## B. GKE Pod Snapshots (managed component) — file internally / with the Pod Snapshots team

### GKE-1 · Storage misconfiguration surfaces as opaque `runsc error: exit status 128`
- Two worked examples, identical user-visible error:
  - bucket does not exist → agent log: `closing state file failed: input/output error`
  - bucket IAM missing (e.g., bucket recreated — IAM does not survive recreation) →
    `closing state file failed: permission denied`
- Trigger condition shows only "runsc error: exit status 128"; nothing validates
  `PodSnapshotStorageConfig` at apply time.
- **Ask:** validate bucket existence/permissions at storage-config admission or first use; surface the
  inner error in the trigger/PodSnapshot condition. Diagnostic chain for users today: trigger condition
  → `pod-snapshot-agent` logs in ns `gke-managed-pod-snapshots` → full runsc cmdline+stderr.

### GKE-2 · Checkpoint/cleanup race in the node agent under self-paced churn
- **Symptom:** `failed to write to metadata file: open /host/var/lib/podsnapshots/<uid>/metadata: no
  such file or directory` and variant `failed to read GCS option file .../gcs_opts.json` (SnapshotSize:0)
  — the snapshot's own staging dir loses files between checkpoint completion and metadata write.
- **Rate data:** absent in all synchronized-wave runs; appears only under self-paced (phase-mixed
  checkpoint/restore/GC) traffic. ~3 per 500 turns at 2-3s dwell; ~7 per 500 turns at 6s dwell
  (dwell-correlated); incidence tracks snapshot count, not node count (same rate on 34 vs 375 nodes).
  Residual floor with a fully retrying client: 3/2,500 turns (~0.1%).
- **Ask:** serialize or guard staging-dir cleanup against in-flight checkpoint finalization.

### GKE-3 · Per-cluster trigger-pipeline throughput ≈ 10 snapshots/s (op-rate, not bandwidth)
- **Isolation:** suspend p50 at 500-way ≈ 51.5s regardless of node count (34 vs 375) and snapshot size
  (~40MB vs ~99MB). Resume path unaffected (2.2s floor throughout).
- **Consequence:** per-turn suspension for RL fleets is capped at ~10 turns/s/cluster (~180 rollouts at
  an 18s turn cadence); horizontal cluster sharding is currently the only scaling lever.
- **Ask:** document the ceiling; raise controller/pipeline throughput or make it scale with cluster size.

---

### SDK-6 · No template-direct claim path (warmpool arg is mandatory)
- `create_sandbox(warmpool=...)` is the only creation path; the claim controller itself supports
  fresh-creation, and on slot-scarce arenas pool-free operation is strictly better (replacement
  minting competes with resumes for slots — measured in the density experiments, Part 7). Expose a
  template-referencing claim path in the SDK.

### SDK-7 · Sandboxes wedge under untrusted code — and memory snapshots make the wedge IMMORTAL
- Four occurrences across three runs; frequency scales with model quality (real models exercise the
  exec server harder). Modes: pod-IP permanently unreachable; exec-server read-timeout hang.
- **Key evidence (3B run): the wedge is pinned to one sandbox across per-step suspend/resume cycles
  while its pod+IP are recreated every step — the hung server state is captured in the snapshot and
  faithfully RESTORED on every resume. Restart-to-recover does not exist under memory snapshots.**
- Each wedged sandbox taxes every subsequent operation with full retry budgets (~252s/step observed)
  and its reward slot flatlines.
- Ask: (1) a cheap liveness signal on the sandbox handle; (2) a "cold resume" escape hatch (resume
  WITHOUT snapshot restore) so orchestrators can recover a wedged sandbox in place; (3) consider a
  runtime-side guard (kill process group on command timeout) — leading hypothesis is orphan
  accumulation from timed-out commands (unconfirmed; repro: repeatedly submit blocking code).

---

## C. Revision note for GKE-3 (2026-09-06, supersedes the framing above)

The swarm ladder (RESULTS Part 6) sustained ~11.8 suspends/s of naturally-staggered real-training
traffic with flat latency — ABOVE the ~10/s figure. The ~10/s number is the pipeline's DRAIN rate
observed under a synchronized 500-deep burst, not an arrival-rate cap; steady arrivals below true
throughput (≥12/s demonstrated) ride the ~5s floor. File GKE-3 as: document burst-vs-steady behavior
(latency = queue-depth ÷ drain-rate for synchronized waves; floor for staggered arrivals), and state
the actual steady-state throughput ceiling — now MEASURED: ~20-25 suspends/s sustained equilibrium
(450 real trainers, ~55/s attempted, suspend p50 4.7→37.4s, zero failures — RESULTS Part 6 rung 6),
on a ~690-node cluster (large GKE control plane). Worker-node count is proven irrelevant to the
ceiling (34-vs-375 null + rung 6's idle fleet); control-plane size is the suspected scaling knob
(small demo cluster collapsed far lower) — ask the Pod Snapshots team to confirm how controller
throughput scales with cluster tier, and whether it can be raised or made a provisionable dimension.

Suggested filing order: SDK-5 and SDK-2 first (they are ~all of the observable failure rate and are
trivial fixes), then GKE-2 (correctness), GKE-1 (diagnosability), SDK-1/3/4/6/7, GKE-3 (as revised).
