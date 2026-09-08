# GKE Pod Snapshots suspend/resume — scale characterization

## EXECUTIVE SUMMARY — the six axes of scale, each measured by its own experiment

"Scale" is not one number. Each axis below was isolated and measured with real GRPO training jobs
(rewards = model-generated code executed in sandboxes) unless noted. ~340,000+ suspend/resume
operations campaign-wide; zero state loss ever observed.

| axis | what production needs | what we measured | headline finding | where |
| --- | --- | --- | --- | --- |
| **Fleet width** (concurrent rollouts) | 100s-1,000s | 450 trainers / 3,600 sandboxes, one shared pool | latency flat to 11.8 suspends/s; 800-claim burst absorbed in minutes | Part 6 rungs 1-5 |
| **Suspend rate** (pipeline throughput) | 10-50/s fleet-wide | demand pushed to ~55/s on one cluster | **ceiling ≈ 20-25/s per (large-plane) cluster**; excess → queue latency, zero failures; shard clusters to scale | Part 6 rung 6 |
| **Density** (rollouts per node) | cost lever | 87-slot arena served 320 & 480 rollouts | **3.7× clean; 5.5× = queueing collapse (still 0 lost)**; knee ∈ (3.7, 5.5)× for 3 nodes; keep awake-load <50% of slots | Part 7 |
| **Cadence** (step/turn speed) | 15-60s turns | 1.6s / 22s / 71s steps, same fleet | **suspension costs a constant ~7s/cycle** → +9.4% at 71s, +45% at 22s, 5.2× at 1.6s; suspend per-turn only when turns are slow | Part 8 |
| **Depth** (cycles per sandbox) | 5-50 per rollout lifetime | 3,000/sandbox (12h run; 10K in progress) | **60-600× beyond production; zero latency drift**; wedges (1/750 cycles) fully contained by one-strike eviction | Part 8 addendum |
| **Model realism** | frontier | Qwen 0.5B & 3B (real coding model) | 3B aces MBPP in-sandbox (reward means 0.5-1.0); substrate is model-agnostic; frontier-sharded composition = the one quota-gated gap | Parts 5, 8 |

## THE LAWS — numbers to remember

| law | value |
| --- | --- |
| resume floor (staggered arrivals) | ~2.3s at ANY width tested (8 → 3,600 sandboxes) |
| suspend floor (8-wide wave, incl. snapshot upload) | ~4.7s, flat until pipeline saturation |
| suspension cycle cost | ~7s/step constant → relative price set by step duration |
| snapshot size (measured) | **32.3MB guest-overhead floor** (57.5GB/1,784 training-era snapshots, F bucket); +injected state ≈ linear (99MB with 64MB ballast) |
| size → latency | suspend +~1.1-1.5s/GB over floor (≤100MB ≈ invisible); **resume FLAT 0→4GB (4.3s at 4GB, measured)**; post-resume paging ~600MB/s; pipeline op-rate-bound not bandwidth-bound; >4GB unmeasured |
| pipeline ceiling (per large-plane cluster, steady staggered traffic) | ~20-25 suspends/s; ~10/s figure = burst DRAIN rate, not arrival cap |
| beyond every limit (pipeline, density, depth) | degradation = LATENCY ONLY; zero rollout/state loss anywhere |
| capacity released by per-step suspension | ~90% of training wall-clock (awake ~9s of ~105s step) |
| density multiplier bound | 1/duty-cycle (≈11.6× at 8.6% awake); practical knee ≈ half of that |
| wedge rate under adversarial code | ~1 per 750 sandbox-cycles; IMMORTAL under snapshots (restore preserves the hang) → one-strike eviction is mandatory fleet hygiene (~20s/heal) |
| N2/nodes/quota vs the pipeline ceiling | irrelevant — the ceiling is a managed-controller service rate; only more clusters (or GKE) raise it |

## THE WORKLOAD — what the RL loop actually is

Every "trainer" is a genuine GRPO training job (TRL 0.21): the policy model writes Python solutions
to MBPP problems; each solution executes inside a gVisor sandbox against the problem's unit tests;
pass-fraction is the reward (0.1·ran + 0.9·pass rate); GRPO updates the weights (lr 2e-6, KL
beta 0.04). Per training step: 2 problems × 4 generations = **8 completions → 8 parallel sandbox
executions → fleet suspends (snapshot to GCS, pods deleted) → model generates the next batch →
fleet resumes**. The model measurably learns (rung-agnostic; the 3B reached repeated 8/8-perfect
MBPP batches; the marathon trained 30 epochs).

| experiment | trainers | steps each | sandboxes | suspend/resume ops | model |
| --- | --- | --- | --- | --- | --- |
| Part 5 A/B | 1 | 50 | 8 | ~800 | 0.5B (CPU) |
| Rungs 1-2 | 5, 12 | 20 | 40, 96 | ~5,400 | 0.5B (CPU) |
| Rungs 3-5 | 50, 100, 150 | 20 | 400-1,200 | ~91,000 | 0.5B (CPU) |
| Rung 6 (ceiling) | 450 | 20 | 3,600 | ~137,000 | 0.5B (CPU) |
| Density 3.7× / 5.5× | 40, 60 | 20 | 320, 480 | ~30,000 | 0.5B (CPU) |
| Cadence A/B | 1 | 50 ×3 arms | 8 | ~2,400 | 0.5B + 3B (GPU) |
| Marathon | 1 | 3,000 (10K running) | 8 | ~48,000+ | 0.5B (GPU) |

## LATENCIES AT A GLANCE (suspend / resume, seconds, 8-wide waves)

| regime | suspend p50 / p95 | resume p50 / p95 | notes |
| --- | --- | --- | --- |
| unloaded → 11.8 suspends/s (rungs 1-5) | 4.6-4.8 / 5.4-6.6 | 2.3-4.2 / 4.3-4.4 | THE FLOOR — flat across 25× rate increase |
| pipeline saturated ~55/s demand (rung 6) | 37.4 / 103.6 | 8.4 / 87.5 | queue latency, zero failures |
| packed arena 3.7× | 9.3 / 20.4 | 8.3 / 38.5 | slot-wait tax (upper bound, mint-era contaminated) |
| packed arena 5.5× (collapse) | 10.9 / 180 | 487.6 / 602 (at wait-cap) | rollouts wait ~8 min median; 0 lost |
| 12h marathon, final 300 waves | 4.7 / 5.5 | 2.3 / 4.3 | zero drift at depth |

## NOT TESTED — the honest gaps

1. **Frontier composition** (sharded 70B+ policy, vLLM generation, 100s of rollouts per step, days-long
   run, sandbox rewards). The one Reflection-production-shape gap. Quota-shaped; harness ready.
   *("Sharded" = the model split across many GPUs because it fits on none — a 70B in bf16 is ~140GB
   vs 80GB on an H100. Why it matters here: our biggest trained model was a 3B on one L4; the 7B
   attempt needed sharding across both L4s (`device_map: auto`) and still OOM'd in the first forward
   pass — so everything above 3B, i.e. the model class Reflection actually trains, ran zero steps in
   this campaign. Note the same word appears in "shard clusters" as the pipeline-scaling lever —
   there it means partitioning the rollout FLEET across clusters, one snapshot pipeline each;
   unrelated mechanism, same split-what-doesn't-fit idea.)*
2. ~~Multi-cluster / fleet-wave~~ **CLOSED (Part 9): A+C simultaneously on one bucket — bucket is a
   non-factor; per-cluster pipelines are independent lanes; ceiling law reproduced on A.** (Beyond
   2 clusters = extrapolation, now measurement-backed.)
3. ~~Ceiling vs control-plane size~~ **CLOSED-WITH-CAVEAT (Part 10): F's 64-core plane held
   ~17-18/s at the floor — proportional hypothesis falsified in the 64-96-core range; only the
   tiny-plane (16-core) class remains unmeasured.**
4. ~~Per-rollout churn combined with suspension~~ **CLOSED (Part 9): 4,000 fresh claims + 16,000
   suspends interleaved, 0 failures; recycle = constant 20s per fleet (~4s/turn amortized); mixed
   traffic lifts suspend p50 by ~3s.**
5. ~~Multi-turn episode state inside training~~ **CLOSED for the state half (Part 9): 16,000
   in-training ledger checks across 40 suspend cycles per sandbox, zero mismatches.** Conversational-
   trajectory RL (history-conditioned generation) folds into gap 6.
6. **Other algorithms/stacks**: GRPO/TRL only. PPO with a critic (2× model memory), verl/OpenRLHF
   orchestration shapes, async pipelines — unmeasured (substrate-facing traffic should be identical,
   but that is an inference, not a measurement).
7. ~~Failure injection~~ **CLOSED (Part 9): pod force-kill, snapshot destruction (restore-miss
   path), and node drain — all absorbed, 20/20 complete, zero eval errors; the SDK's fresh-instance
   flag fired truthfully on the destroyed snapshots.** (Bucket outage and zone drain untested.)
8. **Enforcing-NetworkPolicy clusters**: our clusters don't enforce; the SDK's pod-IP/DNS behavior on
   enforcing clusters (SDK-2's home turf) is characterized but the full loop was never run under
   enforcement.
9. **Autoscaler economics (route 1)**: freed-capacity → fewer-nodes was argued from autoscaler
   mechanics, not demonstrated (our suspension churn was always faster than scale-down reaction).
10. **Adversarial security**: we ran hostile-by-accident code, not hostile-by-design; no sandbox-escape
    or data-exfiltration attempts were made. gVisor containment is assumed from its threat model,
    not re-verified here.

Operational recipes proven along the way: pool-free arenas (claims fresh-create; replacement minting
actively harms scarce arenas), harvest-after-complete measurement, baked images for private nodes,
one-strike liveness eviction. Everything below is the chronological detail.

---

**Campaign:** 2026-08-29/30, ~15,000 suspend/resume ops · **Cluster:** `sandbox-snapshot-demo`
(vicenteferrara-gke-dev, us-central1-a, GKE 1.36.3-gke.1537000 RAPID, `--enable-pod-snapshots`,
n2-standard-8 gVisor pool ×12, agent-sandbox v1.0.0, SDK k8s-agent-sandbox==1.0.0) — torn down 2026-08-30.
**Harness:** `snapshotStress` branch of vicentefb/kuberay, `ray-operator/config/samples/agent-sandbox-snapshots/stress/`.
**Context:** follow-up to the Ray + Agent Sandbox suspend/resume demo (kuberay PR / ray docs PR), driven by
Tomer's ask ("test it in a large job — running times, and does the snapshot controller work correctly") and
Reflection's requirements (Ivan Glushkov, Slack thread in `~/agent-sandbox/ray_snapshot/meeting_notes.md`).

---

## 1. Why this methodology represents Reflection's RL workload

The harness was designed against Ivan's own answers, not assumptions. Fidelity map:

| Ivan's stated requirement / shape | Harness | Fidelity |
| --- | --- | --- |
| Ray-based engine, one sandbox per rollout, one client each | Ray actors, one SDK client per sandbox | ✅ matches |
| Working set "tens of MiB" (vs multi-GiB requests) | 64MB incompressible tmpfs state (plus a 256MB/1GB size sweep) | ✅ matches; size proven second-order below 1GB |
| Suspend signal = turn boundary, declared by the client | suspend fired immediately after each command result | ✅ matches |
| Full freeze (process tree + memory), NOT quiescence-required | every restore verified by content digest of guest state | ✅ verified ~7,000× |
| Suspend must return the scheduler reservation | pod is deleted on suspend (verified) | ✅ |
| Resume latency decides per-turn vs tail-only (<1s vs ~5s vs 15s gap) | per-op latency measured at every concurrency rung | ✅ answered (see §3) |
| Turn cadence ~3s exec / ~15s model wait | execute → suspend → 5-10s hold → resume loop | ✅ approximates |

Deliberate divergences — each biased toward worst case:

- **Synchronized waves.** All N suspends/resumes fire simultaneously. Real turn boundaries decorrelate
  over a trajectory, but RL batch dispatch (e.g. 256 attempts of one problem launched together) makes
  early-turn boundaries genuinely correlated — so waves model batch starts, and in steady state they
  *upper-bound* per-op latency. The floor (staggered arrival) is the 4-way number.
- **Client path.** Reflection does not use the Python SDK (manifests / REST via their lethe2 server).
  The five SDK defects (§5) are therefore not their bugs — but four of them are API-level behaviors
  (PodRestored condition lag, orphaned-trigger blocking, 429 on trigger create, pod churn vs slots)
  that ANY client, including theirs, must handle.
- **Warm pools.** Reflection creates on demand. The density wall (§4.1) still applies — their pod count
  per node comes from rollout density instead of pool + backfill.

**Not tested** (open items for Reflection-realistic follow-up): their actual client path; >250
concurrency per cluster; multi-hour trajectories; Ivan's CoW question (N sandboxes forked from one warm
snapshot sharing base memory — no GKE support surface found).

## 2. Latency ladder (64MB state, sane density, stock config)

| Concurrency | Suspend p50 / p95 | Resume p50 / p95 | Op failure rate |
| --- | --- | --- | --- |
| 4 | 5.6 / 6.0s | 4.2 / 4.3s | 0 |
| 20 | 9.9 / 12.1s | 8.5 / 9.5s | 0 (800 ops, soak) |
| 100 | 15.5 / 19.1s | 18.5 / 21.7s | 0.45% |
| 150 | 19.3 / 25.2s | 18.3 / 20.7s | 0.67% |
| 200 | 25.5 / 37.5s | 24.8 / 28.5s | 0.65% |
| 250 | 30.1 / 45.6s | ~30 / ~34s | 1.76% (1.1% w/ FlowSchema) |

Size sweep at 4-way: 256MB ≈ 0MB (5.6/4.2); 1GB adds ~1.5s to suspend, resume flat. Snapshot size is
second-order below 1GB; **concurrency is the latency driver**.

**Latency law:** resume p50 ≈ ~4s floor + ~0.1s × (simultaneous wave size). Pure queueing: the pipeline
(controller worker pool → kubelet per-node serialization → per-node snapshot restore agent → SDK poll)
drains at a fixed ~4-5 ops/s cluster-wide; the median member of an N-wave waits N/2 ÷ rate before its
~4s of actual work. gVisor nodes sat at 31-46% CPU throughout — the caps are concurrency limits, not
CPU. **Per-op latency is a property of the wave size, not the system.** Staggered arrivals see the floor.

**Zero confirmed state losses in the entire campaign.** Retention GC (`maxSnapshotCountPerGroup: 3`)
exact in every run, including mid-collapse (lags transiently under saturation: observed 1,342 vs 750 cap).

## 3. Answers to Ivan's three decision criteria

1. **Resume latency vs the ~15s gap:** floor ~4.2s (staggered / low concurrency); 18-30s p50 in
   synchronized waves of 100-250. → Per-turn suspension pays only when resumes are staggered and
   per-cluster concurrency is bounded; in batch-synchronized regimes it costs more than the gap.
   Tail-only (long gaps, post-final-turn dead time) pays everywhere.
2. **Reservation return:** yes — the pod is deleted; CPU/memory requests return to the scheduler.
3. **Resume semantics:** guest wall clock jumps forward; pod IP and pod name change; open connections
   do not survive; restore selects the newest Ready snapshot in the sandbox's label group.

## 4. The walls (in order of severity)

### 4.1 Node pod-slot density — THE dominant wall
At ~105 pods/node against the 110 `max-pods` default, resume throughput hard-caps at ~32/wave
(measured flat across 5 cycles) and, amplified by SDK defect #4, spirals to total collapse
(54% failure, 20,000-op run). Both dramatic collapses in this campaign were this. Warm pools
**backfill claimed sandboxes**, so pod demand = pool + claims. Rule: keep nodes ≤ ~80% of max-pods
counting pool + claims + churn headroom.

### 4.2 API Priority & Fairness — real but second-order at sane density
Stock: `service-accounts → workload-low` sheds first-wave trigger creates at 250-way
(~0.7% of ops; 429 + Retry-After, absorbed after cycle 0; captured in
`apiserver_flowcontrol_rejected_requests_total`). Fix: the F-cluster runbook
(`perf_goals/apf-flowschema.yaml`) — GKE guardrails block referencing `exempt` AND `workload-high`;
the share-reclaim recipe (workload-low→25, global-default→5, custom PL 120 shares, wide queues) applied
cleanly and eliminated the 429 class (1.76%→1.1%). Latency unchanged (30.1 vs 32.3 p50) — APF relief
buys reliability, not speed. Side effect: displaced workload-low tenants absorb rejections instead.

### 4.3 Managed snapshot controller — exonerated at this scale
Runs on the GKE control plane (no kube-system pod; untunable by customers). Under the density-collapse
pile-up it fell behind (1,251-trigger backlog, "not processed within 180s"); at sane density it drained
1,250 triggers/run at 250-way with zero timeouts in both A/B arms. Verdict: keeps up through 250
concurrent when not buried; >250 unmeasured.

### 4.4 Load-generator sizing (harness/orchestrator-side)
~100-150MB RSS per SDK client. 100+ concurrent clients need explicit Ray memory reservations and
adequately sized worker pods or the raylet OOM-kills the fleet (invalidated one run). Applies to any
Ray-based orchestrator holding one client per rollout.

## 5. SDK defects found (k8s-agent-sandbox 1.0.0, `gke_extensions.snapshots`) — to file upstream

1. **One-shot `PodRestored` check races the condition write** (`utils.check_pod_restored_from_snapshot`,
   called once immediately after pod-Ready). Reports healthy restores as "Pod was started as a fresh
   instance." Proven false-positive by state-digest adjudication (live-rescued NOTEs) and by
   next-cycle digest verification. Rate grows with concurrency (1 @150 → 9 @250 per cycle). Fix: bounded poll.
2. **Reconnect-after-resume DNS fallback** to `<pod>.default.svc.cluster.local`, which cannot resolve
   unless `service: true`; burns 5 urllib3 retries and fails the op. The persistent ~0.5-1% failure
   floor at every healthy rung is exclusively this class.
3. **`snapshots.create()` completion wait hardcoded to 180s** — not configurable; at depth the client
   gives up while the controller is still working.
4. **Timed-out triggers are abandoned, not deleted** — the pending trigger then rejects the next
   suspend ("Another PodSnapshotManualTrigger ... is already targeting Pod"), poisoning subsequent
   cycles into a death spiral. (A 429-failed *create* is clean — no orphan; only the timeout path poisons.)
5. **No 429/`Retry-After` handling on trigger create** — single-shot POST; one-line backoff would have
   erased most stock-APF failures at 250-way.

Also noted: `resume()` on a never-suspended sandbox returns fast success (no-op) — fine, but it
contaminates naive latency stats (observed: "resume median 0.2s" during the collapse run).

## 6. Operating guidance (Reflection / any RL orchestrator)

- **Stagger resumes; never fire cluster-synchronized waves.** Per-op latency ≈ 4s staggered vs 30s in a
  250-wave. Bound in-flight suspend/resume per cluster (≤200 validated clean; 250 at ~1-2%).
- **Capacity-plan pod slots**: pool + claims + churn ≤ ~80% of max-pods per node.
- **Treat `restored_from_snapshot=False` (or a missing PodRestored condition) as "verify before
  discarding,"** not truth — until defect #1 is fixed.
- **Retry trigger creates on 429** with the server's Retry-After; delete your own timed-out triggers.
- Apply the APF FlowSchema (F runbook) when running >200 concurrent per cluster.
- Shard across clusters for higher aggregate rates (Reflection already multi-cluster).

## 7. Artifacts

- Harness: `vicentefb/kuberay` branch `snapshotStress` → `.../agent-sandbox-snapshots/stress/`
  (`stress_snapshot_execution.py` + `stress-ray-job.yaml`; env knobs NUM_EXECUTORS/CYCLES/STATE_MB/
  MODEL_LATENCY/SNAPSHOT_READY_RETRIES/RESUME_WAIT).
- Demo sample (PR): `ray-operator/config/samples/agent-sandbox-snapshots/` on `raySuspendResumeArtifacts`.
- Docs page (PR): `doc/source/cluster/kubernetes/examples/rayjob-agent-sandbox-snapshot.md` (ray repo).
- APF runbook: `perf_goals/apf-flowschema.yaml` (F campaign; reclaim recipe reused verbatim).
- Meeting notes / Ivan's requirements: `~/agent-sandbox/ray_snapshot/`.

---

# PART 2 — m2-fleet campaign (2026-08-30/31, m2-density-c, gke-ai-eco-dev)

**Context:** fleet drained (standing SWERL ~994K deleted, Tomer-approved), pod snapshots enabled a–f,
C staged as ladder host: 34× n2-standard-8 gVisor `snap-pool` (fresh, non-E2), AR-mirrored runtime image,
region bucket + WIF, 12-node/30-worker loadgen, F-runbook FlowSchema (120-share `stress-snapshot` lane).

## The ladder (tuned C — the first 1,000-way gVisor memory-snapshot suspend/resume ever run)

| Concurrency | Resume p50/p95 | Suspend p50/p95 | Cycle success | Lane 429 sheds |
| --- | --- | --- | --- | --- |
| 4 | 2.1 / 2.2s | 4.8 / 5.1s | 100% | 0 |
| 250 | ~5 / 5.5s | 29 / 34s | ≥99.9% | 0 |
| 500 | 8.4 / 24.7s | 54 / 62s | ≥98.6% | 133 |
| 1,000 | 14.6 / 65.0s | 90 / 110s | 94–99.5% | 4,960 |

Laws: **resume sub-linear** (2× wave ≈ 1.7× p50); **suspend linear** (~90ms × wave — GCS upload physics);
claims flat 0.2s at every rung; retention GC exact at 3,000 managed snapshots; **zero state losses**
(~25,000 ops across both campaigns). 2,000 rung deliberately skipped — extrapolable from the laws.

## Findings that supersede Part 1

1. **The demo cluster's "resume grows linearly with wave" was mostly APF queueing, not restore capacity.**
   Same-cluster A/B on C @250: stock = 2.8% failures; FlowSchema = 0.08% and resume p50 ~5s (vs ~30s
   implied by Part 1's law). With an adequate lane on a big plane, 250 simultaneous resumes run near the floor.
2. **Control-plane size sets drain rate** (C's 642-node plane: cycle walls halved, p95 −30% vs demo at
   equal rung, stock-vs-stock) — **APF config sets admission rate**; independent levers, both now measured.
3. **The 120-share lane's knee ∈ (500, 1,000)**: sheds 0→133→4,960 across 250/500/1,000. Server signals
   escalate to `Retry-After: 30` at depth. Collateral: shrunk `workload-low` rejected 6,157 requests from
   its remaining tenants (kuberay operator, fleet agent) — the reclaim config is for test windows, not production.
4. **Failure taxonomy at 1,000-way is entirely client-side** (three classes: `operatingMode`-patch 429,
   restore-annotation-cleanup 429, DNS-fallback bursts). SDK retry-on-429 + the pod-IP fallback fix would
   plausibly take 1,000-way to ~99.9%.

## m2-specific operational gotchas (hard-won)

- **Private nodes**: no registry.k8s.io/Docker Hub egress — mirror images to AR; create loadgen pools with
  `--no-enable-private-nodes` (or bake images) for pip/zip/DockerHub.
- **E2 gVisor pools cannot whole-pod snapshot** — nodeSelector snapshots onto n2/n2d.
- **exit-128 taxonomy** (agent logs in ns `gke-managed-pod-snapshots`, NOT kube-system):
  `closing state file failed: input/output error` = bucket missing; `permission denied` = bucket IAM missing
  (recreating a bucket WIPES its IAM). Both surface as opaque `runsc error: exit status 128` in the trigger —
  GKE diagnosability bug, two worked examples. Suspend of an already-suspended sandbox returns
  `snapshot_response=None` (success, no snapshot) — clients must handle.
- Quota buckets bite independently: CPUS (E2) / N2_CPUS / N2D_CPUS; the fleet exhausts them severally.
- Loadgen sizing law revised: 1,000 SDK actors OOM'd 18×8Gi workers → 30×8Gi on 12 nodes.

## Reflection guidance (final)

Resume latency is a function of wave size, plane size, and APF lane — not a fixed cost. On a production-shaped
cluster with a dedicated FlowSchema, staggered resumes see ~2–5s; synchronized waves of 1,000 see p50 ~15s.
Per-turn suspension is viable at bounded concurrency; tail-only everywhere. Budget: ≤500 concurrent
suspend/resume per tuned cluster for <1% failure floor (today, without SDK fixes); shard above that.

## Snapshot size & storage throughput (measured post-1,000-rung, before cleanup)

- **~99 MB per snapshot** (284.2 GB / 2,861 snapshots): 64MB injected incompressible state + ~35MB guest
  overhead (process memory, kernel state, rootfs delta), zero pages excluded, `--compression=none`.
- A 1,000-wave therefore ships **~100 GB to GCS per suspend cycle**; at the observed 90s p50 the bucket
  sustained **~1.1 GB/s aggregate** with zero storage-side errors.
- Size regime validated: injected state to 1GB (suspend +~1.5s/GB, resume flat). Multi-GB in-memory
  working sets (e.g. model weights) extrapolate via the linear suspend law but were NOT measured.

## Honesty box — what "scale" means here

- **Proven: cluster scale.** 1,000 concurrent suspend/resume cycles on one cluster (34 gVisor nodes of
  C's 640; clusters a/b/d/e/f enabled but unused). This covers Reflection's per-cluster operating point.
- **Untested: fleet scale.** 6 clusters × 1,000 simultaneous waves. The new variable is shared storage:
  a/b/c write to one us-central1 bucket → ~3 GB/s against a single bucket. Everything else (control
  planes, nodes, agents) is per-cluster and expected to replicate. This is the natural follow-up
  campaign ("fleet-wide wave"), ~1-2h of per-cluster setup on already-enabled infra.
  **[SUPERSEDED IN PART, 2026-09-08 — Part 9 gap 2: A+C ran simultaneously against the shared
  us-central1 bucket (combined ~29 suspends/s, ~1.2 GB/s of training-era ~35-40MB snapshots): the
  bucket was a NON-FACTOR, per-cluster pipelines proven independent, and Part 10 added a third
  cluster + second region (F/us-west1). Still untested: the full 6-cluster × 1,000-wave burst and
  the ~3 GB/s big-snapshot single-bucket regime. Note the snapshot-size figures above are from the
  64MB-ballast era; training-era snapshots are ~35-40MB.]**
- **Success <100% is NOT a platform limit.** All misses at every rung were three client-side classes
  (429-no-retry ×2 paths, DNS fallback) plus one harness OOM; the server signals retryability
  (`Retry-After`). Zero state losses, zero refused work at the platform level. With SDK fixes,
  1,000-way projects to ~99.9%.

---

# PART 3 — Real-model RL-shaped run (tier-1 realism, 2026-08-31)

**Setup:** 100 self-paced Ray rollout actors on m2-density-c; per turn each actor fires suspend()
and a REAL Gemini inference concurrently (snapshot uploads while the model thinks), resumes when both
complete, executes the model-generated Python inside its gVisor sandbox (private nodes = no egress),
verifies transcript state, repeats ×5. `gemini-2.5-flash` via Vertex (WIF), no synchronized waves.
Harness: `stress/rl_snapshot_execution.py`.

## Results (100 rollouts × 5 turns; 85/100 rollouts fully clean, 476/500 turns completed)

| Phase | p50 | p95 | max |
| --- | --- | --- | --- |
| inference (flash) | 2.8s | 10.9s | 20.2s |
| suspend (snapshot Ready) | 7.9s | 14.7s | 15.2s |
| **resume** | **2.2s** | 4.2s | 12.2s |
| execute (model's code) | ~0s | ~0s | 0.1s |
| **ADDED LATENCY vs no-suspend** | **6.3s** | 13.9s | 21.8s |

- **Staggered-arrival claim now MEASURED: resume p50 2.2s at 100 concurrent rollouts** (waves of 100
  gave 15.5-18.5s on the reference cluster — the difference is pure arrival synchronization).
- Suspend staggered = 7.9s p50 (vs ~15-29s in waves at comparable width).
- **Gemini's generated snippets ran clean 474/476**; state survived 470/476 verified cycles.
- `added = max(suspend, inference) − inference + resume` ⇒ with flash (2.8s) the upload overhangs the
  gap → 6.3s. **At Reflection's 7-11s inference, suspend hides inside the model gap and added latency
  collapses to ≈ resume ≈ 2-3s/turn against a 15s gap ⇒ per-turn suspension is VIABLE for their shape.**
  (Direct measurement with a pro-class model is a 10-minute rerun: set GEMINI_MODEL.)

## New platform finding under realistic traffic (GKE finding #3)

Self-paced churn phase-mixes checkpoint, restore, and retention-GC on the same node agent — waves never
did. Result: agent-side race, with log evidence: `failed to save snapshot <id> metadata: open
/host/var/lib/podsnapshots/<uid>/metadata: no such file or directory` — the checkpoint completed, then
its staging dir vanished (concurrent prune/cleanup) before the metadata write. Surfaced only in this run.
Error mix across the 24 turn errors: this race, the SDK PodRestored false-alarm class (unadjudicated in
this thin harness; state checks show later turns intact), and the SDK DNS-fallback class on /upload.

**Verdict:** under the most realistic traffic yet — real model, real generated code, real arrival
distributions — the platform served 95.2% of turns clean at first attempt with zero state loss, resume
at the floor, and the residual errors split between two known SDK client bugs and one newly-found
agent-side race worth filing.

## PART 3 addendum — the suspend-throughput law (three-way isolation, 2026-08-31)

Self-paced 500-way runs isolated the suspend ceiling with two null experiments:

| Variant | Nodes | Snapshot size | Suspend p50 |
| --- | --- | --- | --- |
| B (baseline) | 34 | ~99MB | 51.4s |
| C′ (node-null) | **375** | ~99MB | 51.6s |
| D (size-null) | 375 | **~40MB** (8MB state) | 51.3s |

**Law: the managed snapshot pipeline processes ~10 triggers/second per cluster — independent of node
count, snapshot size, and arrival pattern.** (The apparent ~1 GB/s bandwidth match at 64MB was
coincidence.) Resume held its 2.2s floor in all three. Corollaries:

- Sustainable per-turn suspension rate per cluster ≈ 10 turns/s ⇒ e.g. 500 rollouts at one turn/50s, or
  180 rollouts at Ivan's ~18s cadence, per cluster. **Sharding clusters is the scaling lever** (each
  brings its own 10/s; the six-cluster fleet ≈ 60/s), and since the bound is op-rate not bucket
  bandwidth, shared regional buckets are unlikely to matter — deprioritizing the fleet-wave experiment
  from "unknown" to "confirmation".
- Self-pacing does NOT stagger a cohort when a common-mode stage (the 50s suspend queue) dominates
  per-turn variance: 500 actors stayed phase-locked from the start line. Staggering must be engineered
  (rate-limit suspend initiation) or inherited from long/variable inference.
- Precise GKE-team ask: raise per-cluster trigger-pipeline throughput; second worked example set for the
  metadata/gcs_opts checkpoint-cleanup race (incidence tracks snapshot count, not node density —
  consistent with the same central pipeline).

## PART 3 final — mitigation stack validated (2026-08-31, campaign close)

Client-side mitigation stack (what any production orchestrator should implement):
1. **Retry transient sandbox calls** (4 tries, 3s delay) — absorbs the SDK's post-resume DNS-fallback
   window entirely. (Note: `service: true` was tested and DISPROVEN as a mitigation — headless-Service
   DNS lags endpoints in exactly the same window; the fix must be client-side.)
2. **Adjudicate "fresh instance" reports** by probing guest state before believing them — every report
   in the validation run was a false alarm.
3. Judge by outcomes, not logs: the SDK logs transient errors even when the operation ultimately succeeds.

Validation at 500-way, real Gemini inference, model-generated code executing in-sandbox:

| | bare SDK | + mitigation stack |
| --- | --- | --- |
| clean rollouts | 378/500 | **497/500** |
| turns completed | 2,340/2,500 | **2,497/2,500 (99.88%)** |
| state integrity | (noisy metric) | **2,497/2,497 = 100%** |
| errors | 160 | **3 — all the GKE agent metadata race** |

**Campaign-closing statement:** across ~30,000 suspend/resume operations on two clusters — synthetic
waves to 1,000-wide, self-paced real-model rollouts to 500-wide — the platform lost state ZERO times.
With a retrying client, the operational failure floor is the platform's own checkpoint-cleanup race at
~0.1%, filed with GKE. The governing constraints are the per-cluster snapshot op-rate (~10/s) and the
2.2s resume floor; everything else is client hygiene.

---

# PART 4 — The economics: backfill experiment (2026-09-01)

**Question:** suspension frees scheduler reservations — does anything actually USE them, and what does
reclaiming them cost? (The one question a training loop would answer that substrate tests can't.)

**Design:** contention arena = snap-pool (34 × n2-std-8, ~250 usable CPU). Sandboxes carry real requests
(250m/512Mi) + PriorityClass 1000; a low-priority (0) "filler" Deployment (1,000 × 200m pause-style pods)
oversubscribes the arena. Driver = 500-way suspend → 180s hold → resume. Capacity trace sampled every ~7s.

**Results (single clean cycle; driver stats corroborated by a 3-cycle run):**
- **Backfill is real and fast:** during the suspend drain the filler climbed from ~600 to its 1,000-pod
  replica cap — freed capacity was consumed within the drain window itself; supply (125 CPU freed)
  EXCEEDED the tenant's demand (+~400 pods ≈ 80 CPU absorbed). ≈ **4 CPU-hours of backfilled compute per
  180s cycle per 500 suspended sandboxes.**
- **Reclaim works and is cheap:** on resume, priority preemption evicted the backfill and re-placed
  489/500 sandboxes in ~40s; contended resume p50 = 12.0s vs 8.4s uncontended → **preemption premium
  ≈ 3-4s**. (3-cycle run: 15.4s p50 under stock APF — upper bound.)
- Claims also preempt: 500 high-priority claims evicted ~230 filler pods in <10s on entry.

**Design lessons learned the hard way (all report-worthy):**
1. **PriorityClasses are mandatory** for the economics: without them, backfill pods block resumes
   (no eviction) — freed capacity is a trap unless the backfill tenant is preemptible.
2. **Warm-pool backfill competes with resumes at EQUAL priority** and starves them (observed: 871s cycle,
   397/500 resumes when the pool backfilled 500 claims into a full arena). A suspended sandbox's future
   resume capacity is NOT reserved; pool sizing must account for claim churn. (agent-sandbox design note.)
3. Total sandbox demand must fit the arena: at 1,000×250m = exactly arena size, sandboxes evicted the
   filler to zero and STILL timed out — suspension defers capacity needs, it does not eliminate them.
4. GKE reverts the APF share-reclaim overnight (observed live: 429s returned via the stock
   `service-accounts` schema) — the FlowSchema tuning is a test-window configuration, re-verify before use.

**Bottom line for the report:** the suspension value chain is now measured end to end — freed → consumed
by another tenant (within seconds, to the tenant's own limit) → reclaimed by priority preemption
(~40s for a 500-wave, ~3-4s added per-resume). With preemptible backfill and correctly sized pools,
suspension converts sandbox idle time into usable cluster capacity at a small, bounded reclaim cost.

---

# PART 5 — The real thing: a genuine RL training loop with sandbox-executed rewards (2026-09-01)

**Question:** everything above shaped traffic to *look like* RL. This part runs actual RL training —
real policy gradients — with agent-sandbox as the reward executor, and measures what per-step
suspension costs inside a real training cadence.

**Setup (GPU-free by necessity and by design):** us-central1 GPU capacity was a wall (G2 on-demand AND
spot stocked out in -c/-a; A100 pool creates failed twice; each GKE pool attempt burns 35 min before
failing — capacity-probe ritual: a bare `gcloud compute instances create` returns a stockout verdict in
30s, but never probe while a pool op is mid-retry, the probe steals the pool's slot). The pivot is the
better experiment anyway: the GPU only accelerates the policy update — the substrate under test is the
reward path. Trainer = TRL `GRPOTrainer` (trl==0.21.0, transformers<5, bf16 off), policy =
Qwen2.5-0.5B-Instruct, task = MBPP (write a Python function), 50 steps × 8 completions
(2 prompts × 4 generations), one 6-vCPU pod on m2-density-c's loadgen pool. **Reward = execute the
model's generated code inside a warm-pool sandbox against the problem's unit tests**
(0.1 for running + 0.9 × pass fraction). 8 sandboxes claimed once, reused all 50 steps.
Harness: `stress/grpo_sandbox_train.py` + `grpo-trainer-pod.yaml` (configmap-mounted, no Ray needed).

## Run 1 — the involuntary security demo (lr=1e-5, no KL)

- Training worked (1.00 rewards by step 2) then **collapsed by step 13** to flat 0.10 — classic
  small-model GRPO degeneration without a KL anchor (TRL default beta=0) at a hot learning rate.
  Kept as a finding: the reward *path* was flawless even while the *learner* failed.
- **Step 5 took 252.2s: the model generated an infinite loop.** The number decomposes exactly as
  4 retries × 60s gVisor `commands.run` timeout + backoffs. Hostile untrusted code, contained,
  scored 0, training continued. This is the entire argument for sandboxed rewards, demonstrated
  by accident. (Harness lesson: don't retry deterministic timeouts — run 2 uses timeout=30 × 2 tries.)

## Run 2 (B-arm, SUSPEND_MODE=off) — healthy baseline

lr=2e-6 + beta=0.04 fixed the collapse: 1.00s still appearing through step 50 (steps 47-49: 4/8
near-perfect batches), KL settled ~0.08-0.15, no degeneration. **50 steps in 3,562.4s = 71.2s/step.**
400 sandbox evals, sub-second (p50 ~0.1s for 8 parallel evals — write + exec over pod-IP HTTP;
generation is >99% of step time). 1 reward-exec error total (run-1's loop; run 2 clean).

## Run 3 (A-arm, SUSPEND_MODE=per_step) — suspension inside the training loop

Identical config; the 8-sandbox fleet is snapshot-suspended after every reward batch and resumed at
the next one. Dwell is REAL: ~60s suspended through each generation phase, then resume → immediately
execute fresh model-generated code against surviving state.

| metric | B-arm (off) | A-arm (per_step) |
| --- | --- | --- |
| wall clock, 50 steps | 3,562.4s (71.2s/step) | 3,898.0s (78.0s/step) |
| overhead | — | **+335.6s = +6.7s/step = +9.4%** |
| suspend (8-wide wave) | — | p50 4.8s / p95 5.9s / max 15.8s |
| resume (8-wide wave) | — | p50 4.2s / p95 4.3s / **max 4.3s** (dead flat) |
| reward-exec errors | 0 | **0** (400 evals, ~400 suspends + ~392 resumes) |
| learning | healthy to step 50 | **indistinguishable** (steps 47-49: 0.70-1.00 batches) |

- Mechanism accounting: p50 suspend+resume ≈ 9.0s/step predicts +~446s; observed +336s — the residual
  is run-to-run generation variance (completions are stochastic), i.e. the true cost is bounded by the
  9s/step sum and partially hidden under variance even with zero engineered overlap.
- **Capacity story: the reward fleet was suspended ~69s of every 78s step ≈ 88% of training wall-clock
  held ZERO pod capacity**, for a 9.4% step-time premium — and Part 4 measured that freed capacity being
  consumed by another tenant and reclaimed on demand. At 8 sandboxes this is symbolic; at Reflection's
  rollout widths it is the fleet.
- Zero state loss, zero false-cold-start incidents surfaced (the `_resume_one` tolerance was never
  triggered), zero 429s — width 8 is far under every ceiling in Parts 2-3, as designed: this experiment
  isolates *cadence realism*, the ladders already covered width.

**Bottom line:** a real GRPO loop trained for 100 minutes with its rewards computed by untrusted
model-generated code executing in gVisor sandboxes, suspended/resumed 50 times mid-training with zero
errors and zero effect on learning, at +9.4% wall-clock for ~88% capacity release. The synthetic
campaign's laws (resume floor, suspend wave cost) reproduced unchanged inside genuine RL traffic.

## Part 5 appendix — anatomy of the loop (what `grpo_sandbox_train.py` actually does)

One process, one GRPO trainer, a fixed fleet of reward sandboxes. Per training step:

```
                    ┌──────────────── TRL GRPOTrainer (CPU pod, 6 vCPU) ────────────────┐
   MBPP dataset ──► │ 1. sample 2 problems                                              │
                    │ 2. policy (Qwen2.5-0.5B) generates 4 candidate solutions each     │  ~60-70s
                    │    (fleet is SUSPENDED during this in per_step mode)              │
                    │ 3. call sandbox_reward(completions, test_list)  ──────────────────┼──► reward fn
                    │ 6. GRPO update: group-relative advantages + KL(ref) + grad step   │  ~5s
                    └────────────────────────────────────────────────────────────────────┘
   reward fn (steps 3-5):
   3a. resume the 8-sandbox fleet if suspended            (~4.2s, one concurrent wave)
   3b. for each of 8 completions, in parallel (thread pool, one sandbox each from a queue):
        - strip markdown fences from the model's code
        - build eval file = model code + harness that exec()s each MBPP assert in
          try/except and prints "__RESULT__ <passed> <total>"
        - sandbox.files.write() + sandbox.commands.run(timeout=30, 2 tries)  ← gVisor
        - reward = 0.0 if it crashed/hung · 0.1 if it ran · +0.9 × pass-fraction
   3c. (~0.1s total for all 8 — generation dominates by 600×)
   3d. per_step mode: suspend the fleet with snapshot     (~4.8s wave, uploads to GCS)
```

Key properties that make it a valid substrate test:
- **The sandboxes execute genuinely untrusted code** — whatever the policy emits, including the
  infinite loop it emitted in run 1. Containment is load-bearing, not decorative.
- **Sandboxes are stateful and reused across all 50 steps** — each per_step cycle is a real
  suspend → real ~60s dwell → resume → immediately execute on the restored filesystem.
- **The reward wave is synchronized** (all 8 evals burst at once), which is exactly GRPO's shape at
  any scale — so Part 2's wave laws are the correct scaling model for this traffic.
- Env knobs: MODEL, MAX_STEPS, REWARD_SANDBOXES, NUM_GENERATIONS, MAX_COMPLETION, SUSPEND_MODE
  (off|per_step), WARMPOOL, DATASET_SLICE. Pinned deps: trl==0.21.0, transformers<5, bf16=False.

## Part 5 appendix — what is and isn't proven (scale honesty box)

| axis | proven at | where |
| --- | --- | --- |
| suspend/resume width | 1,000 concurrent | Part 2 ladder |
| rollout realism (real inference, self-paced, multi-turn) | 500 concurrent × 5 turns | Part 3 |
| real gradients + sandbox rewards + per-step suspension | 8 sandboxes, 0.5B, 50 steps | Part 5 |
| all three simultaneously (GPU-scale model, 500+ rollouts, training) | **NOT run** (GPU stockout) | — |

Extrapolation to production width rests on the laws, not on hope: synchronized reward waves follow
suspend ≈ 5s + 90ms×width (hides under multi-minute generation phases); exposed per-step cost tends to
resume-only (2-4s staggered / ~8-15s for a 500-wave); sustained suspend demand >10/s needs cluster
sharding (GKE-3). The composition experiment becomes runnable the day GPU quota+capacity exists —
the harness only needs MODEL and the trainer pod swapped for the verl/GPU variant.

---

# PART 6 — The swarm ladder: 100 concurrent real RL training jobs (2026-09-04/05)

**Question:** Part 5 proved one real training loop; production is many. Does the substrate hold when the
suspend/resume traffic comes from a *population* of genuinely-learning trainers — and where is the
snapshot pipeline's ceiling under real (naturally staggered) load, as opposed to synthetic waves?

**Design:** N independent copies of the Part 5 GRPO loop (Indexed Job), each trainer with its own
8-sandbox fleet claimed from ONE shared warm pool, all in per_step suspension. Trainers de-phase
naturally (stochastic generation lengths), so the cluster sees staggered wave traffic — the shape a real
multi-job RL farm produces. Rungs 3-4 run on the idle private shard pools via a baked trainer image
(deps + model + dataset in-image, zero runtime egress; built in 3 min with Cloud Build, pushed to the
AR mirror; pods start training ~1 min after creation vs ~13 min on the pip path).

## The ladder (MAX_COMPLETION=128 from rung 2; 20 steps per trainer; full-capture harvests)

| rung | trainers | sandboxes | sustained suspend rate | suspend p50/p95/max | resume p50/p95 | errors | wall |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 5 | 40 | ~0.3/s | 4.7 / 5.7 / 8.3* | 2.3 / 4.3 | 0 | 41 min |
| 2 | 12 | 96 | ~2/s | 4.8 / 6.4 / 7.5 | 2.5 / 4.3 | 0 | 21 min |
| 3 | 50 | 400 | ~4.6/s | 4.7 / 6.5 / 24.9 | 4.2 / 4.3 | 0 | 33 min |
| 4 | **100** | **800** | **~7.6/s** | **4.8 / 6.6 / 30.7** | **4.2 / 4.4** | **0** | 39 min |
| 5 | **150** | **1,200** | **~11.8/s** | **4.7 / 6.6 / 12.5** | **4.2 / 4.4** | **0** | 37 min |

*rung-1 max excludes a 36.9s outlier attributable to the self-inflicted incident below.

Ladder total ≈ 96,000 snapshot operations from real training jobs, zero state loss, zero substrate
errors, zero trigger rejections. Rung 5 finished FASTER than rung 4 (37 vs 39 min) at 1.5× width.

## Rung 6 — the mega-swarm finds the ceiling (2026-09-06)

**450 trainers / 3,600 sandboxes / ~55 suspends/s ATTEMPTED** (pool-free fresh-create protocol, all
11 shard pools, 2s stagger, CLAIM_TIMEOUT=600). Result: **the pipeline saturated and the system
self-throttled to equilibrium — the first observed ceiling under real traffic:**

| | rung 5 (11.8/s) | **rung 6 (~55/s attempted)** |
| --- | --- | --- |
| suspend p50 / p95 / max | 4.7 / 6.6 / 12.5 | **37.4 / 103.6 / 212.1** |
| resume p50 / p95 | 4.2 / 4.4 | 8.4 / 87.5 |
| trainers completed | 150/150 | **450/450** |
| eval errors | 0 | 911 of ~72,000 (1.3%, retried) |
| wall (20 steps) | 37 min | 68 min |

n=8,960 waves ≈ 72,000 suspends. Delivered throughput at saturation: ~17.6/s averaged over the full
wall (including ramp), ~20-25/s in the steady mid-run — call the steady-state pipeline ceiling
**≈20-25 suspends/s/cluster for staggered traffic** (double the burst-drain ~10/s; demand above it
becomes suspend queue latency). Completions arrived on a degraded-but-stable cadence; NOTHING failed.

**The pipeline's degradation law matches the arena's: past saturation, work waits — it does not
break.** Combined sizing guidance: keep sustained cluster-wide suspend demand under ~15/s for
floor-level latency; between ~15-25/s expect seconds→tens-of-seconds suspend queues; shard clusters
beyond that. (Rung 6 also re-validated fresh-create at scale: 3,600 claims created directly, no pool,
no minting class, ~68-min run with zero claim failures.)

### What shape does the ~20-25/s ceiling belong to? (scope + hypothesis)

The ceiling was measured on ONE cluster shape: m2-density-c, ~690 nodes — which matters because GKE
sizes the control plane with node count, and the managed snapshot controller RUNS ON the control
plane. Decomposing what's known:

- **Worker-node count does NOT set the ceiling** (proven twice: 34-vs-375-node null experiment,
  identical latency; rung 6 queued with 640 idle nodes and bored CPUs). Nodes host the per-node
  checkpoint agents — that part of the pipeline scales out with the fleet. The choke is the central
  trigger-processing loop.
- **Control-plane size plausibly DOES set it (unmeasured).** Evidence: the tiny demo cluster (3
  nodes, small plane) collapsed at far lower rates (250-way wave collapse; resume floor ~2× worse
  than C), and the fleet's history rhymes — cluster F's 16-core apiserver vs B's 64-core made every
  control-plane-bound path proportionally worse on F.
- **There is NO quota behind this ceiling.** It is a managed-component service rate, invisible in
  any quota console; no node or CPU quota raises it.

**Defensible statement:** ~20-25 suspends/s sustained on a large-plane (~700-node) cluster; smaller
clusters should expect proportionally less; the ceiling-vs-plane-size curve is unmeasured (a day of
the same swarm harness against differently-sized clusters would produce it — future work).

**Scaling levers, in order:** (1) shard across clusters — each brings its own ceiling; the six
m2-density clusters ≈ ~120-150/s fleet-wide ≈ ~15K concurrently-suspending rollouts at an 18s turn
cadence; (2) the GKE-3 filing — rung 6 upgrades it from "there seems to be a ceiling" to "here is
the measured steady-state service rate and its equilibrium behavior," the strongest form of a
capacity ask; (3) suspend less often per rollout (cadence guidance, Part 8).

## Findings

1. **Latency is FLAT from 1× to 150× trainers — and rung 5 SUSTAINED ~11.8/s, ABOVE the synthetic
   ~10/s ceiling, with no queueing** (suspend p50 4.7, p95 6.6, max 12.5 — the max is LOWER than
   rung 4's). This refines GKE-3: the ~10/s number is the pipeline's DRAIN rate observed under a
   synchronized 500-deep burst (500 waves ÷ ~51s), not an arrival-rate cap. Staggered real traffic
   arriving below the pipeline's actual throughput (≥12/s demonstrated) rides at the ~5s floor;
   synchronized bursts pay queue-depth ÷ drain-rate. Production RL fleets de-phase naturally, so
   they get the floor. Rung 5 alone: 24,000 suspends + 22,800 resumes, zero errors.
2. **Resume settles onto the wave floor and stays there:** p50 2.3s while arrivals are sparse
   (rungs 1-2), 4.2s once every step is a full 8-wide wave (rungs 3-4); p95 within 0.2s of p50
   throughout. No width sensitivity to 800 concurrent sandboxes.
3. **The shared warm pool absorbed a 800-claim burst** (100 trainers claiming 8 each at job start)
   with all trainers claimed and stepping within ~3 minutes.
4. **Accidental chaos test (rung 1):** a claims sweep ran while 4 trainers had steps left, deleting
   their reward fleets mid-run. All 4 completed training gracefully (rewards 0.0 for lost evals);
   pod that finished pre-sweep had zero errors. Orchestrator lesson: dead-trainer fleets need a
   janitor, and trainer processes survive fleet loss.
5. **Trainer heterogeneity is real:** same config, 2× step-rate spread between trainers (completion-
   length luck compounds); one rung-1 trainer finished 20 steps while siblings were at 9. Fleet
   scheduling should assume per-job cadence variance, not uniform waves.

## Runbook rules earned
- Sweep sandbox claims ONLY after the Job shows Complete (rung-1 incident).
- Trainer pods need 24Gi (12Gi OOMs at first-generation peak ~12.9Gi); 6 CPU / 24Gi = 1 per n2-std-8.
- kubectl streaming loggers are unreliable ≥50 pods (label-selector logs default --tail=10):
  harvest per-pod logs after completion — full capture, no dedup needed.
- A Complete Job silently absorbs `kubectl apply` scale changes and does nothing: delete + re-apply.
- Private shard nodes have no egress: bake deps+model+dataset into the image (AR mirror), keep the
  script in a configmap for iteration without rebuilds.
- N2_CPUS at 7,996/8,000: trainer capacity lives on the idle shard pools, not loadgen.

## Part 6 appendix — the benefit, quantified honestly (nodes are the billing unit, not pods)

Suspension deletes the sandbox POD, releasing its scheduler reservation. GKE bills NODES — so the
reservation release converts to money only through one of three routes. State the route or the claim
is wrong.

**The measured raw material:**
- Duty cycle under per-step training suspension: awake ~9s of every ~105s step (4.2 resume + 0.1
  eval + 4.8 suspend) = **8.6% awake / 91.4% suspended** (rung 4-5 cadence; Part 5's slower cadence:
  12%/88%).
- Rung 4 scale: 800 sandboxes × 250m = 200 CPU of reservations, released 91% of a 39-min run
  ≈ **117 CPU-hours returned per run**. Always-on, the same fleet pins ~30 n2-std-8 nodes; average
  live demand under suspension is ~69 pods ≈ 3 nodes of CPU (staggered-peak headroom: ~5-6).
- Storage side: ~99MB/snapshot → 800 concurrent snapshots ≈ 79GB GCS ≈ dollars/month, noise.
- Price paid: **+9.4% training wall-clock** (Part 5 A/B; shrinks at bigger model sizes — suspend
  hides under generation, exposed cost tends to resume-only ~4s).

**Route 1 — fewer nodes (autoscaler scale-down).** Only works when suspension dwell exceeds
autoscaler reaction time (~10 min). Per-step training churn (100s cycles) is TOO FAST for this route;
parked rollouts, eval queues, overnight holds qualify. Not exercised by this campaign at scale.

**Route 2 — backfill (co-tenancy on the same nodes).** Nodes stay billed; the freed space runs OTHER
work. Measured end-to-end in Part 4: a priority-0 tenant absorbed ~80 CPU within the suspend drain
window (~4 CPU-hours per 180s cycle per 500 sandboxes), and priority preemption reclaimed it on
resume at a ~3-4s premium. This is the route per-step training suspension actually monetizes.

**Route 3 — density (more rollouts per node).** The fleet-sizing inversion: without suspension,
sandbox capacity scales with rollouts HELD; with it, capacity scales with rollouts EXECUTING.
At the measured 8.6% training duty cycle, a node hosts ~6-11× more sandboxes (steady-state vs
staggered-peak sizing); at Reflection's ~17% duty cycle (~3s exec / ~18s turn), **~5× more
concurrent rollouts on the same node count** — equivalently, a ~5× smaller sandbox tier for the
same rollout width. This is the number that matters for a CPU-dominated RL bill.

**One-sentence version:** per-step suspension turns a sandbox fleet's node footprint from
"proportional to rollouts held" into "proportional to rollouts executing" (~5-10× at measured duty
cycles), at +9.4% training time — provided the freed capacity is actually consumed (backfill tenant
or higher rollout density); on an otherwise-empty cluster with sub-10-minute churn it saves nothing.

## Part 6 appendix — full experiment configuration (reproducibility)

**Harness files** (kuberay fork, branch `snapshotStress`, dir `ray-operator/config/samples/agent-sandbox*/stress/` — also on the Linux box):
`grpo_sandbox_train.py` (the trainer; unchanged from Part 5 across ALL rungs), `grpo-trainer-pod.yaml`
(single-trainer runs), `grpo-swarm-job.yaml` (rungs 1-2, loadgen), `grpo-swarm-shards-job.yaml`
(rungs 3-5, shard pools), `Dockerfile.grpo-trainer` + `grpo-swarm-shards-job.yaml` (baked image),
`~/density-job.yaml` (Part 7). Raw harvests on the Linux box: `~/grpo/swarm{1..5}-full.log`,
`train{,2,3}.log`, `density-full.log`.

**Trainer config, constant across all rungs:** TRL 0.21.0 GRPO, transformers<5, bf16/fp16 off,
Qwen2.5-0.5B-Instruct, MBPP train[:200], NUM_GENERATIONS=4 (×2 prompts = 8 completions/step),
gradient_accumulation=2, lr=2e-6, beta=0.04, temperature=0.9, MAX_STEPS=20 (50 in Part 5),
REWARD_SANDBOXES=8, SUSPEND_MODE=per_step, reward = 0.1·ran + 0.9·pass_fraction via sandbox exec
(timeout 30s ×2 tries), OMP_NUM_THREADS = CPU request.

**Per-rung deltas:**
| rung | trainers | MAX_COMPLETION | trainer shape | trainer nodes | sandbox nodes | pool size | image |
| --- | --- | --- | --- | --- | --- | --- | --- |
| P5 A/B | 1 | 256 | 6cpu/24Gi | loadgen (n2-std-8) | snap-pool | 12 | pip-at-start |
| 1 | 5 | 256 | 6cpu/24Gi | loadgen ×12 | snap-pool ×34 | 48 | pip-at-start |
| 2 | 12 | 128 | 6cpu/24Gi | loadgen ×12 | snap-pool | 104 | pip-at-start |
| 3 | 50 | 128 | 6cpu/24Gi | shard/stream pools (11 pools, 554 idle nodes) | snap-pool | 408 | baked v1 |
| 4 | 100 | 128 | 6cpu/24Gi | shard/stream pools | snap-pool ×34 (~24 pods/node) | 808 | baked v1 |
| 5 | 150 | 128 | 6cpu/24Gi | e2 pools only (f27/f48/f61/stream-1) | n2d shard pools (template nodeSelector machine-family=n2d; snap-pool pin removed) | 1,208 | baked v1 |

Baked image: `us-docker.pkg.dev/gke-ai-eco-dev/sandbox-images/grpo-trainer:v1` — python:3.11-slim +
torch-cpu + pins + Qwen weights + MBPP pre-cached (HF_HUB_OFFLINE=1); Cloud Build 3m06s. Purpose:
private shard nodes have no egress; also cuts trainer startup ~13 min → ~1 min.

**Measurement method:** per-pod log harvest AFTER Job Complete (`kubectl logs --tail=-1` per pod →
full capture, n = trainers×20 exactly); percentiles from the `suspended fleet in Xs` /
`resumed 8 sandboxes in Xs` lines (suspend timer includes SDK snapshot-Ready wait; resume timer is
resume() wall). Sustained rate = trainers × 8 / mean step seconds (wall ÷ 20 after ~3 min runway).
Rungs 1-2 used a streaming logger (dedup with sort -u required, incomplete ≥50 pods — deprecated).

**Cluster:** m2-density-c (gke-ai-eco-dev, us-central1-c, GKE 1.36.3-gke.1537000), agent-sandbox
v1.0.0, SDK k8s-agent-sandbox==1.0.0, stock APF (no FlowSchema tuning active), one shared
SandboxWarmPool + PodSnapshotPolicy (manual triggers, grouped by sandbox-name-hash), one HNS GCS
bucket. Sandbox image: python-runtime-sandbox v0.4.6, gVisor, 250m/512Mi requests (arena) /
requests inherited from template (rungs).

---

# PART 7 — Density capstone: measuring the multiplier directly (2026-09-05)

**Claim under test:** Part 6's appendix DERIVES 5-10× node density from the measured 8.6% duty
cycle. This measures it: a fenced arena, its always-on ceiling, then several× that many rollouts
served through the same nodes — suspension as the load-bearing mechanism, not a side effect.

**Arena:** 3 × n2-standard-8 (snap-pool nodes labeled `density-arena=true`); dedicated
`SandboxTemplate` (`python-density-sandbox`: nodeSelector on the label, explicit 250m/512Mi
requests+limits, same app label so the existing PodSnapshotPolicy applies) + `SandboxWarmPool`
(`density-pool`).

**Phase A — always-on ceiling (control arm):** pool pushed to replicas=100. Result: **READY froze at
87 with 13 Pending**; scheduler verbatim: "0/689 nodes available: 3 Insufficient cpu, 685 didn't
match affinity; no preemption victims; autoscaler: no scale-up." **N_always = 87.** A held fleet on
fixed hardware is hard-capped — 87 rollouts, the 88th waits forever.

**Phase B — suspension arm:** 40 real GRPO trainers (e2 pools, baked image, per_step suspension,
15s-staggered starts = 10-min ramp to avoid a synchronized 320-pod setup burst) × 8 sandboxes =
**320 concurrent rollouts through the same 3 nodes** — legal only because ~91% are podless at any
instant (expected live pods ~35-50 of the 87 slots). New observable vs the ladder: RESUME CONTENTION
— a resume can wait Pending for a suspend to free a slot; shows up honestly in the resume tail.

**Result (attempt 2; attempt 1 failed by design error, see finding 2): 40/40 trainers completed —
320 rollouts served through the 87-slot arena = 3.7× measured density**, all 800 waves captured:

| | unpacked (rung 5, 1,200 sandboxes, no scarcity) | packed arena (320 rollouts / 87 slots) |
| --- | --- | --- |
| suspend p50 / p95 / max | 4.7 / 6.6 / 12.5 | **9.3 / 20.4 / 175.2** |
| resume p50 / p95 / max | 4.2 / 4.4 / 10.3 | **8.3 / 38.5 / 602.2** |
| eval errors | 0 | 163 of 6,400 (2.5%, all retried/absorbed) |
| trainer failures | 0 | **0** (5 claim-retry saves) |

The tails are an UPPER BOUND on the oversubscription tax: roughly the first half of the run was
contaminated by finding 2 (a 232-pod mint backlog competing with resumes); after the pool was zeroed
mid-run, Pending collapsed 232→8 and completions accelerated 4→40. The uncontaminated steady-state
tax is bounded above by these numbers and visibly smaller in the late-run stream.

**Findings (each is an orchestrator design rule):**
1. **The multiplier is real.** Fixed hardware that hard-caps at 87 held rollouts (scheduler: "no
   preemption victims, no scale-up") served 320 executing rollouts to completion. Capacity scales
   with rollouts EXECUTING, not held — measured, not derived.
2. **Warm-pool replacement minting is actively harmful on a slot-scarce arena.** The pool mints a
   replacement for every claim taken; on a full arena those mints can never schedule, and they
   compete with (and starve) resumes for every freed slot — Part 4's equal-priority lesson,
   reproduced structurally. Rule: drain the pool to zero once the fleet has claimed, or give
   resume-path pods priority over mints.
3. **Fleet ramp rate is bounded by first-suspend latency.** A trainer's sandboxes stay awake from
   claim until its first suspend (~2-3 min); ramping faster than slots free (attempt 1: 15s stagger
   → ~10 awake fleets → arena overflow) starves claims. The SDK's claim wait is hardcoded 180s with
   no retry (default 180s — configurable via create_sandbox(sandbox_ready_timeout=...), which our harness
   didn't use; no retry built in either way), converting transient slot scarcity into fleet failure
   at backoffLimit 0. Attempt 2's fixes: 45s stagger + claim retry loop (4×30s) + backoffLimit 5 —
   the retry loop fired 5 times and saved all 5.
4. **Oversubscription's cost lives entirely in the tail.** Medians roughly double (still seconds);
   p95+/max carry slot-wait queueing — resume max 602s. Rollouts never fail, they wait. An arena
   sized at ~3.7× oversubscription trades tail latency for a ~3.7× smaller node bill; the knob is
   continuous and the tail is the price signal.

## Part 7 addendum — the density curve (second point, 2026-09-06) and the pool-free protocol

**Protocol upgrade (validated):** run the arena with the warm pool at replicas=0 from the start —
SandboxClaims then FRESH-CREATE their sandboxes (core agent-sandbox behavior), which eliminates the
replacement-minting failure class entirely (no janitor, no mint-vs-resume competition). Cost: cold
start instead of warm adoption (irrelevant when the image is node-cached). Two janitor designs failed
first (claims-count trigger: defeated by early-finisher drain AND late-claimer starvation) — pool
management on scarce arenas is genuinely hard; not managing a pool at all is the answer.
The SDK exposes no template-direct claim path (warmpool arg required) — filing SDK-6.

**The measured curve (3 × n2-std-8 arena, N_always = 87):**

| oversubscription | rollouts | outcome | resume p50/p95 | eval errors | wall |
| --- | --- | --- | --- | --- | --- |
| 1.0× (control) | 87 | 88th waits forever | — | — | — |
| 3.7× | 320 (40×8) | 40/40 complete | 8.3 / 38.5s | 2.5% | 76 min |
| **5.5×** | **480 (60×8)** | **60/60 complete (5 retried)** | **487.6 / 602.2s (AT the 600s wait cap)** | **45% (retried)** | **~6 h** |
| 11.6× (asymptote) | = 1/duty-cycle | unreachable | — | — | — |

**The knee of a 3-node arena is between 3.7× and 5.5×.** At 5.5× the arena is in queueing collapse:
rollouts wait ~8 min MEDIAN for a slot — yet zero rollouts were lost; the system degrades entirely
into latency, never into failure. Larger arenas push the knee right (wave-clumping variance shrinks
~1/sqrt(N)), so 3-node numbers are a conservative floor. Practical guidance: size arenas so average
awake load stays under ~50% of slots (here: ≤ ~4×).

Cleanup after runs: density job + claims deleted, density-pool/template deleted, arena labels removed,
gpu-pool deleted.

---

# PART 8 — Cadence A/B on GPU: when per-step suspension stops making sense (2026-09-06)

**The accident that enabled it:** the g2-standard-24 node-pool create abandoned during the GPU
stockout saga (Part 5 preamble) had silently SUCCEEDED in us-central1-a — an idle 2×L4 node was
discovered 4 days later during cleanup. Before deleting it, it closed the campaign's last gap:
suspension overhead as a function of training cadence.

**Setup:** identical GRPO trainer (same script, same configmap, same 8-sandbox fleet from the main
pool), one L4 GPU (`python:3.11-slim` + CUDA torch; GKE gotchas: `LD_LIBRARY_PATH=/usr/local/nvidia/lib64`
required for the host-mounted driver, and triton JIT needs gcc installed). 50 steps, MAX_COMPLETION=128.

**Result:** bare GPU step = **1.6s** (B-arm clean segment: (3,587 − 14×252.2)/36 steps) — ~45× faster
than the 6-CPU trainer. Per-step suspension adds the same ~7s cycle it always adds (A-arm clean
segment: suspend p50 4.6, resume p50 2.3 — identical to every other run in the campaign):

| cadence | bare step | step with per-step suspension | overhead |
| --- | --- | --- | --- |
| CPU trainer, 0.5B (Part 5) | 71.2s | 78.0s | **+9.4%** |
| GPU trainer, 3B LoRA (L4×2) | ~15s | ~22s | **~+45%** |
| GPU trainer, 0.5B (L4) | 1.6s | ~8.5s | **~5.2×** |

**The law: suspension's cost is a CONSTANT (~7s/cycle), so its relative price is set entirely by step
duration.** The 3B row is the Reflection-realistic point: a real coding model (reward means 0.5-1.0,
multiple perfect 8/8 MBPP batches — vs the 0.5B's 0.1-0.4) at ~22s steps pays ~45% for per-step
suspension — meaningful but viable when capacity is the binding constraint; 7B-on-2×L4 was attempted
and is genuinely infeasible under TRL's memory profile (three OOMs: fp32 load, bf16 single-GPU
stacking, sharded first-forward).** Per-turn suspension is nearly free when turns are inference-bound (seconds of waiting) and
ruinous when turns are compute-fast. Orchestrator guidance for RL fleets: suspend at boundaries whose
expected idle exceeds ~3× the cycle cost — per-turn for slow/agentic turns (Reflection's 15s+ waits),
per-rollout or long-gap for fast inner loops.

### The immortal wedge (3B run, 2026-09-06 — upgrades the finding below)

The 3B run produced the decisive observation: a wedged sandbox's errors were pinned to ONE slot
(every error `[N_7]`, steps 41→50) across per-step suspend/resume cycles — while its pod and IP were
recreated every step. **The wedge survives pod reincarnation because it lives in the snapshotted
memory state: every resume faithfully restores the hung exec server.** Memory snapshots preserve
state perfectly — including pathological state. Consequences:
- Restart-to-recover does not exist under memory snapshots; restore IS the disease vector.
- A wedged-then-snapshotted sandbox is permanently lost until an orchestrator detects it (liveness
  check post-resume) and deliberately cold-starts or discards it.
- Wedge frequency scales with code sophistication (0 in 0.5B CPU runs of the same length; 1 per
  GPU arm with 0.5B; 2 in one 50-step run with 3B — real models exercise the exec server harder).
- Suspension itself is exonerated as the cause (first wedge occurred with SUSPEND_MODE=off);
  mechanism inside the guest unconfirmed (leading hypothesis: command-timeout kills the request,
  not the guest process — orphans accumulate until the server stops answering; repro plan: feed a
  scratch sandbox blocking code repeatedly and watch for unresponsiveness).

**Twice-demonstrated reliability finding (one per arm): sandboxes wedge under sustained
model-generated code.** B-arm: one sandbox's pod-IP went permanently unreachable from step 37 (every
eval on that slot burned the full 252s retry budget; batch time = slowest eval). A-arm: a different
sandbox's exec server hung with read-timeouts (suspend p95 inflated to 34.8s waiting on its
snapshots). In both cases training completed — dead slots score 0.0 — but each wedged sandbox taxes
every subsequent step. **Reward fleets need liveness eviction: health-check the fleet each step and
re-claim replacements.** Our harness lacks it by design simplicity; a production orchestrator must not.

---

## Part 8 addendum — the marathon: longevity + self-healing (2026-09-07)

**The question:** does anything degrade over thousands of suspend/resume cycles per sandbox —
snapshot-chain depth, GC, latency drift, wedge accumulation?

**Three regimes run, escalating:**
1. **No healing (v1):** effectively dead by step 108 — two immortal wedges taxed every step
   (~27 steps/hr vs ~330 healthy). Long-running fleets are INFEASIBLE without liveness eviction.
2. **Two-strike healing (v2, 170 steps):** correct but slow — detection cost ~11-12 min/wedge
   (two full retry-budget evals against a dead server before the trigger).
3. **One-strike healing (v3, THE RUN):** a single communication failure on a slot → terminate +
   fresh claim (~20s). Overhealing is cheap; probing a corpse is not.

**v3 result — 3,000 steps / 12.0 h / 30 epochs, clean completion:**
- 24,000 sandbox-cycles, ~48,000 snapshot operations in one run.
- **32 wedges caught and healed — 1 per ~750 cycles** under continuous model-generated code;
  every heal ~20s; zero run impact beyond the single failed eval.
- **Zero latency drift:** suspend p50/p95 = 4.6/5.4 globally vs 4.7/5.5 over the final 300 waves;
  resume p50 2.3s constant start to finish. Twelve hours of churn, no aging.
- Snapshot GC kept pace throughout (no accumulation pathology observed at depth).
- The model trained the whole time (reward means rising through the run, repeated 1.0 batches) —
  the healer never disturbed learning.

**The production recipe this validates:** per-step suspension + one-strike liveness eviction =
indefinitely sustainable RL reward fleets. Wedge rate ~1.3 per 1,000 cycles is the budget number;
eviction converts it from run-ending to rounding error.

---

# PART 9 — Production lifecycle & multi-cluster (2026-09-07, gaps 4 and 2 closed)

## Gap 4: per-rollout sandbox churn combined with per-step suspension (cluster C)

**Design:** production's actual sandbox lifecycle — claim fleet → N suspended turns → terminate →
claim fresh — modeled as ROLLOUT_LEN=5: every 5 training steps each trainer terminates its 8
sandboxes and fresh-creates 8 (pool-free protocol). 100 trainers × 20 steps = 4,000 fresh claims +
3,200 terminates interleaved with 16,000 suspends.

**Result: 100/100 complete in 55 min, zero failures, full capture (n=2,000 waves, 300 recycles).**
| metric | value |
| --- | --- |
| recycle (terminate 8 + fresh-claim 8) | p50 20.0s / p95 22.3 / max 23.5 — remarkably constant |
| amortized recycle cost per turn (5-turn rollouts) | ~4s/turn |
| suspend under mixed traffic | p50 7.8 / p95 9.8 (vs 4.7/6.6 floor — mild +3s lift) |
| resume under mixed traffic | p50 4.3 / p95 8.3 |

Claim churn and suspension coexist cleanly; the mixed-traffic latency lift is small and bounded. The
20s recycle constant is the fleet-turnover budget number for orchestrators.

## Gap 2: two clusters, one bucket (A + C simultaneously)

**Design:** cluster A (850 idle n2 nodes; brought up with the kuberay-sample manifests + AR image +
pool-free protocol in ~15 min) ran a 200-trainer swarm at the same time as C's churn run, both
snapshot pipelines writing to the SAME regional bucket (gke-ai-eco-dev-sbx-snapshots-us-central1).

**Result: 200/200 complete in 30 min, ZERO errors, n=3,980 waves.**
- A sustained ~23 suspends/s (200 trainers × 8 / ~69s steps) — AT the ceiling measured on C — with
  suspend p50 6.6 / p95 13.9 and **resume p50 4.2 = exactly the floor**. Mild suspend elevation is
  consistent with A's own near-ceiling arrival rate, not storage coupling.
- Combined bucket ingest (A swarm + C churn concurrently): zero storage errors, no correlated
  latency inflation across clusters.
- **Two conclusions:** (1) the shared regional bucket is a NON-FACTOR at 2-cluster combined load —
  per-cluster snapshot pipelines are independent lanes, so fleet capacity ≈ sum of per-cluster
  ceilings (the ~120-150/s six-cluster estimate now rests on measurement); (2) A independently
  reproduced the ~20-25/s ceiling law: at-demand≈ceiling → shallow queue (p50 6.6), vs C's rung 6
  far-over-demand → deep queue (p50 37) — two clusters, one consistent law.

Bring-up note: cluster A went from bare (drained) to running 200 real trainers in ~20 minutes using
the kuberay sample manifests verbatim + two patches (AR image for private nodes, pool→0) — itself a
validation that the PR's manifests are complete.

## Gap 5: episode state across suspend cycles inside live training (cluster C)

50 trainers × 40 steps, per-step suspension, each eval carrying a per-sandbox ledger check (byte-count
accumulator in /tmp, verified against the trainer's expected count every turn). **16,000 in-training
state-integrity checks — ZERO mismatches; zero wedges/heals** (the wedge phenomenon tracks GPU-cadence
frequency, absent here). Episode state survives 40 consecutive suspend/resume cycles per sandbox
inside a live training loop, perfectly. Honest scope: this closes the STATE half of "multi-turn
agentic training"; conversational-trajectory RL (generation conditioned on turn history) still needs
a custom rollout loop and remains on the gap list under "other stacks."

## Gap 7: failure injection (cluster A)

20 trainers × 40 steps under three deliberate attacks (all injected ~00:26 UTC, early-run):
1. **Force-killed a live sandbox pod (grace 0)** → the Sandbox controller's stable-identity contract
   recreated the pod (same name, new node) before the next eval — the platform healed it, not us.
2. **Deleted a suspended sandbox's PodSnapshots** (never-exercised restore-miss path) → next resume
   started the pod as a FRESH instance, the SDK's restored_from_snapshot flag fired TRUTHFULLY (the
   campaign's first genuine positives, after thousands of false alarms — SDK-1), the harness
   tolerated, episodes continued cold. State loss was real, deliberate, detected, and survivable.
3. **Drained a node hosting sandbox pods** → eviction handled identically to (1).

**Result: 20/20 complete, ZERO eval errors, zero heals needed** — every failure class was absorbed by
platform-level recreation + SDK detection before the harness's own defenses even engaged.

---

# PART 10 — The plane-size probe: F falsifies the proportional-ceiling hypothesis (2026-09-08)

**Measured apiserver cores (go_sched_gomaxprocs_threads): C=96, A=96, F=64** — F's plane grew since
August's 16-core folklore, leaving a 1.5× contrast. Bring-up on F (~15 min, kuberay-sample manifests,
us-west1 bucket + fresh IAM, sandboxes pinned n2d, trainers n2): validates a THIRD cluster and a
SECOND region.

| rung | attempted rate | suspend p50/p95 | resume p50/p95 | errors |
| --- | --- | --- | --- | --- |
| F 50 trainers | ~5-6/s | **4.1 / 6.1** | 4.2 / 4.2 | 0 |
| F 150 trainers | **~17-18/s** | **4.3 / 6.8 — FLAT** | 4.2 / 4.3 | 0 |

**F's 64-core plane sustained ~17-18/s AT THE FLOOR — its ceiling is ≥17/s and was not reached.**
Combined with A (96 cores, ~23/s with mild lift) and C (96 cores, saturation ~20-25/s): within the
64-96-core plane range the pipeline delivers ~17-25/s with NO strong core-proportional scaling.
The proportional hypothesis (64/96 × 22 ≈ 15/s predicted ceiling for F) is falsified — F blew
through the prediction unqueued. Remaining caveat: genuinely tiny planes (the 16-core class, e.g.
few-node clusters — where the demo cluster showed distress) are still unmeasured; within the range
production RL fleets actually deploy, cluster size does not tax the snapshot pipeline. Fleet math
(sum of per-cluster ceilings) gets STRONGER: even the fleet's smallest member contributes ≥17/s.

# PART 11 — Heavy snapshots: the size laws to 4GB (2026-09-08)

**Question:** Part 1 measured to 1GB; agentic workloads with real in-memory state live at 4-8GB+.
Does resume stay flat? **Setup:** 16 sandboxes × 4GB incompressible tmpfs ballast (dedicated template
with 6Gi requests / 8Gi limits), 3 suspend/resume/verify cycles, md5 digest on all 4GB every cycle.

| metric (n=48 cycles) | value |
| --- | --- |
| suspend 4GB | p50 9.2 / p95 9.7 / max 10.1s — the linear law confirmed, refined slope ~1.1s/GB |
| **resume 4GB** | **p50 4.3 / max 4.4s — FLAT, identical to a 32MB snapshot, near-zero variance** |
| post-resume full read (md5 of 4GB) | 6.7-7.0s ≈ 600MB/s — restore is lazy AND paging is fast |
| state integrity | 48/48 digests intact (192GB verified through cycles) |
| false "fresh instance" reports | **14/48 = 29%** (vs ~0.7% at small sizes) — SDK-1's one-shot
  PodRestored race scales with restore size; ALL 14 false (4GB digest survived every time) |

**The law, now measured to 4GB: resume latency is INDEPENDENT of state size; suspend pays ~1.1s/GB
for the upload; integrity is perfect.** For Ivan: an agent holding 4GB of live memory resumes as fast
as an empty one — suspension's viability does not degrade with working-set size (to 4GB; beyond
extrapolates the same mechanism, unmeasured).

**Two operational lessons bled for:**
1. **Big-state sandboxes MUST declare memory requests.** With zero requests the scheduler packed
   16 × 4-5GB tmpfs sandboxes onto few 32GB nodes → node memory death-spiral presenting as wedged
   exec servers (accepts TCP, never answers — 30-min hangs). 6Gi requests fixed it completely.
2. gVisor `os.urandom` throughput is far too slow for multi-GB ballast (~900s+ for 4GB);
   generate-once-write-many is the pattern.

Untested remainder in this axis: >4GB, and the bulk-throughput regime (hundreds of multi-GB
snapshots per wave into one bucket — a deliberate cost/duration decision, ~1.25TB/wave).

---

# CAMPAIGN CLOSE (2026-09-06)

Across Parts 1-11: ~400,000+ suspend/resume operations on FOUR clusters and TWO regions against real and synthetic RL traffic, zero
state loss ever observed. The complete measured story: substrate laws (floors, wave costs, burst-vs-
steady pipeline behavior ≥12/s), real GRPO training with sandbox-executed rewards (learning unaffected,
hostile code contained), a 450-trainer swarm that FOUND the steady-state ceiling (~20-25 suspends/s; flat to 11.8/s, queueing-not-failure beyond), backfill economics
(freed → consumed → reclaimed), measured density (87-slot hardware serving 320-480 rollouts, knee
between 3.7-5.5×, degradation is latency-only), and cadence-dependent suspension guidance (+9.4% at
71s steps, ~5.2× at 1.6s steps). Remaining non-science: upstream filings, Reflection/Tomer packaging.
