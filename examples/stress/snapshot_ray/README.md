# Suspend/Resume Stress Campaign — reproduction bundle (2026-08-28 → 2026-09-08)

Findings: `SNAPSHOT_STRESS_RESULTS.md` (11 parts; executive summary + laws tables up top).
Upstream issues: `SNAPSHOT_UPSTREAM_FILINGS.md` (7 SDK + 3 GKE).

## Canonical code

- Harness + samples fork: https://github.com/vicentefb/kuberay
  - branch `snapshotStress`: `ray-operator/config/samples/agent-sandbox-snapshots/stress/` (scratch harnesses)
  - branch `raySuspendResumeArtifacts`: `ray-operator/config/samples/agent-sandbox/snapshots/` (the PR'd
    demo + `rbac.yaml` + `sandbox-snapshot.yaml` used verbatim for cluster bring-up)
- `harness/` here = the exact versions that produced the results (all live patches applied — the fork
  branch may lag these snapshots).
- Trainer image: `us-docker.pkg.dev/gke-ai-eco-dev/sandbox-images/grpo-trainer:v1`
  (built from `harness/Dockerfile.grpo-trainer` via Cloud Build, ~3 min; deps + model + dataset baked
  so trainers run on egress-less private nodes and start in ~1 min).

## Experiment map (doc part ↔ job spec ↔ raw log ↔ cluster)

| experiment | doc | job spec | raw log(s) | cluster |
| --- | --- | --- | --- | --- |
| Single-trainer suspension A/B (CPU) | Part 5 | grpo-trainer pod (see doc appendix) | train.log / train2.log / train3.log | C |
| Swarm rungs 1-2 (5, 12 trainers; loadgen) | Part 6 | grpo-swarm-job (doc appendix) | swarm1 / swarm2 | C |
| Swarm rungs 3-6 (50→450; shards, baked image) | Part 6 | `jobs/megaswarm-job.yaml` | swarm3 / swarm4 / swarm5 / megaswarm-full | C |
| Density 3.7× / 5.5× (87-slot arena) | Part 7 | `jobs/density-job.yaml` | density-full / density60-full | C |
| GPU cadence A/B (0.5B + 3B LoRA on L4) | Part 8 | `jobs/gpu-7b-pod.yaml` | gpu-off / gpu-perstep-full / gpu-3b | C |
| Marathon (3K done; 10K in flight) | Part 8 addendum | `jobs/gpu-7b-pod.yaml` (MAX_STEPS) | marathon-full / marathon10k | C |
| Churn: per-rollout recycling + suspension | Part 9 | `jobs/churn-job.yaml` | churn-full | C |
| Multi-cluster, shared bucket (with C churn) | Part 9 | `jobs/swarm-a-job.yaml` | swarm-a-full | A |
| Episodic ledger (state across 40 cycles) | Part 9 | `jobs/episodic-job.yaml` | episodic-full | C |
| Chaos: pod kill / snapshot delete / drain | Part 9 | `jobs/chaos-job.yaml` | chaos-full | A |
| Plane-size probe (64- vs 96-core planes) | Part 10 | `jobs/swarm-f-job.yaml` | swarm-f50-full / swarm-f150-full | F |
| Heavy snapshots (4GB state laws) | Part 11 | `jobs/heavy-job.yaml` + `harness/heavy_snapshot_test.py` | heavy-full | C |

Clusters: m2-density-{a,c,f} in gke-ai-eco-dev; C/A planes = 96 apiserver cores, F = 64
(`kubectl get --raw /metrics | grep go_sched_gomaxprocs_threads`). Buckets:
`gke-ai-eco-dev-sbx-snapshots-us-central1` (A+C shared), `-us-west1` (F).

## Reproduction order (any single experiment)

1. **Cluster bring-up (~15 min, Part 9's recipe):** apply `sandbox-snapshot.yaml` from the
   `raySuspendResumeArtifacts` branch with your bucket name; on private nodes patch the template image
   to the AR mirror; set the warm pool `replicas: 0` (fresh-create protocol, Part 7 — pools on scarce
   arenas actively harm); apply `rbac.yaml`; `kubectl create configmap grpo-script
   --from-file=harness/grpo_sandbox_train.py`.
2. Apply the relevant `jobs/*.yaml`. Every env knob is documented in the doc's Part 6 appendix
   (MAX_STEPS, REWARD_SANDBOXES, SUSPEND_MODE, ROLLOUT_LEN, EPISODE_LEDGER, CLAIM_TIMEOUT, MODEL,
   USE_LORA, BF16, STATE_MB…).
3. **Measure by harvest-after-Complete**: `kubectl logs --tail=-1` every pod into one file, then the
   percentile greps (exact commands in the doc appendix). Never trust streaming log followers at
   ≥50 pods (label-selector logs default `--tail=10`).
4. Rituals that will save you (all bled for, see runbook rules in Parts 6-11): grep-verify every sed
   before applying; delete a Job before re-applying scale changes (Complete Jobs silently absorb
   updates); sweep sandbox claims only after Job Complete; big-state sandboxes must declare memory
   requests; one-strike liveness eviction for long runs; fresh-create Ready ≠ exec-server listening
   (retry ~30s).

## Directory contents

- `harness/` — trainer + heavy-state test scripts, Dockerfile for the baked image.
- `jobs/` — every Job/Pod spec as last run.
- `templates/` — live-exported SandboxTemplates, PodSnapshotStorageConfigs and Policies from C, A, F.
- `raw-logs/` — full per-pod harvests; every number in the doc derives from these via the appendix greps.
