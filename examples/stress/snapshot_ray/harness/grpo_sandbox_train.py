"""
Real RL loop on CPU: GRPO (TRL) + agent-sandbox as the reward executor.

Policy = Qwen2.5-0.5B-Instruct, task = MBPP (write a Python function).
Reward = fraction of the problem's unit tests that PASS when the model's
generated code is executed inside a gVisor sandbox (agent-sandbox warm pool).
Untrusted model code never touches the trainer — that is the entire point
of using sandboxes in an RL reward path.

No GPU required. Gradients, KL, and policy updates are all real; a GPU
would only make the steps faster.

Env knobs:
  MODEL (Qwen/Qwen2.5-0.5B-Instruct)   MAX_STEPS (50)
  REWARD_SANDBOXES (8)                 WARMPOOL (python-snapshot-pool)
  NUM_GENERATIONS (4)                  MAX_COMPLETION (256)
  SUSPEND_MODE (off | per_step)        DATASET_SLICE (train[:200])
"""

import os
import queue
import re
import time
from concurrent.futures import ThreadPoolExecutor

MODEL = os.environ.get("MODEL", "Qwen/Qwen2.5-0.5B-Instruct")
MAX_STEPS = int(os.environ.get("MAX_STEPS", "50"))
REWARD_SANDBOXES = int(os.environ.get("REWARD_SANDBOXES", "8"))
WARMPOOL = os.environ.get("WARMPOOL", "python-snapshot-pool")
NUM_GENERATIONS = int(os.environ.get("NUM_GENERATIONS", "4"))
MAX_COMPLETION = int(os.environ.get("MAX_COMPLETION", "256"))
SUSPEND_MODE = os.environ.get("SUSPEND_MODE", "off")
DATASET_SLICE = os.environ.get("DATASET_SLICE", "train[:200]")

# ---------------- sandbox fleet (claimed once, reused every step) ----------
from k8s_agent_sandbox.gke_extensions.snapshots import PodSnapshotSandboxClient
from k8s_agent_sandbox.models import SandboxInClusterConnectionConfig

client = PodSnapshotSandboxClient(
    connection_config=SandboxInClusterConnectionConfig(use_pod_ip=True, server_port=8888),
    cleanup=True,
)
print(f"claiming {REWARD_SANDBOXES} reward sandboxes from warmpool {WARMPOOL}...")
sandboxes = []
for i in range(REWARD_SANDBOXES):
    for attempt in range(4):
        try:
            sandboxes.append(client.create_sandbox(warmpool=WARMPOOL, sandbox_ready_timeout=int(os.environ.get("CLAIM_TIMEOUT", "180"))))
            break
        except Exception as e:
            print(f"  claim {i} attempt {attempt} failed: {e}")
            time.sleep(30)
    else:
        raise RuntimeError(f"claim {i} failed after 4 attempts")
    print(f"  sandbox {i} ready")
free: "queue.Queue" = queue.Queue()
for sb in sandboxes:
    free.put(sb)
pool = ThreadPoolExecutor(max_workers=REWARD_SANDBOXES)
fleet_suspended = False

HARNESS = """
__passed__ = 0
__tests__ = {tests!r}
for __t__ in __tests__:
    try:
        exec(__t__, globals())
        __passed__ += 1
    except Exception:
        pass
print("__RESULT__", __passed__, len(__tests__))
"""


def _retry(fn, tries=4, delay=3):
    last = None
    for _ in range(tries):
        try:
            return fn()
        except Exception as e:
            last = e
            time.sleep(delay)
    raise last


def extract_code(completion) -> str:
    if isinstance(completion, list):  # conversational format
        completion = completion[0]["content"]
    m = re.search(r"```(?:python)?\n(.*?)```", completion, re.DOTALL)
    return (m.group(1) if m else completion).strip()


import threading
_heal_lock = threading.Lock()
_comm_fails = {}
_eval_counts = {}

def _heal(sb):
    """Terminate a wedged sandbox and claim a fresh replacement (SDK-7 mitigation)."""
    global sandboxes
    with _heal_lock:
        try:
            sb.terminate()
        except Exception:
            pass
        for attempt in range(4):
            try:
                new_sb = client.create_sandbox(warmpool=WARMPOOL, sandbox_ready_timeout=int(os.environ.get("CLAIM_TIMEOUT", "180")))
                break
            except Exception as e:
                print(f"  [healer] re-claim attempt {attempt} failed: {e}")
                time.sleep(30)
        else:
            raise RuntimeError("healer could not re-claim")
        sandboxes = [new_sb if x is sb else x for x in sandboxes]
        print("  [healer] replaced wedged sandbox")
        return new_sb

def run_in_sandbox(code: str, tests: list, tag: str) -> float:
    sb = free.get()
    try:
        program = code + "\n" + HARNESS.format(tests=list(tests))
        if os.environ.get("EPISODE_LEDGER", "0") == "1":
            expected = _eval_counts.get(id(sb), 0)
            _eval_counts[id(sb)] = expected + 1
            prelude = (
                "import os as _o\n"
                "_l = '/tmp/episode_ledger.bin'\n"
                "_prev = _o.path.getsize(_l) if _o.path.exists(_l) else 0\n"
                f"print('__LEDGER__', _prev, {expected})\n"
                "open(_l, 'ab').write(b'x')\n"
            )
            program = prelude + program
        name = f"eval_{tag}.py"
        _retry(lambda: sb.files.write(name, program))
        r = _retry(lambda: sb.commands.run(f"python {name}", timeout=30), tries=2)
        m = re.search(r"__RESULT__ (\d+) (\d+)", r.stdout or "")
        lm = re.search(r"__LEDGER__ (\d+) (\d+)", r.stdout or "")
        if lm and lm.group(1) != lm.group(2):
            print(f"  LEDGER MISMATCH [{tag}]: found {lm.group(1)} expected {lm.group(2)}")
        _comm_fails[id(sb)] = 0
        if not m:
            return 0.0  # crashed outright (syntax error, hang, ...)
        passed, total = int(m.group(1)), int(m.group(2))
        return 0.1 + 0.9 * passed / max(total, 1)  # 0.1 floor: it at least ran
    except Exception as e:
        print(f"  reward-exec error [{tag}]: {e}")
        n = _comm_fails.get(id(sb), 0) + 1
        _comm_fails[id(sb)] = n
        if n >= 1:
            try:
                sb = _heal(sb)
            except Exception as he:
                print(f"  [healer] FAILED: {he}")
        return 0.0
    finally:
        free.put(sb)


def _suspend_one(sb):
    res = sb.suspend(snapshot_before_suspend=True)
    if not res.success:
        print(f"  suspend failed: {res.error_reason}")


def _resume_one(sb):
    res = sb.resume(wait_timeout=600)
    if not res.success and "not restored from snapshot" not in (res.error_reason or ""):
        print(f"  resume failed: {res.error_reason}")


step_no = {"n": 0}


def sandbox_reward(prompts, completions, test_list=None, **kwargs):
    """TRL reward function: one score per completion, from sandbox execution."""
    global fleet_suspended, free, sandboxes
    step_no["n"] += 1
    tag = step_no["n"]

    ROLLOUT_LEN = int(os.environ.get("ROLLOUT_LEN", "0"))
    if ROLLOUT_LEN and tag > 1 and (tag - 1) % ROLLOUT_LEN == 0:
        # production lifecycle: rollout over -> terminate fleet, claim fresh
        t0 = time.time()
        for sb in sandboxes:
            try:
                sb.terminate()
            except Exception as e:
                print(f"  [recycle] terminate failed: {e}")
        fresh = []
        for i in range(REWARD_SANDBOXES):
            for attempt in range(4):
                try:
                    fresh.append(client.create_sandbox(warmpool=WARMPOOL, sandbox_ready_timeout=int(os.environ.get("CLAIM_TIMEOUT", "180"))))
                    break
                except Exception as e:
                    print(f"  [recycle] claim {i} attempt {attempt} failed: {e}")
                    time.sleep(30)
            else:
                raise RuntimeError("recycle could not re-claim fleet")
        sandboxes = fresh
        free = queue.Queue()
        for sb in sandboxes:
            free.put(sb)
        fleet_suspended = False
        print(f"[step {tag}] recycled fleet (terminate+reclaim 8) in {time.time() - t0:.1f}s")

    if fleet_suspended:
        t0 = time.time()
        list(pool.map(_resume_one, sandboxes))
        fleet_suspended = False
        print(f"[step {tag}] resumed {len(sandboxes)} sandboxes in {time.time() - t0:.1f}s")

    t0 = time.time()
    codes = [extract_code(c) for c in completions]
    futs = [
        pool.submit(run_in_sandbox, c, t, f"{tag}_{i}")
        for i, (c, t) in enumerate(zip(codes, test_list))
    ]
    rewards = [f.result() for f in futs]
    print(
        f"[step {tag}] {len(rewards)} sandbox evals in {time.time() - t0:.1f}s "
        f"rewards={[f'{r:.2f}' for r in rewards]}"
    )

    if SUSPEND_MODE == "per_step":
        t0 = time.time()
        list(pool.map(_suspend_one, sandboxes))
        fleet_suspended = True
        print(f"[step {tag}] suspended fleet in {time.time() - t0:.1f}s")
    return rewards


# ---------------- dataset ---------------------------------------------------
from datasets import load_dataset

ds = load_dataset("google-research-datasets/mbpp", split=DATASET_SLICE)


def to_prompt(row):
    tests = "\n".join(row["test_list"])
    user = (
        "You are an expert Python programmer. Write a Python function for this "
        "task. Output ONLY the code, no explanations.\n"
        f"Task: {row['text']}\n"
        f"Your code must pass these tests:\n{tests}\n"
    )
    return {"prompt": [{"role": "user", "content": user}], "test_list": row["test_list"]}


ds = ds.map(to_prompt, remove_columns=[c for c in ds.column_names if c != "test_list"])

# ---------------- trainer ---------------------------------------------------
from trl import GRPOConfig, GRPOTrainer

cfg = GRPOConfig(
    output_dir="/tmp/grpo-sandbox",
    learning_rate=2e-6,
    beta=0.04,
    per_device_train_batch_size=NUM_GENERATIONS,
    gradient_accumulation_steps=2,
    num_generations=NUM_GENERATIONS,
    max_prompt_length=512,
    max_completion_length=MAX_COMPLETION,
    max_steps=MAX_STEPS,
    logging_steps=1,
    save_strategy="no",
    report_to="none",
    temperature=0.9,
    bf16=os.environ.get("BF16", "0") == "1",
    model_init_kwargs={"torch_dtype": "bfloat16", "device_map": "auto"} if os.environ.get("BF16", "0") == "1" else None,
    fp16=False,
)

trainer = GRPOTrainer(
    model=MODEL, reward_funcs=sandbox_reward, args=cfg, train_dataset=ds
)

try:
    trainer.train()
finally:
    print("terminating reward sandboxes...")
    for sb in sandboxes:
        try:
            sb.terminate()
        except Exception:
            pass
