"""Heavy-state suspend/resume physics: STATE_MB per sandbox, CYCLES cycles, digest-verified."""

import os
import time
from concurrent.futures import ThreadPoolExecutor
from k8s_agent_sandbox.gke_extensions.snapshots import PodSnapshotSandboxClient
from k8s_agent_sandbox.models import SandboxInClusterConnectionConfig

N = int(os.environ.get("SANDBOXES", "8"))
STATE_MB = int(os.environ.get("STATE_MB", "4096"))
CYCLES = int(os.environ.get("CYCLES", "3"))
WARMPOOL = os.environ.get("WARMPOOL", "swarm-pool")

client = PodSnapshotSandboxClient(
    connection_config=SandboxInClusterConnectionConfig(use_pod_ip=True, server_port=8888), 
    cleanup=True
)
sbs = []

for i in range(N):
    sbs.append(client.create_sandbox(warmpool=WARMPOOL, sandbox_ready_timeout=600))
    print(f"claimed {i}", flush=True)

SETUP = f"""
import os, hashlib
h = hashlib.md5()
b = os.urandom(1024 * 1024)
with open('/tmp/ballast.bin', 'wb') as f:
    for _ in range({STATE_MB}):
        h.update(b)
        f.write(b)
print('DIGEST', h.hexdigest())
"""

CHECK = (
    "import hashlib\n"
    "h = hashlib.md5()\n"
    "f = open('/tmp/ballast.bin','rb')\n"
    "for c in iter(lambda: f.read(16*1024*1024), b''): h.update(c)\n"
    "print('DIGEST', h.hexdigest())\n"
)

def run(sb, code, timeout):
    sb.files.write("op.py", code)
    r = sb.commands.run("python op.py", timeout=timeout)
    return (r.stdout or "").strip().split()[-1]

digests = {}

def setup(i):
    t0 = time.time()
    digests[i] = run(sbs[i], SETUP, 1800)
    print(f"[{i}] wrote {STATE_MB}MB in {time.time()-t0:.1f}s digest={digests[i][:8]}", flush=True)

with ThreadPoolExecutor(max_workers=N) as ex:
    list(ex.map(setup, range(N)))

def suspend(i):
    t0 = time.time()
    res = sbs[i].suspend(snapshot_before_suspend=True)
    print(f"[{i}] HEAVY-SUSPEND {STATE_MB}MB ok={res.success} in {time.time()-t0:.1f}s", flush=True)

def resume(i):
    t0 = time.time()
    res = sbs[i].resume(wait_timeout=900)
    print(f"[{i}] HEAVY-RESUME {STATE_MB}MB ok={res.success} in {time.time()-t0:.1f}s", flush=True)

def verify(i):
    t0 = time.time()
    d = run(sbs[i], CHECK, 300)
    ok = d == digests[i]
    print(f"[{i}] HEAVY-VERIFY ok={ok} in {time.time()-t0:.1f}s", flush=True)
    if not ok:
        print(f"[{i}] STATE LOSS: {d[:8]} != {digests[i][:8]}", flush=True)

for c in range(CYCLES):
    print(f"=== cycle {c} ===", flush=True)
    with ThreadPoolExecutor(max_workers=N) as ex: 
        list(ex.map(suspend, range(N)))
    time.sleep(10)
    with ThreadPoolExecutor(max_workers=N) as ex: 
        list(ex.map(resume, range(N)))
    with ThreadPoolExecutor(max_workers=N) as ex: 
        list(ex.map(verify, range(N)))

print("terminating...", flush=True)
for sb in sbs:
    try: 
        sb.terminate()
    except Exception: 
        pass
print("DONE", flush=True)
