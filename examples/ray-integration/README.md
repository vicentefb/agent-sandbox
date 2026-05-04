# Agentic Reinforcement Learning with Ray and Agent Sandbox

Demonstrate how to integrate the Ray framework with agent-sandbox to securely execute AI-generated code during Agentic Reinforcement Learning (RL) training.

## The Architecture: Proxy Execution

In Agentic RL, AI models generate and execute code during their training phase. Running this untrusted code directly on a Ray worker node introduces severe security risks to the distributed cluster.

To mitigate this, we use a Proxy Execution Model:

1. **The Trusted Actor:** The Ray rollout actor remains a standard Python process within the trusted Ray cluster.
2. **The Proxy Call:** When the actor needs to execute generated code, it uses the Agent Sandbox Python SDK to proxy the command execution to an isolated sandbox.
3. **The Secure Sandbox:** The code executes securely inside a gVisor-isolated container in GKE Autopilot (or Standard), physically separated from Ray's control plane (Redis, gRPC, Object Store).
4. **Low Latency Provisioning:** The SDK claims pre-warmed pods via a SandboxWarmPool, bypassing cold-start container provisioning.


## Deployment Playbook (GKE Autopilot)

### 1: Prepare and Push the Sandbox Image

GKE cluster requires images to be hosted in a reachable container registry. We use Google Artifact Registry (GAR) as an example.

1. Navigate to the Python runtime example directory:

```bash
cd examples/python-runtime-sandbox
```

2. Replace your-project-id with your actual GCP project ID.

```bash
export IMAGE_URL="us-central1-docker.pkg.dev/your-project-id/agent-sandbox-repo/python-runtime-sandbox:latest"
docker build -t $IMAGE_URL .
docker push $IMAGE_URL
```

### 2: Deploy Infrastructure and Router

1. Install CRDs and Controller (you need the extensions for the Python SDK to work):

Releases can be found here: https://github.com/kubernetes-sigs/agent-sandbox/releases

```bash
export VERSION="vX.Y.Z"

kubectl apply -f https://github.com/kubernetes-sigs/agent-sandbox/releases/download/${VERSION}/manifest.yaml

kubectl apply -f https://github.com/kubernetes-sigs/agent-sandbox/releases/download/${VERSION}/extensions.yaml
```

2. Deploy the Sandbox Router:

The router securely funnels traffic from your local Ray script to the GKE sandboxes.
(Note: Ensure you have built and replaced the IMAGE_PLACEHOLDER in sandbox_router.yaml as per the [router documentation](https://github.com/kubernetes-sigs/agent-sandbox/tree/main/clients/python/agentic-sandbox-client/sandbox-router)).

```bash
kubectl apply -f clients/python/agentic-sandbox-client/sandbox-router/manifests.yaml
```

### 3: Configure the Sandbox Template and Warm Pool

Create a file named `ray-autopilot-setup.yaml` to define the execution environment and the warm pool. You can also find an example of a python runtime image here: https://github.com/kubernetes-sigs/agent-sandbox/tree/main/examples/python-runtime-sandbox
```yaml
---
apiVersion: extensions.agents.x-k8s.io/v1alpha1
kind: SandboxTemplate
metadata:
  name: ray-python-template
spec:
  podTemplate:
    spec:
      runtimeClassName: gvisor
      containers:
      - name: runtime
        # UPDATE THIS TO YOUR ACTUAL PYTHON RUNTIME IMAGE URL
        image: us-central1-docker.pkg.dev/your-project-id/agent-sandbox-repo/python-runtime-sandbox:latest
        imagePullPolicy: Always
        ports:
        - containerPort: 8888
        resources:
          requests:
            cpu: "250m"
            memory: "512Mi"
---
apiVersion: extensions.agents.x-k8s.io/v1alpha1
kind: SandboxWarmPool
metadata:
  name: ray-pool
spec:
  replicas: 5 # Maintains 5 secure gVisor pods hot and ready
  sandboxTemplateRef:
    name: ray-python-template
```

Apply the configuration and wait for the pods to spin up. 

```bash
kubectl apply -f ray-autopilot-setup.yaml
```

### 4: The Ray Actor Script

Install python dependencies:

Installation of the agentic-sandbox-client at main:

```bash
# This is needed for now since the latest official release of the python SDK k8s-agent-sandbox==0.4.3 doesn't have the feature to specify warmpool when creating a sandbox
cd /usr/local/google/home/vicenteferrara/agent-sandbox/clients/python/agentic-sandbox-client
pip install -e .
pip install ray
```


When we cut a new elease, we can install ray + latest official version of k8s-agent-sandbox sdk. 
```bash
pip install ray k8s-agent-sandbox
```


Create `rl_poc_local.py`. This script transforms the Ray Rollout Worker into a formal RL Environment. It simulates an AI agent in its exploration phase attempting a destructive action, failing safely within the sandbox, and then succeeding with the correct coding action.

```python
import ray
import time
from k8s_agent_sandbox import SandboxClient
from k8s_agent_sandbox.models import SandboxLocalTunnelConnectionConfig

# Initialize a local Ray cluster for the PoC.
# In a production environment with KubeRay, this script would run inside the cluster.
ray.init()

@ray.remote
class RLEnvironmentWorker:
    """
    A Ray Rollout Worker acting as an RL Environment. 
    It safely executes the Agent's actions (code) and returns Observations and Rewards.
    """
    def __init__(self, template_name: str, pool_name: str):
        print("Initializing RL Environment Worker...")
        
        # --- CONNECTION SETUP ---
        # SandboxLocalTunnelConnectionConfig automatically creates a secure 
        # `kubectl port-forward` tunnel from your local machine to the GKE Router.
        config = SandboxLocalTunnelConnectionConfig(server_port=8888)
        self.client = SandboxClient(connection_config=config, cleanup=True)
        
        # --- SANDBOX PROVISIONING ---
        # Claim a hot sandbox from the warm pool for instant environment reset
        self.sandbox = self.client.create_sandbox(
            template=template_name,
            warmpool=pool_name,
            shutdown_after_seconds=3600
        )
        print(f"Environment ready in remote GKE sandbox: {self.sandbox.claim_name}")

    def step(self, action_code: str):
        """
        The core RL step function.
        - Action: The untrusted code generated by the AI agent.
        - Observation: What the code output to stdout/stderr.
        - Reward: +1.0 for solving the task, -1.0 for errors or destructive behavior.
        """
        # 1. Apply the Agent's action to the environment
        self.sandbox.files.write("agent_action.py", action_code)
        result = self.sandbox.commands.run("python agent_action.py", timeout=5)
        
        # 2. Formulate the Observation
        observation = {
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "exit_code": result.exit_code
        }

        # 3. Calculate the Reward (Task: Calculate the 10th Fibonacci number)
        reward = 0.0
        done = False
        
        if result.exit_code == 0 and "55" in result.stdout:
            reward = 1.0  # Success!
            done = True
        elif result.exit_code != 0:
            reward = -1.0 # Penalize syntax errors or crashes
            
        return observation, reward, done

    def teardown(self):
        """Cleans up the SandboxClaim in Kubernetes."""
        self.client.delete_all()

# ==========================================
# --- Simulated Agentic RL Training Loop ---
# ==========================================

print("Spawning Ray RL Environment Worker...")
env_worker = RLEnvironmentWorker.remote(template_name="ray-python-template", pool_name="ray-pool")

# --- Episode 1: The Exploration Phase (Malicious/Destructive Action) ---
print("\n[Episode 1] Agent attempts a destructive action during exploration...")
destructive_action = """
import os
print('Attempting to delete files...')
os.system('rm -rf /app/*')
raise Exception('Self-destructing the agent!')
"""

future_1 = env_worker.step.remote(destructive_action)
obs_1, reward_1, done_1 = ray.get(future_1)

print(f"Observation (Exit {obs_1['exit_code']}): {obs_1['stderr']}")
print(f"Reward: {reward_1} | Done: {done_1}")
print("Result: Sandbox contained the destruction. Ray worker remains healthy.")

# --- Episode 2: The Exploitation Phase (Correct Action) ---
print("\n[Episode 2] Agent learns and attempts the correct coding action...")
correct_action = """
def fibonacci(n):
    if n <= 0: return 0
    elif n == 1: return 1
    else: return fibonacci(n-1) + fibonacci(n-2)

print(fibonacci(10))
"""

future_2 = env_worker.step.remote(correct_action)
obs_2, reward_2, done_2 = ray.get(future_2)

print(f"Observation (Exit {obs_2['exit_code']}): {obs_2['stdout']}")
print(f"Reward: {reward_2} | Done: {done_2}")
print("Result: Agent successfully solved the task securely.")

# Cleanup resources
env_worker.teardown.remote()
time.sleep(2) # Allow time for K8s deletion commands to fire over the network
ray.shutdown()
```

## Execution
Ensure your Python virtual environment points to your local SDK checkout (pip install -e . from the agentic-sandbox-client directory).

```bash
python ray_rl_autopilot_poc.py
```

You should see something like the following: 

```bash
2026-05-01 20:54:02,832 INFO worker.py:2012 -- Started a local Ray instance.
Spawning Ray RL Environment Worker...

[Episode 1] Agent attempts a destructive action during exploration...
(RLEnvironmentWorker pid=1682391) Initializing RL Environment Worker...
(RLEnvironmentWorker pid=1682391) Environment ready in remote GKE sandbox: sandbox-claim-bb2b0d31
Observation (Exit 1): Traceback (most recent call last):
  File "/app/agent_action.py", line 5, in <module>
Exception: Self-destructing the agent!
Reward: -1.0 | Done: False
Result: Sandbox contained the destruction. Ray worker remains healthy.

[Episode 2] Agent learns and attempts the correct coding action...
Observation (Exit 0): 55
Reward: 1.0 | Done: True
Result: Agent successfully solved the task securely.
```


## Using Gateway

To make the "Remote Ray -> GKE Sandboxes" architecture more stable, we can drop the local tunnel and use Gateway Mode.

This provisions a native Google Cloud L7 Load Balancer that securely routes external internet (or VPC) traffic directly into your sandbox-router.

Here is the exact playbook to upgrade your PoC to the Gateway architecture.

### Step 1: Deploy the GKE Gateway

The repository already includes the necessary manifests to provision a GKE managed Gateway and the HTTP routing rules.  

Apply the Gateway manifest to your cluster:

```bash
kubectl apply -f clients/python/agentic-sandbox-client/sandbox-router/gateway.yaml
```


### Step 2: Wait for the Public IP

GKE will spin up a Cloud Load Balancer. This can take a few minutes. You need to wait until an external IP address is assigned.

Check the status with:

```bash
kubectl get gateway external-http-gateway -w
```

Wait until you see an IP address under the `ADDRESS` column.


### Step 3: Upgrade the Python Code

Now that your router is exposed behind a robust Load Balancer, we can strip out the brittle tunneling logic.

Update the `__init__` method of your `RLEnvironmentWorker` in your local Python script:

```python
@ray.remote
class RLEnvironmentWorker:
    def __init__(self, template_name: str, pool_name: str):
        print("Initializing RL Environment Worker...")
        
        # --- THE EXTERNAL CONFIG ---
        # Instead of port-forwarding, the SDK will automatically query the K8s API 
        # for the 'external-http-gateway' IP and route all HTTP traffic through it.
        from k8s_agent_sandbox.models import SandboxGatewayConnectionConfig
        
        config = SandboxGatewayConnectionConfig(
            gateway_name="external-http-gateway",
            gateway_namespace="default",
            server_port=8888
        )
        
        self.client = SandboxClient(connection_config=config, cleanup=True)
        
        # The rest of your claiming logic remains identical
        self.sandbox = self.client.create_sandbox(
            template=template_name,
            warmpool=pool_name,
            shutdown_after_seconds=3600
        )
        print(f"Environment ready via Gateway: {self.sandbox.claim_name}")
```

### 5: Clean Up
To avoid unnecessary compute charges in your GKE Autopilot cluster and remove the PoC infrastructure, run the following commands:

1. Delete the Warm Pool and Template:
This will instantly spin down the 5 gVisor sandbox pods.

```bash
kubectl delete -f ray-autopilot-setup.yaml
```

2. Delete the Sandbox Router:
Removes the routing deployment and internal service.

```bash
kubectl delete -f clients/python/agentic-sandbox-client/sandbox-router/sandbox_router.yaml
```

3. Delete Agent Sandbox controller: 

```bash
kubectl delete deployment agent-sandbox-controller -n agent-sandbox-system
```