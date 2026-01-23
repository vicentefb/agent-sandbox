for i in {1..30}; do kubectl apply -f - <<EOF
apiVersion: extensions.agents.x-k8s.io/v1alpha1
kind: SandboxClaim
metadata:
  name: claim-$i
spec:
  sandboxTemplateRef:
    name: autopilot-test-template
EOF
done


#for i in {1..5}; do kubectl delete sandboxclaim claim-$i; done