# Kubernetes checks (K7-K13 workload + K1-K6 access architecture, validated on live GKE and EKS canaries)

## Workload checks (kubectl, read-only)

EXCLUDE system namespaces (kube-system, kube-public, kube-node-lease, gmp-system, gke-managed*) from workload findings: their pods are privileged/hostPath by design and flagging them drowns the report in false positives. Cover system namespaces with one summary line.

| # | Check | Command | Finding if |
|---|---|---|---|
| K7 | Privileged containers | `kubectl get pods -A -o json` filtered to user namespaces, check securityContext.privileged | Any workload pod privileged = container escape path |
| K8 | hostPath volumes | Same dump, check spec.volumes[].hostPath | hostPath / or /var/run/docker.sock = node takeover |
| K9 | RBAC over-grant | `kubectl get clusterrolebindings -o json`, bindings to cluster-admin with ServiceAccount subjects | Workload SA with cluster-admin |
| K10 | Public exposure | `kubectl get svc -A --field-selector spec.type=LoadBalancer` | LB on an admin/internal panel |
| K11 | Image + limits | Same pod dump: :latest or untagged image, empty resources.limits | Unpinned images, no limits = OOM and supply-chain risk |
| K12 | NetworkPolicy | `kubectl get netpol -A` | Zero policies in user namespaces = any pod reaches any pod. This is the default on fresh clusters |
| K13 | Token automount | Same pod dump: automountServiceAccountToken not false on pods not using the API | Every pod holds a live API token it never uses |

Detection: one python pass over the pods JSON, flag privileged/hostPath/:latest/missing limits, under 30 lines of output.

## Access architecture (discovery questions for EKS/GKE behind a VPN)

Map the access path before judging. needs_validation by default; confirmed only when you saw the config yourself.

| # | Question | Finding if |
|---|---|---|
| K1 | Cluster API endpoint public or private? (`aws eks describe-cluster`) | Public API with broad CIDR allowlist |
| K2 | How does CI/CD reach the private cluster? | Long-lived kubeconfig on a runner or credentials in CI vars. Correct: in-VPC runner, OIDC role, or GitOps pull (ArgoCD/Flux) |
| K3 | How do external vendors get access? | Shared VPN accounts or shared kubeconfig = no attribution, no revocation. Correct: per-person temporary IAM role + SSM Session Manager |
| K4 | VPN cloud-native or third-party? | Third-party acceptable; check manual route tables, no SG references, no MFA on the VPN |
| K5 | Who has cluster-admin? (`kubectl get clusterrolebindings`, read-only) | More than 2-3 humans, or a vendor |
| K6 | Jenkins or legacy CI with prod credentials? | Jenkins master with static cloud keys = one compromised box owns prod. Migration path: GitOps + ephemeral runners |

## Planted-case validation record (GKE canary)

All detected: privileged pod + hostPath /, LoadBalancer on admin panel, cluster-admin to default SA, :latest without limits, zero NetworkPolicy. GKE default state: kube-system pods are privileged by design (excluded), no netpol (finding), public endpoint default.
