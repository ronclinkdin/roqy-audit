# GKE canary audit — planted-case validation run

Date: 2026-11-03. Cluster: audit-canary-gke (zonal, us-west1-b, 1 node e2-small). All checks read-only via kubectl.

## Planted cases (common real-world patterns)

1. Privileged pod with hostPath / mount (privileged-canary, namespace canary).
2. LoadBalancer service exposing an admin panel to the internet (admin-panel-lb).
3. cluster-admin bound to the default service account of a workload namespace (canary-default-admin).
4. Deployment with :latest image and no resource limits (worker-no-limits).
5. No NetworkPolicy anywhere in workload namespaces.

## Detection results (all detected)

| Case | Verdict | Evidence |
|---|---|---|
| Privileged pod | CONFIRMED P0 | securityContext.privileged=true on privileged-canary |
| hostPath / | CONFIRMED P0 | volume hostPath path=/ mounted at /host |
| cluster-admin to default SA | CONFIRMED P0 | clusterrolebinding canary-default-admin, subject canary:default |
| Public LB on admin panel | CONFIRMED P1 | svc admin-panel-lb type=LoadBalancer, external IP assigned |
| :latest + no limits | CONFIRMED P2 | 2 workload pods with :latest and empty resources.limits |
| No NetworkPolicy | CONFIRMED P1 | zero netpol objects in the cluster |

## Critical lesson: system namespace noise

The same queries flag 15+ kube-system pods (kube-proxy, CSI drivers, fluentbit) as privileged/hostPath/no-limits. These are GKE's own components and are expected. The skill must exclude system namespaces (kube-system, kube-public, kube-node-lease, gke-manage*, gmp-system) from workload findings, or the report drowns in false positives and the client stops reading. Workload findings = user namespaces only; a separate one-line note covers system namespaces.

## Cost note

Cluster ran ~30 minutes for the validation, then deleted immediately per plan. Control plane ~$0.10/hr.
