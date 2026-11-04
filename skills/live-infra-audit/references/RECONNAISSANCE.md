# Reconnaissance

Map what exists before judging anything. One batched terminal call per phase. Record the inventory in the report before any finding.

## Docker/VPS host

Run together: `hostname; uname -r; uptime`; `docker ps --format '{{.Names}}\t{{.Image}}\t{{.Status}}'`; `ss -tlnp | grep -v 127.0.0.1`; `docker images`; `df -h` on all mounts; `free -m`; `crontab -l`; `systemctl list-units --state=failed`.

## GCP project

`gcloud projects list`; `gcloud projects get-iam-policy <p>`; `gcloud iam service-accounts list`; `gcloud storage ls`; `gcloud compute instances list`; `gcloud compute firewall-rules list`; `gcloud billing projects describe <p>`. Set CLOUDSDK_CORE_PROJECT explicitly.

## AWS account

`aws sts get-caller-identity`; `aws iam list-users`; `aws s3api list-buckets`; `aws ec2 describe-instances`; `aws ec2 describe-security-groups`; `aws eks list-clusters`; `aws cloudtrail describe-trails`; `aws budgets describe-budgets`.

## Kubernetes cluster

`kubectl get ns`; `kubectl get pods -A -o json` (to a file, never to the conversation); `kubectl get svc -A`; `kubectl get clusterrolebindings -o json`; `kubectl get netpol -A`.

## Rules

- Count before you list (`| wc -l` first). Over 50 resources = sample top 20 by exposure plus the count.
- Raw output goes to files in `~/infra-readiness-audit/<target>/<date>/raw/`, never to the conversation.
- Disabled APIs or missing tools are a finding-adjacent note, not a blocker — report what the enabled surface is.
- A clean sandbox account proves the pipeline, not the value. State that explicitly.


## Curl discipline (zero-friction rule)

Client veto: before the FIRST network probe of the audit, present the list of planned probes (which checks, which endpoints, one request each) and ask the client to approve or strike any of them. The client can refuse any probe at any time, including mid-audit. A refused probe is never run; the check becomes needs_validation with the reason "client declined network probe". Never argue, never work around a refusal (no alternate endpoints, no different methods).

Every network probe must survive three questions: whose infrastructure is it, did they consent to this audit scope, and does the probe fetch content or just prove reachability.

1. Status code only: every probe uses `-o /dev/null -w '%{http_code}'` or `-sI` (HEAD). Never save a response body to the report or to disk. The status code is the evidence; the body is somebody's data.
2. Scope: probes only against the client's own infrastructure, inside the consented audit scope. No probing of third-party infrastructure, ever. If recon of public surface finds a third-party exposure, report the observation without accessing it and let the client verify.
3. K17 exception: kubelet 10255 `/pods` returns real pod data. Only run it when the client's written scope includes internal network checks; otherwise report "port 10255 reachable" from the connection state alone.
4. One request per check. No scanning, no fuzzing, no wordlists, no retries beyond a single retry on timeout. A probe that needs brute force is not an audit finding, it is an attack.
5. Rate and footprint: sequential, human-paced. If the client has rate limiting or WAF, a single probe is indistinguishable from a user; a scan is not.
