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
