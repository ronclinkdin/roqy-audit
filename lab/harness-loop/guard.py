"""Read-only guardrail enforcement for every audit command (aws / kubectl / helm).
Raises GuardViolation BEFORE the command runs. Rules live in surface/guardrails.yaml."""
import os, re, yaml

PATH = os.environ.get("ROQY_GUARDRAILS", os.path.join(os.path.dirname(os.path.abspath(__file__)), "surface", "guardrails.yaml"))
G = yaml.safe_load(open(PATH))


class GuardViolation(RuntimeError):
    pass


def check_aws(cmd, env):
    g = G["aws"]
    if cmd[0] != "aws":
        raise GuardViolation(f"not an aws command: {cmd[0]}")
    for k in g["forbid_env"]:
        if env.get(k):
            raise GuardViolation(f"{k} present in audit env (admin credentials must never reach the audit)")
    if env.get("AWS_PROFILE") not in g["allowed_profiles"]:
        raise GuardViolation(f"profile {env.get('AWS_PROFILE')!r} not in allowed_profiles")
    svc, op = cmd[1], (cmd[2] if len(cmd) > 2 else "")
    if svc in g["denied_services"]:
        raise GuardViolation(f"service {svc} denied (object data)")
    if op in g["denied_ops"]:
        raise GuardViolation(f"{svc} {op}: returns secret values / data, denied")
    if not (re.match(g["allowed_op_regex"], op) or op in g["allowed_ops_extra"]):
        raise GuardViolation(f"{svc} {op}: verb not on the read-only allowlist")
    for a in cmd[3:]:
        if any(a == d or a.startswith(d + "=") for d in g["denied_args"]):
            raise GuardViolation(f"argument {a} denied")
    return True


def check_kubectl(cmd):
    g = G["kubectl"]
    if g.get("require_context") and "--context" not in cmd:
        raise GuardViolation("kubectl without --context")
    rest = [x for i, x in enumerate(cmd[1:], 1) if not (cmd[i - 1] == "--context" or x == "--context")]
    verb = rest[0] if rest else ""
    if verb not in g["allowed_verbs"]:
        raise GuardViolation(f"kubectl {verb}: verb not allowed")
    if verb == "get" and re.search(g["denied_resources_regex"], " ".join(rest[1:2]).lower()):
        raise GuardViolation("kubectl get secrets is never allowed")
    return True


def check_helm(cmd):
    g = G["helm"]
    if g.get("require_kube_context") and "--kube-context" not in cmd:
        raise GuardViolation("helm without --kube-context")
    rest = [x for i, x in enumerate(cmd[1:], 1) if not (cmd[i - 1] == "--kube-context" or x == "--kube-context")]
    if not rest or rest[0] not in g["allowed_verbs"]:
        raise GuardViolation(f"helm {rest[:1]}: verb not allowed (helm get values reads release Secrets)")
    return True
