import os, sys, pytest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import guard
RO = {"AWS_PROFILE": "roqy-audit-ro"}
ok = [["aws", "iam", "list-users"], ["aws", "s3api", "get-bucket-policy", "--bucket", "x"], ["aws", "budgets", "describe-budgets"],
      ["aws", "elasticbeanstalk", "check-dns-availability", "--cname-prefix", "a"], ["aws", "iam", "generate-credential-report"]]
bad = [["aws", "secretsmanager", "get-secret-value", "--secret-id", "x"], ["aws", "ssm", "get-parameter", "--name", "x"],
       ["aws", "s3api", "get-object", "--bucket", "b", "--key", "k", "/tmp/o"], ["aws", "s3", "cp", "s3://b/k", "."],
       ["aws", "ec2", "run-instances"], ["aws", "iam", "create-access-key"], ["aws", "lambda", "invoke", "--function-name", "f", "o"],
       ["aws", "ssm", "describe-parameters", "--with-decryption"], ["aws", "ec2", "get-password-data", "--instance-id", "i"],
       ["aws", "ecr", "get-login-password"], ["aws", "logs", "get-log-events"], ["aws", "dynamodb", "get-item"]]
@pytest.mark.parametrize("c", ok)
def test_allowed(c): assert guard.check_aws(c, RO)
@pytest.mark.parametrize("c", bad)
def test_denied(c):
    with pytest.raises(guard.GuardViolation): guard.check_aws(c, RO)
def test_admin_env_blocked():
    with pytest.raises(guard.GuardViolation): guard.check_aws(["aws", "iam", "list-users"], {"AWS_PROFILE": "roqy-audit-ro", "AWS_ACCESS_KEY_ID": "AKIAX"})
def test_wrong_profile():
    with pytest.raises(guard.GuardViolation): guard.check_aws(["aws", "iam", "list-users"], {"AWS_PROFILE": "default"})
def test_kubectl():
    assert guard.check_kubectl(["kubectl", "--context", "c", "get", "pods", "-A", "-o", "json"])
    for c in (["kubectl", "--context", "c", "get", "secrets", "-A"], ["kubectl", "--context", "c", "get", "secret/x"],
              ["kubectl", "--context", "c", "exec", "p", "--", "sh"], ["kubectl", "get", "pods"], ["kubectl", "--context", "c", "delete", "pod", "x"]):
        with pytest.raises(guard.GuardViolation): guard.check_kubectl(c)
def test_helm():
    assert guard.check_helm(["helm", "--kube-context", "c", "list", "-A"])
    for c in (["helm", "--kube-context", "c", "get", "values", "r"], ["helm", "--kube-context", "c", "uninstall", "r"], ["helm", "list"]):
        with pytest.raises(guard.GuardViolation): guard.check_helm(c)
