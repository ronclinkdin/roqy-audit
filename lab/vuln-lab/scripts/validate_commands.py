#!/usr/bin/env python3
"""Validate every `aws <service> <operation>` in EXPECTED-FINDINGS.yaml against the installed AWS CLI
command table (awscli + botocore). Usage: python scripts/validate_commands.py [EXPECTED-FINDINGS.yaml]"""
import sys, re, shlex, yaml
from awscli.clidriver import create_clidriver
import botocore

path = sys.argv[1] if len(sys.argv) > 1 else "EXPECTED-FINDINGS.yaml"
doc = yaml.safe_load(open(path))
drv = create_clidriver()
services = drv._get_command_table()
cache, bad, n = {}, [], 0
for pl in doc["plants"]:
    for cmd in pl["detect_read_only"]:
        toks = shlex.split(cmd.replace("<", "_").replace(">", "_"))
        if len(toks) < 3 or toks[0] != "aws":
            bad.append((pl["id"], cmd, "not an aws CLI command")); continue
        svc, op = toks[1], toks[2]
        n += 1
        if svc not in services:
            bad.append((pl["id"], cmd, f"unknown service {svc}")); continue
        if svc not in cache:
            cache[svc] = services[svc]._get_command_table() if hasattr(services[svc], "_get_command_table") else services[svc].subcommand_table
        if op not in cache[svc]:
            bad.append((pl["id"], cmd, f"unknown operation {svc} {op}"))
print(f"botocore {botocore.__version__}: checked {n} commands, {len(bad)} invalid")
for b in bad:
    print("INVALID", *b, sep=" | ")
sys.exit(1 if bad else 0)
