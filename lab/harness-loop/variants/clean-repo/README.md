Hardened twin of vuln-lab/client-repo. Every envelope repo check should be SILENT here: any finding = false positive.

Includes clean counterparts for c26/c27: pinned image digest, no pipe-to-shell, pinned requirements + package-lock, Renovate `minimumReleaseAge`, clean skills/MCP (pinned versions, narrow filesystem root, no secrets).
