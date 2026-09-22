#!/usr/bin/env bash
set -euo pipefail

cp "$(command -v python3)" /usr/local/bin/e2e-churn
chmod 0755 /usr/local/bin/e2e-churn

