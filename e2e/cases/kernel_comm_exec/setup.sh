#!/usr/bin/env bash
set -euo pipefail

cp --dereference "$(command -v python3)" /usr/local/bin/e2e-kmatch
cp --dereference "$(command -v python3)" /usr/local/bin/e2e-kmiss
chmod 0755 /usr/local/bin/e2e-kmatch /usr/local/bin/e2e-kmiss
