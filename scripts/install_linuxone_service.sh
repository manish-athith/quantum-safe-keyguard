#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="/home/linux1/quantum-keyguard"
UNIT_SOURCE="${PROJECT_ROOT}/deploy/quantum-keyguard.service"
UNIT_TARGET="/etc/systemd/system/quantum-keyguard.service"

if [[ "$(uname -m)" != "s390x" ]]; then
  echo "This service installer is intended for the LinuxONE s390x VM." >&2
  exit 1
fi
if [[ ! -f "${UNIT_SOURCE}" ]]; then
  echo "Missing service definition: ${UNIT_SOURCE}" >&2
  exit 1
fi

install -d -m 0700 "${PROJECT_ROOT}/runtime"
find "${PROJECT_ROOT}/runtime" -maxdepth 1 -type f -exec chmod 0600 {} +
sudo install -o root -g root -m 0644 "${UNIT_SOURCE}" "${UNIT_TARGET}"
sudo systemctl daemon-reload
sudo systemctl enable --now quantum-keyguard.service

for _ in {1..10}; do
  if curl --fail --silent http://127.0.0.1:8000/health >/dev/null; then
    echo "Quantum-Safe KeyGuard is active on 127.0.0.1:8000."
    exit 0
  fi
  sleep 1
done

systemctl status quantum-keyguard.service --no-pager -l >&2
exit 1
