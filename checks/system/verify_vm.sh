#!/bin/sh
# Local VM verification only. No sudo, SSH or Git operations in this script.
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

cd ../..

if [ "$(uname -s)" != "Linux" ]; then
    echo "Run this script inside your Linux VM."
    exit 2
fi
if ! command -v getfacl >/dev/null 2>&1 || ! command -v setfacl >/dev/null 2>&1; then
    echo "ACL tools are missing. On Ubuntu, install them and rerun:"
    echo "  Ubuntu: sudo apt update"
    echo "  Ubuntu: sudo apt install acl python3-venv"
    echo "  Rocky: sudo dnf install acl python3-pip"
    exit 2
fi

if [ ! -x .venv/bin/python ]; then
    if ! python3 -m venv .venv; then
        echo "Cannot create the project-only Python environment. On Ubuntu:"
        echo "  sudo apt install python3-venv"
        echo "Then rerun: bash checks/system/verify_vm.sh"
        exit 2
    fi
fi
if ! .venv/bin/python -c 'from jsonschema import Draft202012Validator; import rfc3339_validator' >/dev/null 2>&1; then
    .venv/bin/python -m pip install -r checks/system/requirements-dev.txt
fi
exec .venv/bin/python -m checks.system.verify_all "$@"
