#!/usr/bin/env bash
# Full CLI test driver for the windows provider (terraform commands only).
#
# Offline stages (no Windows host needed):
#   1. terraform init
#   2. terraform fmt -check
#   3. terraform validate
#   4. terraform test   (mocked provider, no network)
#
# Online stages (need a reachable Windows target, see terraform.tfvars):
#   5. terraform plan
#   6. terraform apply + output cross-checks (check blocks fail the apply)
#   7. terraform apply -destroy (idempotence: second apply must be empty)
#
# Usage:
#   cd test/terraform-cli
#   cp terraform.tfvars.example terraform.tfvars   # adjust host/password
#   ./run-tests.sh            # offline only (default)
#   ./run-tests.sh --apply   # offline + plan/apply/destroy against the lab host
set -euo pipefail

TERRAFORM="${TERRAFORM:-terraform}"
MODE="offline"
if [[ "${1:-}" == "--apply" ]]; then
  MODE="online"
fi

cd "$(dirname "$0")"

pass() { printf 'PASS: %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

[[ -f terraform.tfvars ]] || {
  echo "terraform.tfvars missing — copying example (edit it for your lab host)."
  cp terraform.tfvars.example terraform.tfvars
}

echo "==> terraform init"
$TERRAFORM init -input=false

echo "==> terraform fmt -check"
$TERRAFORM fmt -check -diff . || fail "terraform fmt found diffs (run: terraform fmt .)"

echo "==> terraform validate"
$TERRAFORM validate || fail "validate failed"

echo "==> terraform test (mocked provider, offline)"
$TERRAFORM test -test-directory=. || fail "mocked terraform test failed"
pass "offline stages (init/fmt/validate/test) OK"

if [[ "$MODE" != "online" ]]; then
  cat <<'EOF'
SKIP: online stages (plan/apply/destroy need a Windows target).
Re-run with ./run-tests.sh --apply once terraform.tfvars points at a
reachable host (see test/windows-container/README.md).
EOF
  exit 0
fi

echo "==> terraform plan (online, against lab host)"
$TERRAFORM plan -input=false -out=tfplan || fail "plan failed"

echo "==> terraform apply"
$TERRAFORM apply -input=false -auto-approve tfplan || fail "apply failed"
rm -f tfplan

echo "==> output cross-checks (resource vs data source)"
$TERRAFORM output -json > /tmp/opencode/cli-outputs.json
python3 - <<'EOF'
import json, sys
out = json.load(open('/tmp/opencode/cli-outputs.json'))
def val(name):
    return out[name]['value']
checks = [
    ('check_registry_value', val('check_registry_value')['resource'], val('check_registry_value')['data']),
    ('check_registry_dword', val('check_registry_dword')['resource'], val('check_registry_dword')['data']),
    ('check_local_user_sid', val('check_local_user_sid')['resource'], val('check_local_user_sid')['data']),
    ('check_group_member_sid', val('check_group_member_sid')['resource'], val('check_group_member_sid')['data']),
    ('check_env_var', val('check_env_var')['resource'], val('check_env_var')['data']),
]
failed = False
for name, resource, data in checks:
    status = 'PASS' if resource == data else 'FAIL'
    if status == 'FAIL':
        failed = True
    print(f'{status}: {name} resource={resource!r} data={data!r}')
sys.exit(1 if failed else 0)
EOF
pass "resource vs data source outputs agree"

echo "==> idempotence: second plan must be empty"
$TERRAFORM plan -input=false -detailed-exitcode && pass "second plan empty (no diff)" || {
  code=$?
  [[ $code -eq 2 ]] && fail "second plan still shows a diff (non-idempotent)"
  fail "second plan errored (exit $code)"
}

echo "==> terraform destroy"
$TERRAFORM apply -input=false -auto-approve -destroy || fail "destroy failed"
pass "online stages (plan/apply/verify/destroy) OK"
