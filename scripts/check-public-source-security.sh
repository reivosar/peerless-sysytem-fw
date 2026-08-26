#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
scan_root="${1:-$repo_root}"
cd "$scan_root"

failures=0

source_files() {
  if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git ls-files -z --cached --others --exclude-standard
  else
    find . -type f -print0
  fi
}

report_matches() {
  local description="$1"
  local pattern="$2"
  local matches
  matches="$(
    while IFS= read -r -d '' path; do
      [[ "$path" == 'scripts/check-public-source-security.sh' ]] && continue
      grep -n -I -H -E -- "$pattern" "$path" || true
    done < <(source_files)
  )"
  if [[ -n "$matches" ]]; then
    printf 'public-source security failure: %s\n%s\n' "$description" "$matches" >&2
    failures=1
  fi
}

report_rust_matches() {
  local description="$1"
  local pattern="$2"
  local matches
  matches="$(
    while IFS= read -r -d '' path; do
      [[ "$path" == *.rs ]] || continue
      grep -n -I -H -E -- "$pattern" "$path" || true
    done < <(source_files)
  )"
  if [[ -n "$matches" ]]; then
    printf 'public-source security failure: %s\n%s\n' "$description" "$matches" >&2
    failures=1
  fi
}

# Build high-risk markers from fragments so this gate does not match its own
# source. These are operational-secret formats, not public test-vector values.
pem_begin='-----BEGIN '
pem_secret="${pem_begin}(RSA |EC |OPENSSH )?PRIVATE KEY-----"
report_matches 'tracked private-key PEM material' "$pem_secret"

aws_prefix='AKI''A[0-9A-Z]{16}'
report_matches 'tracked AWS access-key shaped value' "$aws_prefix"

github_classic='gh''p_[A-Za-z0-9]{30,}'
github_fine='github_pat''_[A-Za-z0-9_]{30,}'
report_matches 'tracked GitHub token shaped value' "${github_classic}|${github_fine}"

slack_token='xo''x[baprs]-[A-Za-z0-9-]{20,}'
report_matches 'tracked Slack token shaped value' "$slack_token"

assignment_name='(api[_-]?key|password|private[_-]?key|secret|token[_-]?seed)'
assignment_value="[[:space:]]*[:=][[:space:]]*['\"][A-Za-z0-9+/=_-]{16,}['\"]"
report_matches 'tracked hard-coded secret assignment' "${assignment_name}${assignment_value}"

tracked_key_files="$(
  while IFS= read -r -d '' path; do
    if grep -q -E '(^|/)(key\.protobuf|id_(rsa|dsa|ecdsa|ed25519)|[^/]+\.(key|pem|p12|pfx))$' \
      <<<"$path"; then
      printf '%s\n' "$path"
    fi
  done < <(source_files)
)"
if [[ -n "$tracked_key_files" ]]; then
  printf 'public-source security failure: tracked operational-key shaped files\n%s\n' \
    "$tracked_key_files" >&2
  failures=1
fi

# Test vectors must be visibly scoped. Production code must not expose a
# feature or environment switch that accepts deterministic private material.
deterministic_bypass='(ALLOW|ACCEPT|USE)_(FIXED|TEST|DETERMINISTIC)_(KEY|SECRET|TOKEN)'
report_matches 'production secret-bypass shaped switch' "$deterministic_bypass"

# RUSTSEC-2023-0071 affects the RustCrypto RSA private operation. The
# privacypass dependency is restricted to client blinding/finalization and
# public verification. Issuer private operations use OpenSSL. Keep that
# reachability claim machine-enforced whenever source is public or modified.
private_rsa_api='(IssuerServer|IssuerKeyStore|PrivateIssuerKeyPair|blind_sign\()'
report_rust_matches 'forbidden RustCrypto private-RSA operation' "$private_rsa_api"

if (( failures != 0 )); then
  exit 1
fi

printf 'public-source-security status=PASS tracked_operational_secrets=false hidden_key_bypass=false rustcrypto_private_rsa=false\n'
