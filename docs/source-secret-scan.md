# Source-only secret scan

The `Source secret scan` workflow runs Gitleaks against the exact checked-out source
tree for pull requests and pushes to `main`. It is deliberately narrower than a
release or enterprise DevSecOps pipeline.

## Trust boundary

The workflow:

- grants only `contents: read`;
- never reads GitHub secrets, variables, environments, or OIDC tokens;
- uses a hosted `ubuntu-24.04` runner with a timeout;
- disables persisted checkout credentials;
- pins checkout to a full commit and Gitleaks to an immutable image digest;
- runs the scanner as a non-root user with no network, a read-only root filesystem,
  dropped capabilities, `no-new-privileges`, and a read-only repository mount;
- scans directory content with `gitleaks dir`, not Git history; and
- does not upload artifacts, publish packages, sign, deploy, or mutate Git.

Because this is a source-tree gate, it does not claim to find a secret that was
removed from the current tree but remains in repository history. Historical incident
response and credential rotation remain separate operations.

The repository dogfood scanner also analyzes this workflow. Adding the thirteenth
scanned file contributes exactly one `safe`, one `review`, and one `dangerous`
finding, so the checked-in dogfood ceiling changes from `16/158/155` to
`17/159/156` while `maximum_errors` remains zero and
`minimum_scanned_files` rises from 12 to 13. This is an inventory adjustment, not
a suppression of the new workflow.

## Allowlist policy

`.gitleaks.toml` extends the upstream defaults. Exceptions are limited to synthetic
fixtures or confirmed detector false positives. Every exception must bind the detector
rule to an exact repository-root path (accepting only the workflow's fixed `/repo/`
mount prefix). A matching basename under another directory must not be suppressed.
Exceptions outside dedicated synthetic fixtures must also bind a distinctive line
expression with `condition = "AND"`.

Do not add broad path globs, commit-wide exclusions, generic regexes, or stopwords.
A new exception requires reading the reported source line, confirming it contains no
credential, updating the contract test, and rerunning the real hardened scanner.

## Local verification

With Docker available from a POSIX-compatible shell at the repository root:

```bash
image='ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f'
docker run --rm \
  --network none \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --user 65532:65532 \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --mount "type=bind,source=$PWD,target=/repo,readonly" \
  "$image" dir /repo \
    --config /repo/.gitleaks.toml \
    --no-banner \
    --redact \
    --verbose
```

On Git Bash for Windows, use a native bind-source path and disable MSYS argument
rewriting for the Docker invocation. A successful run must report a nonzero scanned
byte count and `no leaks found`; exit status alone is not sufficient evidence.

## Out of scope

Bandit, dependency auditing, Checkov, SBOM generation, commercial scanners, package or
container promotion, protected environments, and GitOps/deployment changes belong in
separate independently reviewed changes.
