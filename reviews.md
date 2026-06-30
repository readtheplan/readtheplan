# PR Reviews

`gh pr diff 131`, `gh pr diff 132`, and `gh pr diff 133` were attempted first, but this sandbox cannot reach `api.github.com`. I reviewed the matching local branches (`feat/non-tf-provider-rules`, `feat/deprecation-runtime-test`, `feat/cfn-framework-support`) against `origin/main` instead, and spot-validated the changed behavior with direct Python probes where possible.

## PR #131 - feat: add non-Terraform provider rules for GCP, Azure, and K8s

### What's good

- Good expansion of provider coverage across GCP, Azure, and Kubernetes resource types.
- The PR adds corresponding rule tests in `tests/test_rules.py`, instead of shipping new heuristics untested.
- The new explanations follow the existing tone and fit the current `safe` / `review` / `dangerous` / `irreversible` model.

### What should change

- Several deletion-only rules are classified as `irreversible` even though they are closer to the existing repo definition of `dangerous`: disruptive and high-risk, but reconstructible. The clearest cases are in `src/readtheplan/rules.py:1602` (`_gcp_compute_firewall_candidates`), `src/readtheplan/rules.py:1832` (`_azurerm_network_security_candidates`), `src/readtheplan/rules.py:1922` (`_k8s_service_candidates`), `src/readtheplan/rules.py:2030` (`_k8s_rbac_candidates`), and `src/readtheplan/rules.py:2077` (`_k8s_network_policy_candidates`). Current AWS network equivalents use `dangerous` for similar "connectivity/authorization breaks immediately" cases, for example `src/readtheplan/rules.py:955` and `src/readtheplan/rules.py:1082`. Marking these new cases as `irreversible` will over-escalate gates and encode a stronger semantic than the rest of the rules engine currently uses.
- The tests currently lock in that stronger classification, so they should move with the rule fix. The affected expectations are around `tests/test_rules.py:669`, `tests/test_rules.py:759`, `tests/test_rules.py:814`, `tests/test_rules.py:874`, and `tests/test_rules.py:904`.

### Decision

- Request changes

## PR #132 - test: add deprecation-runtime freshness test

### What's good

- Good idea to add a guardrail around `_DEPRECATED_RUNTIMES`; the set is easy to forget otherwise.
- Coverage is sensible in shape: the tests check both "every deprecated runtime is documented" and "every documented past-EOL runtime is present in the code set."
- The current branch state passes the new checks under direct invocation.

### What should change

- Nothing blocking for today's data set.
- Minor cleanup: the logic in `tests/test_rules_freshness.py:90` says future placeholder entries in `_KNOWN_EOL` are "fine", but the test still fails the run via `tests/test_rules_freshness.py:99`. Either allow that case without failing, or change the comment/message so the behavior is not self-contradictory.

### Decision

- Approve

## PR #133 - test: add CloudFormation --framework control ID tests

### What's good

- The tests cover the behavior that matters: `cloudformation` without `--framework` omits control IDs, and `cloudformation --framework soc2` emits them.
- Reusing the existing mixed CloudFormation fixture keeps the coverage close to a real CLI path instead of unit-testing internals only.
- I directly exercised the CLI on this branch and confirmed the expected split: no `rtp.control.*` checks without `--framework`, and SOC 2 control checks present with it.

### What should change

- Nothing blocking.
- If you want to tighten the test file later, the first two new tests are somewhat redundant with the later output assertions, but that is not a correctness problem.

### Decision

- Approve
