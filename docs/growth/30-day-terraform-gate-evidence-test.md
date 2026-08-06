# 30-day evidence test: AI-generated Terraform gate

## Status and window

- **Status:** proposed operating plan; founder outreach and any live analytics-goal changes require separate approval.
- **Acquisition window:** 2026-08-06 through 2026-09-04, inclusive.
- **Final retention read:** 2026-09-18, allowing a full 14-day observation period for a trial that begins on the last acquisition day.
- **Product under test:** the same free, public, MIT-licensed build available to every readtheplan user.

This is an evidence test, not a private product pilot. Setup help may shorten the path to first value, but it does not unlock features, require an account, create a paid tier, or upload infrastructure data.

## Decision to make

Test one claim:

> Teams that let AI agents propose Terraform or OpenTofu changes will keep an independent, deterministic plan gate after seeing it operate in a real repository.

Success requires all three outcomes:

1. **20 qualified contacts** during the acquisition window.
2. **5 real-repository trials** started by qualified contacts.
3. **2 gates retained at day 14** after their trial starts.

The test does not use package downloads, clone counts, generic page views, stars, bot traffic, or unqualified clicks as evidence of adoption.

## Definitions

### qualified contact

A contact counts only when all of these are true:

- they use Terraform or OpenTofu in a real repository;
- an AI coding agent currently proposes or edits infrastructure code, or they have a scheduled workflow where it will;
- they can run plan generation in an existing reviewed environment;
- they can influence whether a CI or agent gate remains in that repository; and
- they respond to a specific one-to-one conversation or request setup help.

A scraped profile, bulk message recipient, anonymous visitor, package download, or non-response does not count.

### real-repository trial

A trial counts when a qualified contact runs readtheplan against Terraform/OpenTofu plan JSON generated from a non-demo repository and reaches a `proceed`, `warn`, or `block` decision. A bundled example can teach the workflow but cannot satisfy this definition.

The user generates the plan. readtheplan does not run Terraform, refresh state, contact providers, merge, or apply. The founder never needs a copy of the plan or repository.

### useful finding

A useful finding counts only when the user explicitly confirms that a finding or the aggregate gate decision did at least one of the following:

- changed what they reviewed before merge or apply;
- caused them to request a human or security review;
- identified a risk they had not already noticed; or
- gave enough independent evidence to keep the gate for another change.

Record only `yes`, `no`, or blank in the ledger. Do not record the finding text, resource address, filename, plan size, command output, or infrastructure detail.

### gate retained at day 14

A gate counts as retained when, at or after `trial_started_at + 14 days`, either:

- the user confirms that the same repository still runs the gate; or
- the user voluntarily shows the gate configuration without exposing repository or plan data.

A copied workflow that was never enabled does not count. A gate removed before the due date does not count. No repository access is required.

## Trust boundary

- Every assisted trial uses the public release and public documentation.
- The product remains local and account-free.
- Do not request or store plans, state, HCL, repository contents, repository names, URLs, credentials, screenshots containing infrastructure details, filenames, resource addresses, or command output.
- Contact coordinates stay in the founder's existing address book or communication tool, not in this repository.
- The shared ledger uses opaque `C01`–`C20` and optional `T01`–`T05` identifiers only.
- Do not put names, handles, emails, employers, repository identifiers, or free-form infrastructure notes in the ledger.
- Stop immediately if a participant asks to stop or if continuing would require access to private infrastructure data.

## Activation signals

The website may emit only these allowlisted event names:

- `verify_change_click`
- `copy_install`
- `playground_run`
- `generate_ci`
- `setup_help_click`

These signals show intent or first interaction. They do **not** prove qualification, a real-repository trial, a useful finding, or retention. Events have no custom properties and use one fixed synthetic event URL rather than the visited page URL. Do not infer repository activation from telemetry.

Do not change live Plausible goals, deploy telemetry, or treat queued events as production evidence without explicit owner approval. Until then, the manual ledger is the decision record.

## Acquisition plan

Use four weekly cohorts of five qualified people. Prefer, in order:

1. platform, DevOps, and infrastructure engineers already known to use AI coding agents;
2. maintainers who publicly document an AI-assisted Terraform/OpenTofu workflow;
3. opt-in replies from relevant technical communities; and
4. inbound `setup_help_click` requests after the site change is approved and deployed.

Rules:

- send a specific one-to-one note, never a bulk blast;
- reference the person's public workflow, not guessed private infrastructure;
- offer one small repository trial, not a roadmap pitch;
- stop after one unanswered follow-up;
- do not count someone as qualified until they reply and meet the definition above.

### Initial message

> I maintain readtheplan, a local deterministic second check for Terraform/OpenTofu plan JSON. You mentioned using an AI coding agent around infrastructure changes. I can help you add the public gate to one non-production branch; nothing is uploaded and the agent does not approve its own output. Would a 20-minute trial on one real plan be useful?

### Follow-up after a reply

Ask only what is needed to qualify the workflow:

1. Does an AI agent propose or edit Terraform/OpenTofu in a real repository?
2. Where is plan JSON already generated—locally or in CI?
3. Could this person keep or remove a review gate after the trial?
4. Is there a safe non-production branch or change they already intend to review?

## Assisted trial runbook

1. Confirm the participant understands that readtheplan analyzes structured plan JSON only.
2. Have the participant generate the plan in their existing reviewed environment:

   ```sh
   terraform plan -out=tfplan -input=false
   terraform show -json tfplan > plan.json
   ```

   OpenTofu users substitute `tofu` for `terraform`.
3. Have the participant install and run the public package locally:

   ```sh
   python -m pip install readtheplan
   readtheplan agent-gate plan.json
   ```

4. Ask the participant to interpret the finding risk tiers separately from the aggregate `proceed`, `warn`, or `block` decision.
5. If they choose to continue, help them copy the smallest existing CI integration. Their CI or agent workflow—not readtheplan—enforces the decision.
6. Ask two outcome questions:
   - Did any finding or the decision change what you reviewed?
   - Will you keep the gate for the next infrastructure change?
7. Record only categorical answers in `activation-ledger.csv`.
8. Schedule the day-14 check from `trial_started_at`; do not ask for repository access.

## Ledger instructions

`activation-ledger.csv` is preallocated with 20 opaque contact IDs. Allowed values:

- booleans: `yes`, `no`, or blank;
- timestamps and dates: ISO 8601;
- trial IDs: `T01` through `T05` or additional opaque `TNN` values;
- loss reason: one closed category from the list below;
- next action: `qualify`, `schedule_trial`, `follow_up_once`, `check_day14`, `close`, or blank.

Closed loss-reason categories:

- `not_qualified`
- `no_reply`
- `no_time`
- `install_blocked`
- `plan_json_blocked`
- `no_useful_signal`
- `too_noisy`
- `no_ci_authority`
- `existing_control_preferred`
- `privacy_concern`
- `unknown`

Do not add free-form notes to the shared ledger. Keep consented contact logistics in the communication tool where the relationship already exists.

## Weekly operating cadence

At the end of each week, record an aggregate readout:

```text
Week ending:
Qualified contacts to date:
Replies to date:
Trials started to date:
Useful findings confirmed to date:
Day-14 checks due / completed:
Gates retained at day 14:
Top closed loss-reason categories:
Next week's single bottleneck:
```

Do not calculate conversion rates on bot traffic, downloads, or anonymous events. Small cohort counts and explicit reasons are the evidence.

## Decision rules

At the final retention read:

- **Continue the wedge:** all three thresholds are met. Keep the focused Terraform/OpenTofu journey and run another bounded cohort before expanding scope.
- **Distribution inconclusive:** fewer than 20 qualified contacts were reached. Do not claim the pain was disproved; fix access to the target audience and rerun the same test.
- **Activation failed:** at least 20 contacts qualified but fewer than 5 real-repository trials began. Fix install, plan-generation, or setup friction before adding adapters.
- **Retention failed:** at least 5 trials began but fewer than 2 gates were retained at day 14. Review the closed loss reasons and reconsider the wedge or decision quality before broader positioning.
- **Trust stop:** any trial requires plan transfer, credential sharing, hidden data collection, or misleading capability claims. Stop the trial and fix the boundary first.

One request for an unsupported adapter is not evidence to expand the homepage. One successful bundled demo is not a real trial. One copied workflow is not retention.

## Final report template

```text
Acquisition window: 2026-08-06 through 2026-09-04
Retention read complete: 2026-09-18
Qualified contacts: __ / 20
Real-repository trials: __ / 5
Useful findings confirmed: __
Gates retained at day 14: __ / 2
Most common closed loss reasons: __
Decision: continue wedge / distribution inconclusive / activation failed / retention failed / trust stop
Evidence limitations: __
Authorized next test: __
```
