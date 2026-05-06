# Weekly Terraform/SOC 2 Brief Runbook

This runbook supports the static `/brief/` paid-output loop slice. It defines how
to produce a weekly Terraform/SOC 2 change intelligence brief without adding a
backend, raw plan upload, account system, storage, billing flow, hosted analyzer,
hosted MCP service, or activated automation.

## Source Categories To Monitor

- Terraform and OpenTofu ecosystem release notes, provider changelogs, registry
  notices, and migration guides.
- AWS identity, logging, networking, data protection, encryption, backup, and
  audit-service documentation updates.
- GitHub Actions security, permissions, artifact, runner, and organization-policy
  changes.
- SOC 2 evidence and cloud-control guidance that affects change management,
  logical access, monitoring, confidentiality, and availability.
- readtheplan project progress, including CLI, GitHub Action, local MCP preview,
  Terraform risk calculator, SOC 2 cloud control mapper, docs, and examples.

Do not ask customers to upload raw Terraform plans. If company-specific context
is approved, use high-level source categories, keywords, control priorities, and
links supplied by the customer.

## Quality Bar

- Label demo or sample content clearly when it is not current external news.
- Include only items that a platform team, SRE team, DevOps consultancy, SOC 2
  consultant, or infra/devtool startup can act on.
- Explain why each item matters in operational language.
- Map each item to a Terraform/SOC 2 risk angle such as IAM, logging, networking,
  data protection, change management, monitoring, confidentiality, or availability.
- Prefer concise action checklists over broad commentary.
- Preserve the local-first privacy posture in every issue.
- Avoid unsupported current-news assertions; cite source links in paid/private
  issues before delivery.

## Output Format

1. Title and issue number.
2. Audience and scope.
3. Privacy boundary: no raw Terraform plan upload or hosted analysis.
4. Top 5 infra/compliance changes.
5. Why each change matters.
6. Terraform/SOC 2 risk angle for each change.
7. SOC 2 evidence notes.
8. Action checklist.
9. readtheplan CTA: local CLI, setup generator, local MCP preview, or private
   pilot/custom integration.
10. Placeholder or approved delivery contact.

## Approval And Delivery Steps

1. Draft the issue from monitored sources and clearly mark sample/demo items.
2. Verify every current external claim against its source before private delivery.
3. Remove raw customer secrets, raw Terraform plan JSON, account identifiers, and
   sensitive infrastructure details.
4. Confirm the CTA uses the configured placeholder convention unless a production
   inbox has been approved.
5. Review for prohibited product claims: no backend, no storage, no hosted
   analyzer, no hosted MCP service, no account system, no billing flow, and no raw
   Terraform plan submission.
6. Deliver only through the approved manual channel for the pilot.

## Automation Boundary

Cron, scheduled delivery, and other recurring automation must not be enabled until
explicitly approved. This repository slice is a static landing page, sample page,
and editorial runbook only.
