# Benchmark results

Generated: 2026-05-03
readtheplan version: 0.0.2

| Plan | Source | Resources | Actions | Risks | Time | Edge cases |
| --- | --- | ---: | --- | --- | --- | --- |
| `01-vpc-module-complete` | terraform-aws-modules/vpc | 43 | create:43 | safe:43 | <0.1s | network resources action-only |
| `02-eks-managed-node-groups` | terraform-aws-modules/eks | 12 | create:4, delete/create:1, update:7 | dangerous:1, review:7, safe:4 | <0.1s | node group replacement |
| `03-rds-upgrade-window` | terraform-aws-modules/rds | 9 | create:2, delete:1, delete/create:1, update:5 | dangerous:2, irreversible:1, review:4, safe:2 | <0.1s | major DB upgrade |
| `04-s3-log-archive` | terraform-aws-modules/s3-bucket | 12 | create:6, update:6 | review:6, safe:6 | <0.1s | lifecycle resources action-only |
| `05-kms-multi-region` | aws-samples/aws-tf-kms | 7 | create:3, delete:1, delete/create:1, update:2 | dangerous:1, irreversible:1, review:2, safe:3 | <0.1s | replica key action-only |
| `06-security-group-rules` | terraform-aws-modules/security-group | 16 | create:6, delete:1, delete/create:1, update:8 | dangerous:1, irreversible:1, review:8, safe:6 | <0.1s | NACL action-only |
| `07-iam-boundary-refresh` | terraform-aws-modules/iam | 11 | create:4, delete:1, update:6 | irreversible:1, review:6, safe:4 | <0.1s | instance profile action-only |
| `08-route53-cutover` | terraform-aws-modules/route53 | 8 | create:1, delete:1, delete/create:1, update:5 | dangerous:1, irreversible:1, review:5, safe:1 | <0.1s | zone delete |
| `09-cloudtrail-org-trail` | cloudposse/cloudtrail | 10 | create:5, update:5 | review:5, safe:5 | <0.1s | metric alarms action-only |
| `10-large-platform-release` | terraform-aws-modules composition | 129 | create:62, delete:2, delete/create:3, update:62 | dangerous:4, irreversible:2, review:61, safe:62 | 0.1s | many unmapped service types |

## Summary

- Total plans: 10
- Total resource changes processed: 257
- Edge cases / rule gaps: 10 (see follow-ups.md)
- Avg time per resource: <1ms in local Python 3.13 smoke runs
- No crashes / no exceptions across the suite
