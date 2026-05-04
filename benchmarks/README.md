# readtheplan benchmarks

Source-derived Terraform plan JSON fixtures used to exercise readtheplan against larger and more varied infrastructure shapes than the unit tests.

These fixtures are anonymized plan JSON documents derived from public Terraform AWS examples. They are committed so the benchmark can run without cloud credentials, Terraform provider downloads, or live AWS access.

## Rerun

```bash
scripts/run-benchmarks.sh
```

The script regenerates every `analysis.md` file and refreshes `benchmarks/results.md` from the committed `plan.json` files.

## Scope

- AWS only, matching the current rule catalog.
- Ten plans: small, medium, and one large mixed release.
- Rule gaps are documented in [follow-ups.md](follow-ups.md), not fixed here.
