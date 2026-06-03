# Contributing

Thanks for working on the AWS PAM platform. This is a short pointer; the full
guide is **[documentation/ONBOARDING.md](documentation/ONBOARDING.md)**.

## TL;DR

```bash
make setup                                   # one-time: deps + pre-commit hooks
git checkout -b feat/short-description        # never commit to main
# ...make your change...
make ci                                       # fmt + validate + lint + tests
git commit -m "feat: what and why"            # hooks run automatically
git push -u origin feat/short-description      # open a PR
```

## Ground rules

- **Branch + PR for everything.** No direct commits to `main`. Every change to
  privileged access gets a second reviewer.
- **Local gate must pass.** `make ci` mirrors the `iac-validate.yml` pipeline.
- **No secrets, ever.** No AWS keys, no secret values, no `terraform.tfvars` in
  commits. Pre-commit (gitleaks + detect-aws-credentials) and a repo test guard
  this, but you are the first line of defense.
- **Keep MFA enforcement intact.** Don't strip `aws:MultiFactorAuthPresent`
  conditions; `tests/compliance/` will fail and so will review.
- **Document as you go.** New behaviour → update the relevant `documentation/`
  page in the same PR.

## Where to put your change

| Change type | Location |
| ----------- | -------- |
| AWS resources | `terraform/modules/` (+ wire into env if new) |
| Env-specific values | `terraform/environments/<env>/terraform.tfvars` |
| Operational behaviour | `scripts/python/` (+ a test) |
| CI/CD | `.github/workflows/` |
| Dashboards / alarms | `monitoring/` |

## Commit messages

Conventional-style prefixes keep history scannable: `feat:`, `fix:`, `docs:`,
`refactor:`, `test:`, `chore:`. Say **what** changed and **why** in the body.

See the [onboarding guide](documentation/ONBOARDING.md) for the full repo tour,
recipes, and guardrails.
