# CloudJack

> **Status:** work in progress. This README is a Stage 3 stub; the full
> README is written in Stage 10 once all features are implemented and tested.

**CloudJack** is an offline AWS IAM identity attack-path simulator. It
analyses synthetic snapshots of AWS IAM users, roles, policies, trust
relationships and selected resources to identify plausible escalation paths
from a starting identity to a high-value target - with evidence, risk scores,
and least-privilege remediation.

## Safety boundary

CloudJack operates on **synthetic JSON snapshots only**. It never authenticates
to AWS, never reads real credentials, and never makes changes to any cloud
account. All findings are labelled by evidence tier
(`theoretical` / `policy_supported` / `validated`) so that reviewers know
exactly how strong each claim is.

## Licence

MIT - see `LICENSE`.
