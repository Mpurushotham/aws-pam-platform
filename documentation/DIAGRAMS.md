# Architecture Diagrams

All diagrams use [Mermaid](https://mermaid.js.org/), which GitHub renders
natively — no external tooling needed. Edit the fenced ` ```mermaid ` blocks
directly and the rendered picture updates on push.

> **How to read this page:** start with the *System context* for the big
> picture, then the *Module dependency graph* to see how the Terraform fits
> together, then the *sequence diagrams* for the two flows people ask about
> most (getting access, rotating a secret), and finally the *CI/CD* flow for
> how changes ship.

---

## 1. System context (who talks to what)

**Use this** to understand the moving parts and trust boundaries at a glance.

```mermaid
flowchart TB
    eng["👤 Engineer<br/>(federated + MFA)"]
    ci["⚙️ GitHub Actions<br/>(OIDC, no static keys)"]
    pam["🔐 External PAM<br/>(CyberArk / BeyondTrust)"]

    subgraph aws["AWS Account (per environment)"]
        direction TB
        roles["IAM Roles<br/>MFA-enforced, time-bound"]
        ssm["SSM Session Manager<br/>keyless, recorded"]
        sm["Secrets Manager<br/>KMS + rotation"]
        ct["CloudTrail<br/>100% API capture"]
        cfg["AWS Config<br/>CIS / PCI / SOC2 rules"]
        kms["KMS Keys<br/>secrets + audit"]

        s3audit[("S3 audit logs<br/>immutable, KMS")]
        s3sess[("S3 session logs<br/>KMS")]
        cw["CloudWatch Logs<br/>+ metric alarms"]
        sns["SNS alerts"]
    end

    graf["📊 Grafana<br/>(CloudWatch datasource)"]

    eng -->|AssumeRole + MFA| roles
    eng -->|StartSession| ssm
    ci  -->|terraform apply| aws
    roles --> sm
    ssm --> s3sess
    ssm --> cw
    sm  --> kms
    ct  --> s3audit
    ct  --> cw
    cw  -->|metric filters| sns
    cfg -->|NON_COMPLIANT| sns
    kms -. encrypts .-> sm
    kms -. encrypts .-> s3audit
    kms -. encrypts .-> s3sess
    pam <-->|discovery export| roles
    graf -->|reads metrics| cw

    classDef store fill:#e8f0fe,stroke:#4285f4;
    class s3audit,s3sess store;
```

---

## 2. Module dependency graph (Terraform)

**Use this** before editing modules — it shows what feeds what. `kms-encryption`
is the root dependency; break it and everything downstream fails.

```mermaid
flowchart LR
    kms["kms-encryption"]
    ct["cloudtrail-audit"]
    pol["iam-policies"]
    roles["iam-roles"]
    sec["pam-secrets-manager"]
    ssm["ssm-session-manager"]
    comp["compliance-framework"]

    kms --> ct
    kms --> pol
    kms --> sec
    kms --> ssm
    kms --> comp
    pol --> roles
    ct  --> ssm

    classDef root fill:#fce8b2,stroke:#f9ab00,stroke-width:2px;
    class kms root;
```

Each environment in `terraform/environments/{dev,stage,prod}/main.tf` is an
identical composition of these seven modules — only the variable *values*
differ (rotation cadence, retention, trusted accounts).

---

## 3. Access provisioning flow (request → approval → expiry)

**Use this** when working on `pam_access_provisioner.py`. Note the
separation-of-duties rule: the approver must differ from the requester.

```mermaid
sequenceDiagram
    autonumber
    participant U as Engineer
    participant CLI as pam_access_provisioner.py
    participant DDB as DynamoDB<br/>(pam-access-requests)
    participant A as Approver
    participant IAM as AWS IAM

    U->>CLI: request --user --role --hours --reason
    CLI->>DDB: put_item(status="pending")
    Note over CLI,DDB: justification required;<br/>duration capped at 12h

    A->>CLI: approve --request-id --approver
    CLI->>DDB: get_item
    CLI-->>A: reject if self-approval
    CLI->>IAM: add_user_to_group(role)
    CLI->>DDB: status="active", expires_at=now+hours

    Note over CLI,IAM: ...time passes...

    CLI->>CLI: expire-sweep (scheduled)
    CLI->>IAM: remove_user_from_group
    CLI->>DDB: status="expired"
```

---

## 4. Secret rotation flow (with rollback)

**Use this** when working on `pam_secret_rotation.py`. It implements the
four-step Secrets Manager rotation contract and always keeps the prior value
recoverable.

```mermaid
sequenceDiagram
    autonumber
    participant Job as secrets-rotation.yml
    participant R as pam_secret_rotation.py
    participant SM as Secrets Manager

    Job->>R: rotate --secret-id
    R->>SM: get AWSCURRENT
    R->>R: generate strong value
    R->>SM: put AWSPENDING (new version)
    R->>SM: get AWSPENDING (verify round-trip)
    alt verification passes
        R->>SM: move AWSCURRENT → pending<br/>(old becomes AWSPREVIOUS)
        R-->>Job: success
    else verification fails
        R-->>Job: abort (AWSCURRENT untouched)
    end

    Note over R,SM: rollback path
    Job->>R: rotate --rollback
    R->>SM: move AWSCURRENT → AWSPREVIOUS
```

---

## 5. CI/CD pipeline (how a change ships)

**Use this** to understand what runs when. Dev is automatic on merge; prod is
manual, confirmation-gated, and approval-gated.

```mermaid
flowchart TD
    pr["Pull Request"] --> val["iac-validate.yml<br/>fmt · validate · tflint · checkov · pytest"]
    val -->|pass| merge["Merge to main"]
    merge --> devjob["deploy-dev.yml<br/>OIDC → terraform apply (dev)"]
    devjob --> smoke["post-deploy compliance audit"]

    disp["workflow_dispatch<br/>(human)"] --> guard["deploy-prod.yml<br/>confirm phrase = deploy-prod"]
    guard --> planj["plan (production-plan env)"]
    planj --> approve{"production env<br/>required reviewer"}
    approve -->|approved| applyj["apply (prod)"]
    approve -->|rejected| stop["blocked"]

    cron["weekly cron"] --> audit["compliance-audit.yml<br/>CIS/PCI/SOC2 + anomaly scan"]
    audit -->|high severity| issue["auto-file GitHub issue"]

    cron2["weekly cron"] --> rot["secrets-rotation.yml<br/>rotate all managed secrets"]

    classDef gate fill:#fce8b2,stroke:#f9ab00;
    class guard,approve gate;
```

---

## Regenerating / exporting

- **GitHub** renders these inline automatically.
- **VS Code**: install the *Markdown Preview Mermaid Support* extension.
- **PNG/SVG export**: `npx @mermaid-js/mermaid-cli -i documentation/DIAGRAMS.md -o out.png`
