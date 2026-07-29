# Project Argus

**Privileged Access Misuse & Insider Threat Detection on AWS**

An event-driven AWS serverless solution that detects, correlates, and automatically responds to privileged IAM misuse in near real time.

![AWS](https://img.shields.io/badge/AWS-Cloud_Security-orange)
![Python](https://img.shields.io/badge/Python-3.x-blue)
![Serverless](https://img.shields.io/badge/Architecture-Serverless-success)
![License](https://img.shields.io/badge/License-MIT-green)

Just-In-Time Access • Continuous Monitoring • Identity-Aware Risk Engine • Automated Response

---

## Table of Contents

- [The Problem](#the-problem)
- [Design Philosophy](#design-philosophy)
- [Features](#features)
- [Architecture](#architecture)
- [How It Works](#how-it-works)
- [Example: What Triggers a Critical Alert](#example-what-triggers-a-critical-alert)
- [Why It's Built This Way](#why-its-built-this-way)
- [AWS Services Used](#aws-services-used)
- [Repository Structure](#repository-structure)
- [Skills Demonstrated](#skills-demonstrated)
- [Documentation](#documentation)

---

## The Problem

Banks and large organizations give certain employees "privileged access" — the ability to create users, change permissions, delete accounts, disable logging, and so on. This access is necessary for admins to do their jobs, but it's also the single biggest risk in the system: if that access is misused — by a malicious insider, a negligent employee, or an attacker who's stolen those credentials — the damage can be enormous, because the perpetrator is acting *as* a trusted identity, not breaking in from outside.

Traditional security tools (firewalls, intrusion detection) are built to catch outsiders crossing a boundary. They're mostly useless here, because there's no boundary being crossed — the "attacker" already has valid credentials and is doing things the system is designed to let them do.

Argus takes a different approach: not "block bad traffic," but **make power temporary, watch what power is used for, and respond fast when it looks wrong.**

## Design Philosophy

1. **Nobody should have standing power.** Access is requested, proven, and temporary — not permanently granted.
2. **Watch behavior, not single events.** One action can be innocent; a sequence of specific actions in a short window is often not.
3. **Explain findings in plain language.** A raw risk score means nothing to a human who has to decide what to do next.
4. **Respond automatically for the worst cases.** Waiting for a human to notice and act gives an attacker more time to do damage.

## Features

- Just-In-Time privileged access (MFA-gated, 1-hour STS sessions)
- Continuous IAM activity monitoring via CloudTrail + GuardDuty
- Rolling 10-minute behavioral correlation across IAM activities
- Identity-aware, policy-specific risk scoring
- Risk-based severity classification (Low / Medium / High / Critical)
- Automatic incident creation and audit trail
- Forensic evidence collection to S3
- SNS alerting with plain-language explanations
- Automated emergency role lockdown on Critical findings

## Architecture

![Project Argus Architecture](diagrams/architecture.png)

### Architecture Overview

```
Admin User → MFA + AWS STS → PrivilegedAdminRole (1hr session, JIT)
                    │
                    ▼
          ArgusAdminServer (EC2, private subnet, no IGW, SSM only)
                    │
     ┌──────────────┴──────────────┐
     ▼                              ▼
 AWS CloudTrail                Amazon GuardDuty
     │                              │
     └──────────────┬───────────────┘
                     ▼
            Amazon EventBridge (3 rules)
                     │
                     ▼
          RiskEngine (Lambda, Python)
   ┌─────────────────┼─────────────────┐
   ▼                 ▼                 ▼
DynamoDB          S3 Evidence       SNS Alert
(rolling window   (JSON per       (email/SMS to
 + incidents)      incident)      security team)
                     │
                     ▼
        Critical? → EmergencyDenyAllPolicy
           attached to the ROLE (not the user)
```

## How It Works

1. **Identity** — `admin-test-user` has zero standing permissions. To do anything privileged, it must explicitly assume `PrivilegedAdminRole` via AWS STS. The role's trust policy requires MFA, and sessions are capped at 1 hour.

2. **Private network** — The admin server sits in a VPC with **no Internet Gateway**, reachable only via AWS Systems Manager Session Manager (no SSH, no SSH keys, every command logged). VPC Endpoints give it precise, named access to exactly the services it needs (SSM, KMS, Secrets Manager, S3, DynamoDB, CloudWatch).

3. **Detection** — CloudTrail Management Events record privileged IAM API activity; GuardDuty applies AWS's ML models to catch anomalies CloudTrail rules alone wouldn't flag. EventBridge routes both into a single Lambda via three separate rules (IAM actions, CloudTrail tampering, GuardDuty findings).

4. **Risk Engine (`RiskEngine` Lambda)** — On every triggered event, it:
   - Resolves the acting identity (including assumed-role sessions) back to a consistent name
   - Scores the specific action (e.g. `AttachUserPolicy(AdministratorAccess)` = 95, `AttachUserPolicy(ReadOnlyAccess)` = 10)
   - Correlates all activity by that identity in the last **10 minutes**, not just the triggering event
   - Classifies severity: Low / Medium / High / Critical
   - Generates a deterministic, plain-language explanation (no external AI call — one less dependency that can fail)
   - On **Critical**, automatically attaches `EmergencyDenyAllPolicy` to the **role** (not the user) — because once a role is assumed, permissions are evaluated against the role's policies, so denying the user would silently do nothing to an already-active session. The deny policy propagates within seconds, rapidly cutting off further privileged operations without waiting for the session to expire on its own.

5. **Storage & evidence** — A rolling-window DynamoDB table (TTL: 1 day) for correlation, a permanent `Incidents` table for audit history, and every High/Critical incident written as JSON to S3. An SNS alert notifies the security team immediately.

6. **Observability** — A CloudWatch dashboard surfaces incidents, invocation counts, and errors at a glance.

## Example: What Triggers a Critical Alert

```
CreateUser (score 20) → AttachUserPolicy:AdministratorAccess (score 95) → DeleteUser (score 80)
```

All three within a 10-minute window from the same identity → cumulative score crosses the Critical threshold → the emergency deny policy is attached to the role, rapidly cutting off further privileged operations once it propagates, evidence is saved, and the security team is emailed within seconds.

This exact scenario was run live against the deployed system — see the incident walkthrough in the full documentation.

## Why It's Built This Way

- **Serverless throughout** (Lambda, DynamoDB on-demand, EventBridge) — you only pay when something actually happens, matching how unpredictable privileged-access events are.
- **Single region** — IAM is a global service whose events route through one region internally; staying in that region avoids cross-region complexity.
- **Deterministic explanations, not an external AI call** — removes a dependency that can fail for reasons outside your control, while still giving readable, specific explanations instead of raw scores.
- **Deny the role, not the user** — the decision most people get wrong, and the one most worth explaining precisely (see full docs).

## AWS Services Used

### Detection
- AWS CloudTrail
- Amazon GuardDuty
- Amazon EventBridge

### Compute
- AWS Lambda

### Storage
- Amazon DynamoDB
- Amazon S3

### Notification
- Amazon SNS

### Monitoring
- Amazon CloudWatch

### Identity
- AWS IAM
- AWS STS

### Infrastructure
- Amazon VPC Endpoints
- AWS Systems Manager

## Repository Structure

```text
Project-Argus/
│
├── README.md
├── LICENSE
├── lambda/
│   └── risk_engine.py
├── documentation/       # Full technical write-up
├── diagrams/            # Architecture diagram(s)
├── screenshots/         # Console evidence (IAM, CloudTrail, DynamoDB, SNS, etc.)
├── iam/                 # Role and policy definitions
└── eventbridge/         # Event pattern rules
```

## Skills Demonstrated

- AWS IAM & STS
- Privileged Access Management (PAM)
- Event-Driven Architecture
- AWS Lambda (Python)
- Security Automation
- Incident Response
- Behavioral Risk Scoring
- CloudTrail & GuardDuty Integration
- DynamoDB Data Modeling
- Infrastructure Hardening

## Documentation

Full technical documentation — including the architecture diagram and a screenshot-by-screenshot live incident walkthrough — is included in this repo under `documentation/`.

---

**Project Argus demonstrates a practical implementation of privileged access monitoring, insider threat detection, event correlation, and automated incident response using AWS serverless services. It was developed as a cloud security portfolio project to showcase secure architecture design, IAM governance, and security automation.**
