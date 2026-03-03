# LEAN INCIDENT RESPONSE PLAN

### A Practical Security Playbook for Startups

**Version 1.0  |  Confidential  |  2025**

Prepared by: Security Operations Team Reviewed by: CTO / Head of Engineering Next Review Date: Q4 2026

This document is intended for internal use. It defines the protocols, responsibilities, and communication flows your team should follow in the event of a cybersecurity incident. Review it. Practice it. Update it often.

# 1. Introduction

Startups operate in a high-trust, fast-paced environment where security is often reactive rather than proactive. A single data breach, credential compromise, or ransomware event can stall product development, erode customer confidence, and attract regulatory scrutiny at the worst possible time.

This Lean Incident Response Plan (IRP) is designed for early-to-mid stage startups with limited dedicated security headcount. It gives your team a repeatable, low-friction framework to detect, contain, and recover from security incidents, without requiring a 20-person SOC team or enterprise-grade tooling.

## What Makes This "Lean"?

A lean IRP strips away bureaucratic overhead and focuses on three things: clear ownership, fast communication, and documented action. It assumes your team is small, your tools are modern (Slack/Teams, cloud-native infrastructure), and your window for decision-making is narrow.

## 1.1 Scope and Applicability

This plan applies to all employees, contractors, and third-party vendors with access to company systems, data, or infrastructure. It covers incidents involving:

- Unauthorized access to internal systems, cloud accounts, or customer data
- Malware, ransomware, or destructive code execution
- Business Email Compromise (BEC) and phishing attacks
- Credential theft or identity-based attacks
- Data exfiltration, leakage, or loss
- Denial-of-service attacks affecting product availability
- Insider threats and unauthorized privilege escalation

## 1.2 Plan Objectives

- Minimize the time between detection and containment
- Ensure every team member knows their role before an incident occurs
- Maintain clear, consistent communication with internal stakeholders and customers
- Preserve forensic evidence to support post-incident analysis
- Drive continuous improvement through structured post-mortems

# 2. Incident Severity Levels

LEVEL | SEVERITY | RESPONSE SLA | DESCRIPTION | EXAMPLE SCENARIOS
--- | --- | --- | --- | ---
SEV-1 | CRITICAL | Immediate (< 15 min) | Active breach with confirmed data loss or system compromise. Business operations severely impacted. | Ransomware active in production, customer PII exfiltrated, cloud root account compromised
SEV-2 | HIGH | < 1 Hour | Credible threat with high probability of impact. No confirmed data loss yet but exposure is likely. | Credential stuffing attack underway, suspicious admin login from foreign IP, phishing campaign targeting employees
SEV-3 | MEDIUM | < 4 Hours | Isolated event with limited business impact. Requires investigation but no immediate containment needed. | Single employee account locked out after failed logins, misconfigured S3 bucket (no data accessed), unusual API call volume
SEV-4 | LOW | < 24 Hours | Low-risk events, policy violations, or informational alerts requiring documentation and monitoring. | Spam email reported, minor policy violation, routine vulnerability scan alert with no active exploit

## Important Note on Escalation

Severity should be re-assessed as new information emerges. A SEV-3 can escalate to SEV-1 within minutes if evidence of lateral movement or data exfiltration is confirmed. Always err on the side of escalating up, then downgrading if the threat proves less serious.

## 2.1 Severity Escalation Triggers

- Evidence of lateral movement across multiple systems or accounts
- Confirmed or suspected access to customer PII, PCI, or HIPAA-regulated data
- Attacker maintains persistence despite initial containment attempts
- A second incident is discovered during investigation of the first
- External parties (customers, journalists, regulators) report the incident before internal detection

# 3. Slack / Teams Reporting Flow

## 3.1 Channel Structure

Channel | Purpose | Access
--- | --- | ---
#security-alerts | Automated alerts from tooling | Engineering + Security
#security-incidents | Active incident coordination | Incident Response Team only
#security-exec-bridge | Executive briefings | C-Suite + IR Lead
#security-postmortems | Post-mortem documentation | All Engineering

## 3.2 Initial Alert Format

🚨 INCIDENT REPORT

SEVERITY: [ SEV-1 | SEV-2 | SEV-3 | SEV-4 ]
TIME: [UTC timestamp]
REPORTER: [Your name and role]
SYSTEM: [Affected system]
SUMMARY: [2-3 sentence description]
INDICATORS: [IOCs]
ACTION TAKEN: [Steps already taken]
IC ASSIGNED: [Incident Commander]

# 4. Role-Based Responsibilities

## Incident Commander

- Declares the incident and assigns the severity level
- Owns command channel decisions
- Coordinates response work
- Provides 30-minute updates
- Decides when incident is closed
- Ensures all actions are logged

## Technical Responder

- Executes containment and eradication
- Investigates logs and alerts
- Preserves evidence
- Tests fixes in staging
- Documents actions

## Communications Lead

- Drafts external communications
- Coordinates with Legal
- Monitors public channels
- Updates status page
- Prevents unauthorized statements

## Executive Sponsor

- Makes business risk decisions
- Approves emergency spending
- Communicates with board
- Approves disclosures
- Participates in post-incident review

Lean Incident Response Plan | Confidential | v1.0
