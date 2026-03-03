# Cloud Security Baseline Policy

**Document Owner:** Security Team\
**Version:** 1.0\
**Effective Date:** 2026-03-03\
**Review Cycle:** Annual

------------------------------------------------------------------------

## 1. Purpose

This document defines the minimum mandatory security controls required
for all cloud environments. The objective is to ensure confidentiality,
integrity, and availability of organizational systems and data.

This baseline applies to cloud environments hosted in:

-   Amazon Web Services\
-   Microsoft Azure\
-   Google Cloud Platform

These controls are mandatory unless formally exempted through documented
risk acceptance.

------------------------------------------------------------------------

## 2. Scope

This policy applies to:

-   Production and non-production cloud environments\
-   All employees, contractors, and third parties with access\
-   Infrastructure-as-a-Service (IaaS)\
-   Platform-as-a-Service (PaaS)\
-   Software-as-a-Service (SaaS)\
-   Cloud-hosted data and identity systems

------------------------------------------------------------------------

## 3. Governance Structure

  Role                Responsibility
  ------------------- ---------------------------------------------------
  Security Team       Defines baseline controls and monitors compliance
  Cloud Engineering   Implements required configurations
  DevOps Teams        Enforces secure deployment practices
  Compliance          Conducts control validation and audits
  Executive Sponsor   Approves risk exceptions

------------------------------------------------------------------------

## 4. Multi-Factor Authentication (MFA) Enforcement

### 4.1 Requirements

1.  MFA must be enabled for:
    -   All human users\
    -   All privileged accounts\
    -   All remote access sessions\
    -   All cloud console access
2.  Root or tenant-level accounts:
    -   Must have MFA enabled\
    -   Must not be used for daily operations
3.  Authentication methods must support:
    -   Time-based one-time passwords (TOTP)\
    -   Hardware security keys (preferred)
4.  Conditional access must enforce:
    -   Device compliance\
    -   Geographic restrictions where applicable\
    -   Risk-based authentication policies

### 4.2 Prohibited

-   Shared accounts without MFA\
-   MFA bypass for convenience\
-   Interactive login for service accounts

------------------------------------------------------------------------

## 5. Identity and Access Management (IAM) -- Least Privilege

### 5.1 Principle

Access must follow the principle of least privilege. Users and services
receive only the minimum permissions required.

### 5.2 Requirements

1.  Role-Based Access Control (RBAC) must be implemented.

2.  High-privilege roles must be:

    -   Just-in-time (JIT) where supported\
    -   Time-bound\
    -   Approval-based

3.  Privileged accounts must:

    -   Be reviewed monthly\
    -   Require documented business justification

4.  Standard user access must be reviewed quarterly.

5.  Service accounts must:

    -   Use scoped permissions\
    -   Avoid wildcard (\*) permissions\
    -   Be non-interactive

6.  Separation of duties must be enforced between:

    -   Development and production\
    -   Security administration and system ownership

### 5.3 Access Review Requirements

  Access Type        Review Frequency
  ------------------ ------------------
  Standard Users     Quarterly
  Privileged Users   Monthly
  Service Accounts   Quarterly

------------------------------------------------------------------------

## 6. Logging and Monitoring

### 6.1 Mandatory Logging

The following logs must be enabled:

-   Authentication logs\
-   Administrative activity logs\
-   API activity logs\
-   Network flow logs\
-   Storage access logs\
-   Configuration change logs

Cloud-native logging must be enabled.

### 6.2 Log Retention

-   Minimum retention: 365 days\
-   Logs must be immutable where supported\
-   Logs must be centrally aggregated\
-   Logs must be encrypted at rest and in transit

### 6.3 Alerting Requirements

Real-time alerts must be configured for:

-   Failed administrative logins\
-   Root account usage\
-   Privilege escalation\
-   IAM policy changes\
-   Public exposure of storage\
-   Security group rule modifications\
-   Backup deletion attempts

### 6.4 Centralized Monitoring Architecture

All logs must flow into a centralized SIEM platform.

**Logging Flow Overview:**\
Cloud Account → Native Logging Service → Central Log Storage → SIEM →
Alerting System → Security Operations

------------------------------------------------------------------------

## 7. Backup and Recovery Requirements

### 7.1 Backup Scope

All production systems must have automated backups enabled, including:

-   Databases\
-   Object storage\
-   Virtual machines\
-   Configuration states\
-   Encryption key configurations

### 7.2 Backup Strategy

Backups must follow the 3-2-1 principle:

-   3 copies of data\
-   2 different storage types\
-   1 copy offsite or cross-region

### 7.3 Backup Frequency

  System Type             Minimum Backup Frequency
  ----------------------- --------------------------
  Critical Systems        Daily
  High-Change Databases   Hourly or Continuous
  Configuration           After major change

### 7.4 Backup Protection

-   Encrypted at rest and in transit\
-   Separate administrative boundary\
-   Deletion protection enabled\
-   Backup deletion must be logged and alerted

### 7.5 Recovery Testing

-   Restore testing must occur twice per year\
-   RTO and RPO must be documented\
-   Failed restore tests require remediation plan

------------------------------------------------------------------------

## 8. Secrets Management

### 8.1 Definition

Secrets include:

-   API keys\
-   Credentials\
-   Encryption keys\
-   Certificates\
-   Tokens

### 8.2 Storage Requirements

Secrets must not be stored in:

-   Source code\
-   Plaintext configuration files\
-   Infrastructure-as-Code templates\
-   CI/CD pipeline variables without encryption

### 8.3 Controls

1.  Secrets must be encrypted using strong cryptography.\
2.  Access must follow least privilege.\
3.  Secrets must be rotated:
    -   Every 90 days minimum\
    -   Immediately upon suspected compromise\
4.  Applications must retrieve secrets dynamically at runtime.

------------------------------------------------------------------------

## 9. Encryption Requirements

### 9.1 Data at Rest

-   All storage must use encryption by default.\
-   Customer-managed keys are preferred for sensitive data.

### 9.2 Data in Transit

-   TLS 1.2 or higher required.\
-   Internal service-to-service traffic must be encrypted.

------------------------------------------------------------------------

## 10. Compliance Mapping

  Control Area         NIST CSF   ISO 27001 Annex A
  -------------------- ---------- -------------------
  MFA                  PR.AC-7    A.9.4.2
  Least Privilege      PR.AC-4    A.9.1.2
  Logging              DE.CM-1    A.12.4.1
  Backup               PR.IP-4    A.12.3.1
  Secrets Management   PR.DS-1    A.10.1.1

------------------------------------------------------------------------

## 11. Risk Exceptions

All deviations must:

-   Be documented\
-   Include risk justification\
-   Be approved by executive sponsor\
-   Have expiration date\
-   Be reviewed annually

------------------------------------------------------------------------

## 12. Enforcement

Non-compliance may result in:

-   Access revocation\
-   Deployment blocking\
-   Security incident escalation\
-   Formal disciplinary action

Automated compliance scanning is required wherever possible.

------------------------------------------------------------------------

## 13. Revision History

  Version   Date         Author          Description
  --------- ------------ --------------- -----------------
  1.0       2026-03-03   Security Team   Initial Release

------------------------------------------------------------------------

## Appendix A -- Control Validation Checklist

  Control                              Verified   Notes
  ------------------------------------ ---------- -------
  MFA enforced for all users           ☐          
  Root account MFA enabled             ☐          
  Least privilege enforced             ☐          
  Privileged access reviewed monthly   ☐          
  Logging enabled across accounts      ☐          
  Log retention ≥ 365 days             ☐          
  Backup automation enabled            ☐          
  Restore testing performed            ☐          
  Secrets centralized                  ☐          
  Secrets rotated                      ☐          

------------------------------------------------------------------------

## Document Classification

Internal Use Only
