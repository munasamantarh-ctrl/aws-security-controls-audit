# aws-security-controls-audit
# AWS Automated Security Controls Audit

## Overview
This project is an automated security controls testing script built in Python using AWS boto3. 
It simulates the type of "Audit-as-Code" work performed by cloud risk and controls testing teams.

## What It Does
Automatically audits three key AWS security controls:

1. **S3 Bucket Access** - Checks if any buckets are publicly accessible
2. **IAM Password Policy** - Validates password strength requirements
3. **MFA Configuration** - Verifies Multi-Factor Authentication is enabled on root account

## How It Works
- Connects to AWS using boto3
- Runs automated checks against each control area
- Assigns severity levels (CRITICAL, HIGH, MEDIUM)
- Generates recommendations for any gaps found
- Outputs a structured JSON report

## Sample Output



## Technologies Used
- Python
- AWS boto3
- AWS CloudShell
- IAM, S3, MFA controls
