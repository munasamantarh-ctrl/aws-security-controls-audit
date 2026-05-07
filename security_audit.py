import boto3
import json
from datetime import datetime

def run_security_audit():
    report = {
        "audit_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "findings": []
    }
    
    # Check S3 Buckets
    s3 = boto3.client('s3')
    buckets = s3.list_buckets()['Buckets']
    for bucket in buckets:
        try:
            acl = s3.get_bucket_acl(Bucket=bucket['Name'])
            for grant in acl['Grants']:
                if 'AllUsers' in str(grant):
                    report["findings"].append({
                        "severity": "HIGH",
                        "resource": f"S3 Bucket: {bucket['Name']}",
                        "issue": "Bucket is publicly accessible",
                        "recommendation": "Restrict bucket access to authorized users only"
                    })
        except:
            pass

    # Check IAM Password Policy
    iam = boto3.client('iam')
    try:
        policy = iam.get_account_password_policy()['PasswordPolicy']
        if not policy.get('RequireUppercaseCharacters'):
            report["findings"].append({
                "severity": "MEDIUM",
                "resource": "IAM Password Policy",
                "issue": "Uppercase characters not required",
                "recommendation": "Enable uppercase character requirement"
            })
        if not policy.get('RequireNumbers'):
            report["findings"].append({
                "severity": "MEDIUM", 
                "resource": "IAM Password Policy",
                "issue": "Numbers not required in passwords",
                "recommendation": "Enable number requirement in password policy"
            })
        if not policy.get('RequireSymbols'):
            report["findings"].append({
                "severity": "MEDIUM",
                "resource": "IAM Password Policy", 
                "issue": "Symbols not required in passwords",
                "recommendation": "Enable symbol requirement in password policy"
            })
    except:
        report["findings"].append({
            "severity": "HIGH",
            "resource": "IAM Password Policy",
            "issue": "No password policy configured",
            "recommendation": "Configure a strong password policy immediately"
        })

    # Check MFA on root account
    try:
        summary = iam.get_account_summary()['SummaryMap']
        if summary.get('AccountMFAEnabled', 0) == 0:
            report["findings"].append({
                "severity": "CRITICAL",
                "resource": "Root Account",
                "issue": "MFA not enabled on root account",
                "recommendation": "Enable MFA on root account immediately"
            })
    except:
        pass

    # Print report
    print("\n" + "="*60)
    print("AUTOMATED SECURITY CONTROLS AUDIT REPORT")
    print("="*60)
    print(f"Date: {report['audit_date']}")
    print(f"Total Findings: {len(report['findings'])}")
    print("="*60)
    
    for i, finding in enumerate(report['findings'], 1):
        print(f"\nFinding #{i}")
        print(f"Severity: {finding['severity']}")
        print(f"Resource: {finding['resource']}")
        print(f"Issue: {finding['issue']}")
        print(f"Recommendation: {finding['recommendation']}")
    
    if not report['findings']:
        print("\nNo issues found! All controls passed.")
    
    print("\n" + "="*60)
    
    # Save to file
    with open('audit_report.json', 'w') as f:
        json.dump(report, f, indent=2)
    print("Report saved to audit_report.json")

run_security_audit()
