# AWS IAM Security Analyzer

> A comprehensive security analysis tool for AWS IAM configurations, detecting misconfigurations and privilege escalation paths.

Part of the **AWS Security Mastery** series by an AWS Community Builder.

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![AWS](https://img.shields.io/badge/AWS-IAM-orange.svg)](https://aws.amazon.com/iam/)

## 🎯 Overview

This tool performs comprehensive security analysis of AWS IAM configurations to identify:

- 🔴 **Critical**: Root account access keys, privilege escalation paths
- 🟠 **High**: Missing MFA, overly permissive policies
- 🟡 **Medium**: Unused credentials, wildcard usage
- 🟢 **Low**: Best practice violations

## 🚀 Features

### Security Checks

1. **Root Account Security**
   - Detects root account access keys
   - Validates root account MFA

2. **MFA Configuration**
   - Identifies users with console access but no MFA
   - Flags high-privilege accounts without MFA

3. **Credential Hygiene**
   - Finds unused credentials (default: 90+ days)
   - Identifies keys that have never been used

4. **Privilege Escalation Detection**
   - Scans for 11 common privilege escalation paths
   - Checks both users and roles
   - Detects dangerous permission combinations:
     - `iam:CreatePolicy` + `iam:AttachUserPolicy`
     - `iam:PassRole` + `lambda:CreateFunction`
     - `iam:UpdateAssumeRolePolicy` + `sts:AssumeRole`
     - And 8 more...

5. **Policy Analysis**
   - Identifies admin access patterns
   - Flags wildcard usage in actions/resources
   - Reviews custom policies for best practices

## 📋 Prerequisites

- Python 3.8 or higher
- AWS CLI configured with credentials
- IAM permissions to read IAM configurations:
  ```json
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": [
          "iam:Get*",
          "iam:List*",
          "sts:GetCallerIdentity"
        ],
        "Resource": "*"
      }
    ]
  }
  ```

## 🔧 Installation

### Option 1: Clone the Repository

```bash
git clone https://github.com/yourusername/aws-iam-security-analyzer.git
cd aws-iam-security-analyzer
pip install -r requirements.txt
```

### Option 2: Direct Script Usage

```bash
wget https://raw.githubusercontent.com/yourusername/aws-iam-security-analyzer/main/iam_analyzer.py
pip install boto3
python3 iam_analyzer.py
```

## 💻 Usage

### Basic Scan

```bash
python3 iam_analyzer.py
```

### Using Specific AWS Profile

```bash
python3 iam_analyzer.py --profile production
```

### Specify Region

```bash
python3 iam_analyzer.py --region us-west-2
```

### Save Results to JSON

```bash
python3 iam_analyzer.py --output results.json
```

### Combined Options

```bash
python3 iam_analyzer.py --profile prod --region eu-west-1 --output audit-2024.json
```

## 📊 Sample Output

```
🔍 Starting IAM Security Analysis...

Running: Root Account Keys...
Running: MFA Configuration...
Running: Unused Credentials...
Running: Privilege Escalation Paths...
Running: Overly Permissive Policies...

======================================================================
IAM SECURITY ANALYSIS RESULTS
======================================================================

📋 Account: 123456789012
👤 User: arn:aws:iam::123456789012:user/security-auditor
⏰ Scan Time: 2024-12-15T10:30:00

📊 Total Findings: 12
   🔴 Critical: 3
   🟠 High: 4
   🟡 Medium: 3
   🟢 Low: 2

──────────────────────────────────────────────────────────────────────
🔎 PRIVILEGE ESCALATION
──────────────────────────────────────────────────────────────────────

🔴 Finding #1 [CRITICAL]
   Issue: Privilege escalation path detected for user dev-admin
   Description: Path: pass_role_lambda - Permissions: iam:PassRole, lambda:CreateFunction, lambda:InvokeFunction
   Remediation: Remove dangerous permission combinations
```

## 🏗️ Project Structure

```
aws-iam-security-analyzer/
├── iam_analyzer.py          # Main analyzer script
├── requirements.txt         # Python dependencies
├── README.md               # This file
├── LICENSE                 # MIT License
├── examples/
│   ├── vulnerable-policies/    # Example vulnerable IAM policies
│   ├── secure-policies/        # Example secure IAM policies
│   └── sample-output.json      # Sample scan output
├── labs/
│   ├── lab1-setup.md          # Lab: Setting up vulnerable environment
│   ├── lab2-detection.md      # Lab: Detecting vulnerabilities
│   └── lab3-remediation.md    # Lab: Fixing issues
└── docs/
    ├── privilege-escalation.md # Detailed escalation path documentation
    └── best-practices.md       # IAM security best practices
```

## 🎓 Learning Labs

### Lab 1: Setting Up a Vulnerable Environment
Create intentionally misconfigured IAM resources to practice detection.

### Lab 2: Running Security Analysis
Use the analyzer to identify vulnerabilities you created.

### Lab 3: Remediation
Fix the identified issues following AWS best practices.

[View detailed labs in the `/labs` directory]

## 🔍 Detected Privilege Escalation Paths

| Path Name | Required Permissions | Risk Level |
|-----------|---------------------|------------|
| `create_policy_attach` | `iam:CreatePolicy`, `iam:AttachUserPolicy` | Critical |
| `put_user_policy` | `iam:PutUserPolicy` | Critical |
| `pass_role_lambda` | `iam:PassRole`, `lambda:CreateFunction`, `lambda:InvokeFunction` | Critical |
| `pass_role_ec2` | `iam:PassRole`, `ec2:RunInstances` | High |
| `update_assume_role` | `iam:UpdateAssumeRolePolicy`, `sts:AssumeRole` | Critical |
| `create_access_key` | `iam:CreateAccessKey` | High |
| `add_user_to_group` | `iam:AddUserToGroup` | Medium |

[View full documentation](docs/privilege-escalation.md)

## 🛡️ Remediation Guidance

### Critical Findings

**Root Access Keys Detected**
```bash
# Delete root access keys immediately
aws iam delete-access-key --access-key-id AKIAIOSFODNN7EXAMPLE
```

**Privilege Escalation Path**
```bash
# Review and remove dangerous permissions
aws iam detach-user-policy --user-name vulnerable-user --policy-arn arn:aws:iam::aws:policy/IAMFullAccess
```

### High Findings

**Missing MFA**
```bash
# Enable virtual MFA device
aws iam create-virtual-mfa-device --virtual-mfa-device-name user-mfa
aws iam enable-mfa-device --user-name username --serial-number arn:aws:iam::123456789012:mfa/user-mfa
```

## 🔗 Related Resources

- 📝 [Medium Article: AWS IAM Security - Beyond the Basics](your-medium-link)
- 📚 [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- 🔧 [IAM Policy Simulator](https://policysim.aws.amazon.com/)
- 🎯 [AWS Security Hub](https://aws.amazon.com/security-hub/)

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes:

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 Roadmap

- [ ] Add support for AWS Organizations (SCPs analysis)
- [ ] Implement permission boundary detection
- [ ] Add cross-account trust analysis
- [ ] Generate remediation scripts automatically
- [ ] Create HTML report output
- [ ] Add integration with AWS Security Hub
- [ ] Support for batch account scanning

## ⚠️ Disclaimer

This tool is for security assessment and educational purposes. Always:
- Test in non-production environments first
- Ensure you have proper authorization
- Review findings with your security team
- Follow your organization's security policies

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👤 Author

**AWS Community Builder - Security Series**

- 📝 Medium: [Your Medium Profile]
- 💼 LinkedIn: [Your LinkedIn]
- 🐦 Twitter: [@YourHandle]
- 🌐 Website: [Your Website]

## 🙏 Acknowledgments

- AWS Security Team for comprehensive documentation
- The AWS Community Builders program
- Open source security tools that inspired this project:
  - [Prowler](https://github.com/prowler-cloud/prowler)
  - [ScoutSuite](https://github.com/nccgroup/ScoutSuite)
  - [Pacu](https://github.com/RhinoSecurityLabs/pacu)

## 📊 Star History

If you find this tool useful, please consider giving it a star! ⭐

---

**Next in the Series**: Session 2 - Building Your AWS Security Audit Pipeline

Stay tuned for more AWS security content!