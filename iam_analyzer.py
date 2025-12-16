#!/usr/bin/env python3
"""
AWS IAM Security Analyzer
Identifies common IAM misconfigurations and privilege escalation paths
Author: AWS Community Builder - Security Series
"""

import boto3
import json
from datetime import datetime, timezone
from typing import Dict, List, Tuple
import argparse

class IAMSecurityAnalyzer:
    """Analyzes AWS IAM configuration for security issues"""
    
    # Dangerous permission combinations for privilege escalation
    PRIV_ESC_PATTERNS = {
        'create_policy_attach': ['iam:CreatePolicy', 'iam:AttachUserPolicy'],
        'put_user_policy': ['iam:PutUserPolicy'],
        'put_role_policy': ['iam:PutRolePolicy'],
        'pass_role_lambda': ['iam:PassRole', 'lambda:CreateFunction', 'lambda:InvokeFunction'],
        'pass_role_ec2': ['iam:PassRole', 'ec2:RunInstances'],
        'update_assume_role': ['iam:UpdateAssumeRolePolicy', 'sts:AssumeRole'],
        'attach_role_policy': ['iam:AttachRolePolicy'],
        'create_access_key': ['iam:CreateAccessKey'],
        'create_login_profile': ['iam:CreateLoginProfile'],
        'update_login_profile': ['iam:UpdateLoginProfile'],
        'add_user_to_group': ['iam:AddUserToGroup']
    }
    
    def __init__(self, profile_name=None, region='us-east-1'):
        """Initialize AWS session"""
        session = boto3.Session(profile_name=profile_name, region_name=region)
        self.iam = session.client('iam')
        self.sts = session.client('sts')
        
    def get_account_info(self) -> Dict:
        """Get current AWS account information"""
        try:
            identity = self.sts.get_caller_identity()
            return {
                'account_id': identity['Account'],
                'user_arn': identity['Arn'],
                'user_id': identity['UserId']
            }
        except Exception as e:
            return {'error': str(e)}
    
    def check_root_account_keys(self) -> Dict:
        """Check if root account has access keys"""
        findings = []
        try:
            summary = self.iam.get_account_summary()
            root_keys = summary['SummaryMap'].get('AccountAccessKeysPresent', 0)
            
            if root_keys > 0:
                findings.append({
                    'severity': 'CRITICAL',
                    'issue': 'Root account has access keys',
                    'description': 'Root access keys should be deleted immediately',
                    'remediation': 'Delete root access keys and use IAM users instead'
                })
        except Exception as e:
            findings.append({'error': str(e)})
            
        return {'check': 'root_access_keys', 'findings': findings}
    
    def check_mfa_enabled(self) -> Dict:
        """Check MFA status for users"""
        findings = []
        try:
            users = self.iam.list_users()
            
            for user in users['Users']:
                username = user['UserName']
                mfa_devices = self.iam.list_mfa_devices(UserName=username)
                
                if len(mfa_devices['MFADevices']) == 0:
                    # Check if user has console access
                    try:
                        self.iam.get_login_profile(UserName=username)
                        findings.append({
                            'severity': 'HIGH',
                            'issue': f'User {username} has console access without MFA',
                            'description': 'Console access without MFA is a security risk',
                            'remediation': f'Enable MFA for user {username}'
                        })
                    except self.iam.exceptions.NoSuchEntityException:
                        pass  # No console access
                        
        except Exception as e:
            findings.append({'error': str(e)})
            
        return {'check': 'mfa_enabled', 'findings': findings}
    
    def check_unused_credentials(self, days=90) -> Dict:
        """Find credentials unused for specified days"""
        findings = []
        try:
            users = self.iam.list_users()
            current_time = datetime.now(timezone.utc)
            
            for user in users['Users']:
                username = user['UserName']
                
                # Check access keys
                keys = self.iam.list_access_keys(UserName=username)
                for key in keys['AccessKeyMetadata']:
                    last_used = self.iam.get_access_key_last_used(
                        AccessKeyId=key['AccessKeyId']
                    )
                    
                    last_used_date = last_used.get('AccessKeyLastUsed', {}).get('LastUsedDate')
                    
                    if last_used_date:
                        days_unused = (current_time - last_used_date).days
                        if days_unused > days:
                            findings.append({
                                'severity': 'MEDIUM',
                                'issue': f'Access key for {username} unused for {days_unused} days',
                                'description': f'Key ID: {key["AccessKeyId"]}',
                                'remediation': 'Rotate or delete unused access keys'
                            })
                    else:
                        findings.append({
                            'severity': 'LOW',
                            'issue': f'Access key for {username} never used',
                            'description': f'Key ID: {key["AccessKeyId"]}',
                            'remediation': 'Consider deleting unused keys'
                        })
                        
        except Exception as e:
            findings.append({'error': str(e)})
            
        return {'check': 'unused_credentials', 'findings': findings}
    
    def check_privilege_escalation(self) -> Dict:
        """Detect privilege escalation paths"""
        findings = []
        try:
            # Check users
            users = self.iam.list_users()
            for user in users['Users']:
                username = user['UserName']
                user_perms = self._get_user_permissions(username)
                escalation_paths = self._detect_escalation_paths(user_perms)
                
                for path_name, path_perms in escalation_paths:
                    findings.append({
                        'severity': 'CRITICAL',
                        'issue': f'Privilege escalation path detected for user {username}',
                        'description': f'Path: {path_name} - Permissions: {", ".join(path_perms)}',
                        'remediation': 'Remove dangerous permission combinations'
                    })
            
            # Check roles
            roles = self.iam.list_roles()
            for role in roles['Roles']:
                if role['Path'].startswith('/aws-service-role/'):
                    continue  # Skip service-linked roles
                    
                rolename = role['RoleName']
                role_perms = self._get_role_permissions(rolename)
                escalation_paths = self._detect_escalation_paths(role_perms)
                
                for path_name, path_perms in escalation_paths:
                    findings.append({
                        'severity': 'CRITICAL',
                        'issue': f'Privilege escalation path detected for role {rolename}',
                        'description': f'Path: {path_name} - Permissions: {", ".join(path_perms)}',
                        'remediation': 'Remove dangerous permission combinations'
                    })
                    
        except Exception as e:
            findings.append({'error': str(e)})
            
        return {'check': 'privilege_escalation', 'findings': findings}
    
    def check_overly_permissive_policies(self) -> Dict:
        """Find policies with wildcards or admin access"""
        findings = []
        try:
            policies = self.iam.list_policies(Scope='Local', MaxItems=1000)
            
            for policy in policies['Policies']:
                policy_name = policy['PolicyName']
                policy_arn = policy['Arn']
                
                # Get policy document
                version = self.iam.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=policy['DefaultVersionId']
                )
                
                doc = version['PolicyVersion']['Document']
                
                # Check for admin access
                if self._has_admin_access(doc):
                    findings.append({
                        'severity': 'HIGH',
                        'issue': f'Policy {policy_name} grants admin access',
                        'description': 'Policy allows Action: * on Resource: *',
                        'remediation': 'Apply principle of least privilege'
                    })
                
                # Check for wildcards
                wildcards = self._check_wildcards(doc)
                if wildcards:
                    findings.append({
                        'severity': 'MEDIUM',
                        'issue': f'Policy {policy_name} uses wildcards',
                        'description': f'Wildcard usage: {", ".join(wildcards)}',
                        'remediation': 'Scope down permissions to specific resources/actions'
                    })
                    
        except Exception as e:
            findings.append({'error': str(e)})
            
        return {'check': 'overly_permissive_policies', 'findings': findings}
    
    def _get_user_permissions(self, username: str) -> List[str]:
        """Extract all permissions for a user"""
        permissions = set()
        
        # Inline policies
        inline = self.iam.list_user_policies(UserName=username)
        for policy_name in inline['PolicyNames']:
            policy = self.iam.get_user_policy(UserName=username, PolicyName=policy_name)
            permissions.update(self._extract_actions(policy['PolicyDocument']))
        
        # Attached policies
        attached = self.iam.list_attached_user_policies(UserName=username)
        for policy in attached['AttachedPolicies']:
            version = self.iam.get_policy_version(
                PolicyArn=policy['PolicyArn'],
                VersionId=self.iam.get_policy(PolicyArn=policy['PolicyArn'])['Policy']['DefaultVersionId']
            )
            permissions.update(self._extract_actions(version['PolicyVersion']['Document']))
        
        return list(permissions)
    
    def _get_role_permissions(self, rolename: str) -> List[str]:
        """Extract all permissions for a role"""
        permissions = set()
        
        # Inline policies
        inline = self.iam.list_role_policies(RoleName=rolename)
        for policy_name in inline['PolicyNames']:
            policy = self.iam.get_role_policy(RoleName=rolename, PolicyName=policy_name)
            permissions.update(self._extract_actions(policy['PolicyDocument']))
        
        # Attached policies
        attached = self.iam.list_attached_role_policies(RoleName=rolename)
        for policy in attached['AttachedPolicies']:
            version = self.iam.get_policy_version(
                PolicyArn=policy['PolicyArn'],
                VersionId=self.iam.get_policy(PolicyArn=policy['PolicyArn'])['Policy']['DefaultVersionId']
            )
            permissions.update(self._extract_actions(version['PolicyVersion']['Document']))
        
        return list(permissions)
    
    def _extract_actions(self, policy_doc: Dict) -> set:
        """Extract actions from policy document"""
        actions = set()
        statements = policy_doc.get('Statement', [])
        
        if isinstance(statements, dict):
            statements = [statements]
        
        for statement in statements:
            if statement.get('Effect') == 'Allow':
                action = statement.get('Action', [])
                if isinstance(action, str):
                    action = [action]
                actions.update(action)
        
        return actions
    
    def _detect_escalation_paths(self, permissions: List[str]) -> List[Tuple[str, List[str]]]:
        """Detect privilege escalation paths in permissions"""
        found_paths = []
        
        # Normalize permissions to lowercase for comparison
        perms_lower = {p.lower() for p in permissions}
        
        # Add wildcard check
        if '*' in permissions or 'iam:*' in perms_lower:
            found_paths.append(('wildcard_admin', ['*']))
        
        for path_name, required_perms in self.PRIV_ESC_PATTERNS.items():
            required_lower = {p.lower() for p in required_perms}
            
            # Check if all required permissions exist
            if required_lower.issubset(perms_lower):
                found_paths.append((path_name, required_perms))
        
        return found_paths
    
    def _has_admin_access(self, policy_doc: Dict) -> bool:
        """Check if policy grants admin access"""
        statements = policy_doc.get('Statement', [])
        
        if isinstance(statements, dict):
            statements = [statements]
        
        for statement in statements:
            if statement.get('Effect') == 'Allow':
                action = statement.get('Action', [])
                resource = statement.get('Resource', [])
                
                if isinstance(action, str):
                    action = [action]
                if isinstance(resource, str):
                    resource = [resource]
                
                if '*' in action and '*' in resource:
                    return True
        
        return False
    
    def _check_wildcards(self, policy_doc: Dict) -> List[str]:
        """Check for wildcard usage in policy"""
        wildcards = []
        statements = policy_doc.get('Statement', [])
        
        if isinstance(statements, dict):
            statements = [statements]
        
        for statement in statements:
            if statement.get('Effect') == 'Allow':
                action = statement.get('Action', [])
                resource = statement.get('Resource', [])
                
                if isinstance(action, str):
                    action = [action]
                if isinstance(resource, str):
                    resource = [resource]
                
                if '*' in action:
                    wildcards.append('Action: *')
                if '*' in resource:
                    wildcards.append('Resource: *')
                    
                for act in action:
                    if '*' in act and act != '*':
                        wildcards.append(f'Action: {act}')
        
        return list(set(wildcards))
    
    def run_all_checks(self) -> Dict:
        """Run all security checks"""
        print("🔍 Starting IAM Security Analysis...\n")
        
        results = {
            'account_info': self.get_account_info(),
            'timestamp': datetime.now().isoformat(),
            'checks': []
        }
        
        checks = [
            ('Root Account Keys', self.check_root_account_keys),
            ('MFA Configuration', self.check_mfa_enabled),
            ('Unused Credentials', self.check_unused_credentials),
            ('Privilege Escalation Paths', self.check_privilege_escalation),
            ('Overly Permissive Policies', self.check_overly_permissive_policies)
        ]
        
        for check_name, check_func in checks:
            print(f"Running: {check_name}...")
            result = check_func()
            results['checks'].append(result)
        
        return results
    
    def print_results(self, results: Dict):
        """Pretty print results"""
        print("\n" + "="*70)
        print("IAM SECURITY ANALYSIS RESULTS")
        print("="*70)
        
        # Account info
        info = results['account_info']
        print(f"\n📋 Account: {info.get('account_id', 'Unknown')}")
        print(f"👤 User: {info.get('user_arn', 'Unknown')}")
        print(f"⏰ Scan Time: {results['timestamp']}\n")
        
        # Count findings by severity
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        total_findings = 0
        
        for check in results['checks']:
            for finding in check.get('findings', []):
                if 'severity' in finding:
                    severity_counts[finding['severity']] += 1
                    total_findings += 1
        
        print(f"📊 Total Findings: {total_findings}")
        print(f"   🔴 Critical: {severity_counts['CRITICAL']}")
        print(f"   🟠 High: {severity_counts['HIGH']}")
        print(f"   🟡 Medium: {severity_counts['MEDIUM']}")
        print(f"   🟢 Low: {severity_counts['LOW']}\n")
        
        # Detailed findings
        for check in results['checks']:
            check_name = check.get('check', 'Unknown')
            findings = check.get('findings', [])
            
            if findings:
                print(f"\n{'─'*70}")
                print(f"🔎 {check_name.upper().replace('_', ' ')}")
                print(f"{'─'*70}")
                
                for i, finding in enumerate(findings, 1):
                    if 'error' in finding:
                        print(f"\n❌ Error: {finding['error']}")
                        continue
                    
                    severity_icons = {
                        'CRITICAL': '🔴',
                        'HIGH': '🟠',
                        'MEDIUM': '🟡',
                        'LOW': '🟢'
                    }
                    
                    icon = severity_icons.get(finding['severity'], '⚪')
                    print(f"\n{icon} Finding #{i} [{finding['severity']}]")
                    print(f"   Issue: {finding['issue']}")
                    print(f"   Description: {finding['description']}")
                    print(f"   Remediation: {finding['remediation']}")
        
        print("\n" + "="*70)
        print("Scan Complete!")
        print("="*70 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description='AWS IAM Security Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '--profile',
        help='AWS profile name',
        default=None
    )
    
    parser.add_argument(
        '--region',
        help='AWS region',
        default='us-east-1'
    )
    
    parser.add_argument(
        '--output',
        help='Output file for JSON results',
        default=None
    )
    
    args = parser.parse_args()
    
    try:
        analyzer = IAMSecurityAnalyzer(
            profile_name=args.profile,
            region=args.region
        )
        
        results = analyzer.run_all_checks()
        analyzer.print_results(results)
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            print(f"\n✅ Results saved to {args.output}")
            
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        return 1
    
    return 0


if __name__ == '__main__':
    exit(main())