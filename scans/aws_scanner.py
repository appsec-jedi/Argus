import boto3
import json
from botocore.exceptions import ClientError
from typing import List
from issues import Issue

class AWSScanner:
    """
    AWSScanner encapsulates S3 misconfiguration checks:
      - Public ACLs
      - Missing default encryption
      - Public Access Block settings
    """
    def __init__(self,
                 aws_key: str,
                 aws_secret: str):
        session = boto3.Session(
            aws_access_key_id=aws_key,
            aws_secret_access_key=aws_secret,
        )
        self.s3 = session.client("s3")

    def scan_s3_buckets(self) -> List[Issue]:
        """
        Scan all S3 buckets and return a list of Issues for any misconfigurations found.
        """
        issues: List[Issue] = []
        buckets = self.s3.list_buckets().get("Buckets", [])
        print("Buckets found:")
        for b in buckets:
            name = b["Name"]
            print(f"\t• {name}")

            # 1) Check for public ACLs
            try:
                acl = self.s3.get_bucket_acl(Bucket=name)
                for grant in acl.get("Grants", []):
                    grantee = grant.get("Grantee", {})
                    uri = grantee.get("URI", "")
                    if uri in [
                        "http://acs.amazonaws.com/groups/global/AllUsers",
                        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
                    ]:
                        print("FOUND AN ISSUE")
                        issues.append(
                            Issue(
                                id="S3_PUBLIC_BUCKET",
                                resource=name,
                                description="Bucket has a public ACL allowing global access.",
                                severity="HIGH"
                            )
                        )
            except ClientError:
                # Skip buckets that return an error
                pass

            # 2) Check for default encryption
            try:
                self.s3.get_bucket_encryption(Bucket=name)
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code", "")
                if code == "ServerSideEncryptionConfigurationNotFoundError":
                    issues.append(
                        Issue(
                            id="S3_UNENCRYPTED_BUCKET",
                            resource=name,
                            description="Bucket does not have default encryption enabled.",
                            severity="MEDIUM"
                        )
                    )

            # 3) Check Public Access Block settings
            try:
                pab = self.s3.get_public_access_block(Bucket=name)
                config = pab.get("PublicAccessBlockConfiguration", {})
                # Ensure all flags are True
                required_flags = ["BlockPublicAcls", "IgnorePublicAcls",
                                  "BlockPublicPolicy", "RestrictPublicBuckets"]
                if not all(config.get(flag, False) for flag in required_flags):
                    issues.append(
                        Issue(
                            id="S3_PUBLIC_ACCESS_BLOCK",
                            resource=name,
                            description="Public Access Block is not fully enabled.",
                            severity="MEDIUM"
                        )
                    )
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code", "")
                if code == "NoSuchPublicAccessBlockConfiguration":
                    issues.append(
                        Issue(
                            id="S3_PUBLIC_ACCESS_BLOCK",
                            resource=name,
                            description="No Public Access Block configuration found.",
                            severity="MEDIUM"
                        )
                    )
            
            # 4. Detect any bucket policy statements that allow '*' (everyone).
            try:
                raw = self.s3.get_bucket_policy(Bucket=name)['Policy']
                policy = json.loads(raw)
                for stmt in policy.get('Statement', []):
                    principal = stmt.get('Principal')
                    effect    = stmt.get('Effect')
                    # Catch Allow to everyone
                    if effect == 'Allow' and (principal == '*' or principal.get('AWS') == '*'):
                        issues.append(
                            Issue(
                                id="S3_PUBLIC_BUCKET_POLICY",
                                resource=name,
                                description="Bucket policy allows public access (Principal: *).",
                                severity="HIGH"
                            )
                        )
            except ClientError as e:
                # No policy or access denied 
                code = e.response.get("Error", {}).get("Code", "")
                # If no policy is found - skip and continue checks
                if code == "NoSuchBucketPolicy":
                    pass
            
                

            # 5) Check server access logging
            try:
                log_conf = self.s3.get_bucket_logging(Bucket=name)
                if not log_conf.get("LoggingEnabled") or not log_conf["LoggingEnabled"].get("TargetBucket"):
                    issues.append(
                        Issue(
                            id="S3_SERVER_ACCESS_LOGGING",
                            resource=name,
                            description="Bucket does not have server access logging enabled.",
                            severity="LOW"
                        )
                    )
            except ClientError as e:
                print(e)
                continue

            # 6) Check for overly permissive buckets
            result = self.s3.get_bucket_acl(Bucket=name)
            owner_id = result['Owner']['ID']

            for grant in result['Grants']:
                grantee = grant.get('Grantee', {})
                perm    = grant.get('Permission')
                gr_type = grantee.get('Type')

                # only care about other AWS accounts (CanonicalUser)
                if gr_type == 'CanonicalUser':
                    grantee_id = grantee.get('ID')
                    if grantee_id and grantee_id != owner_id:
                        # map permission → severity
                        sev_map = {
                            'FULL_CONTROL': 'HIGH',
                            'WRITE':        'MEDIUM',
                            'READ':         'LOW'
                        }
                        severity = sev_map.get(perm, 'LOW')

                        issues.append(
                            Issue(
                                id="S3_CROSS_ACCOUNT_ACL",
                                resource=name,
                                description=(
                                    f"Bucket ACL grants {perm} permission "
                                    f"to external AWS account {grantee_id}."
                                ),
                                severity=severity
                            )
                        )

        return issues


{'ResponseMetadata': 
    {'RequestId': 'CVSG169RRD59FCG7', 
     'HostId': 'pA23Jg11wXOC4O1HcRvwqOczR+5YVb3s8AKgYPHJ0okj845gEifSgf8II9svzrMF1UX2YNHX2bv8ug7V3yhtUAtcrJ8+xjMw', 
     'HTTPStatusCode': 200, 
     'HTTPHeaders': 
        {'x-amz-id-2': 'pA23Jg11wXOC4O1HcRvwqOczR+5YVb3s8AKgYPHJ0okj845gEifSgf8II9svzrMF1UX2YNHX2bv8ug7V3yhtUAtcrJ8+xjMw', 
        'x-amz-request-id': 'CVSG169RRD59FCG7', 
        'date': 'Wed, 30 Apr 2025 23:16:06 GMT', 
        'content-type': 'application/xml', 
        'transfer-encoding': 'chunked', 
        'server': 'AmazonS3'}, 
      'RetryAttempts': 0}, 
'Owner': 
    {'DisplayName': 'jake.jacobssmith', 
     'ID': 'bfa8f5933a854fe24356166f4a65ad4b9cc7459fc27a9581fb786a48ff705efe'}, 
'Grants': 
        [
            {'Grantee': 
             {'DisplayName': 'jake.jacobssmith', 
              'ID': 'bfa8f5933a854fe24356166f4a65ad4b9cc7459fc27a9581fb786a48ff705efe', 
              'Type': 'CanonicalUser'}, 
              'Permission': 'FULL_CONTROL'}]}