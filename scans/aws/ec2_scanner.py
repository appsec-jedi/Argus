import boto3 # type: ignore
import json
import concurrent.futures
from datetime import datetime, date
from botocore.exceptions import ClientError # type: ignore
from typing import List, Tuple, Set, Dict, Any
from issues import Issue

class AWSEC2Scanner:
    """
    AWSEC2Scanner encapsulates EC2 misconfiguration checks:
      - Public ACLs
      - Missing default encryption
      - Public Access Block settings
      - Security group misconfigurations
      - Monitoring
      - AMI age
    """
    def __init__(self,
                 aws_key: str,
                 aws_secret: str,
                 region: str = "us-east-2"):
        self.aws_key = aws_key
        self.aws_secret = aws_secret
        self.region = region
        session = boto3.Session(
            aws_access_key_id = aws_key,
            aws_secret_access_key = aws_secret,
            region_name = region
        )
        self.ec2 = session.client("ec2")

    def _list_instances(self) -> Tuple[List[Dict[str, Any]], Set[str]]:
        """
        Returns a tuple of (list of instance dicts, set of security group IDs).
        """
        sg_ids: Set[str] = set()
        instances: List[Dict[str, Any]] = []

        # List all instances & collect SG IDs
        paginator = self.ec2.get_paginator("describe_instances")
        instances = []
        for page in paginator.paginate():
            for res in page.get("Reservations", []):
                for inst in res.get("Instances", []):
                    instances.append(inst)
                    for sg in inst.get("SecurityGroups", []):
                        sg_ids.add(sg["GroupId"])

        return instances, sg_ids

    def ec2_monitoring_check(self, inst) -> List[str]:
        # Check if monitoring is enabled
        issues = []
        if inst["Monitoring"]["State"] == "disabled":
            issues.append(
                Issue(
                    id="EC2_MONITORING_NOT_ENABLED",
                    resource=inst["InstanceId"],
                    description="Instance does not have monitoring enabled.",
                    severity="MEDIUM"
                )
            )
        return issues
    
    def ec2_public_access(self, inst) -> List[str]:
        # Check if the instance is publically accessible
        issues = []
        if inst["PublicIpAddress"] or inst["PublicDnsName"]:
            issues.append(
                Issue(
                    id="EC2_PUBLICALLY_ACCESSIBLE",
                    resource=inst["InstanceId"],
                    description="Instance is publically accessible.",
                    severity="MEDIUM"
                )
            )
        return issues
    
    def ec2_ami_age_check(self, inst) -> List[str]:
        # Check for outdated AMIs
        issues = []
        ami = self.ec2.describe_images(ImageIds=[inst["ImageId"]])
        date_string = ami["Images"][0]['CreationDate'].split('T')[0]
        ami_date = datetime.strptime(date_string, "%Y-%m-%d").date()
        today = datetime.now().date()
        age_days = (today - ami_date).days
        if age_days > 90:
            issues.append(
                Issue(
                    id="EC2_AMI_OUTDATED",
                    resource=inst["InstanceId"],
                    description=(
                        f"AMI {inst['ImageId']} was created on {date_string} "
                        f"({age_days} days ago), which exceeds the 90-day threshold."
                    ),
                    severity="LOW"
                )
            )
        return issues
    
    def ec2_scan_security_groups(self, sg_ids: Set[str]) -> List[str]:
        issues = []
        # Describe all security groups in bulk
        if sg_ids:
            resp = self.ec2.describe_security_groups(GroupIds=list(sg_ids))
            for sg in resp["SecurityGroups"]:
                for perm in sg.get("IpPermissions", []):
                    for ip_range in perm.get("IpRanges", []):
                        cidr = ip_range.get("CidrIp")
                        if cidr == "0.0.0.0/0":
                            if perm["ToPort"] == perm["FromPort"]:
                                issues.append(
                                Issue(
                                    id="SECURITY_GROUP_GLOBAL_ACCESS",
                                    resource=sg["GroupId"],
                                    description=f"Instance has a public ACL allowing global access on port {perm['FromPort']}.",
                                    severity="HIGH"
                                    )
                                )   
                            else:
                                issues.append(
                                Issue(
                                    id="SECURITY_GROUP_GLOBAL_ACCESS",
                                    resource=sg["GroupId"],
                                    description=f"Instance has a public ACL allowing global access on port {perm['FromPort']} through {perm['ToPort']}.",
                                    severity="HIGH"
                                    )
                                )
                for perm in sg.get("IpPermissionsEgress", []):
                    for ip_range in perm.get("IpRanges", []):
                        cidr = ip_range.get("CidrIp")
                        if cidr == "0.0.0.0/0":
                            issues.append(
                                Issue(
                                    id="SECURITY_GROUP_GLOBAL_EGRESS_ACCESS",
                                    resource=sg["GroupId"],
                                    description=f"Instance has a public ACL allowing global egress.",
                                    severity="HIGH"
                                    )
                                )   
        return issues

    def ec2_ebs_encryption_scan(self) -> List[str]:
        # Scan instances for ebs encryption
        issues = []
        try:
            response = self.ec2.get_ebs_encryption_by_default()
            if response["EbsEncryptionByDefault"] == False:
                issues.append(
                    Issue(
                        id="EBS_ENCRYPTION_NOT_ENABLED",
                        resource="this account",
                        description=f"EBS encryption by default is not enabled for this account in the current region.",
                        severity="HIGH"
                        )
                )  
        except ClientError as e:
            # Skip if there are permission issues
            code = e.response.get("Error", {}).get("Code", "")
            if code == "DryRunOperation" or code == "UnauthorizedOperation":
                pass
        
        return issues
    
    def ec2_scan_volume_encryption(self, inst):
        issues = []
        volume_detail = self.ec2.describe_volumes(VolumeIds=[inst["BlockDeviceMappings"][0]["Ebs"]["VolumeId"]])
        for volume in volume_detail["Volumes"]:
            if not volume["Encrypted"]:
                issues.append(
                    Issue(
                        id="VOLUME_NOT_ENCRYPTED",
                        resource=inst["InstanceId"],
                        description=f"Encryption is not enabled for this volume",
                        severity="HIGH"
                        )
                )  
        return issues
    
    def ec2_scan_tags(self, inst):
        issues = []
        if not inst["Tags"]:
            issues.append(
                Issue(
                    id="NO_TAGS_ASSOCIATED_WITH_INSTANCE",
                    resource=inst["InstanceId"],
                    description=f"No tags have been applied to this instance",
                    severity="LOW"
                    )
            )  
        return issues
    
    def run_all(self) -> List[Issue]:
        issues = []
        # self.run_all_regions()
        instances, sg_ids = self._list_instances()
        for inst in instances: 
            self.ec2_scan_tags(inst)
            issues += self.ec2_scan_volume_encryption(inst)
            issues += self.ec2_monitoring_check(inst)
            issues += self.ec2_public_access(inst)
            issues += self.ec2_ami_age_check(inst)
        issues += self.ec2_scan_security_groups(sg_ids)
        # issues += self.ec2_ebs_encryption_scan()
        
        return issues
    
    def scan_region(self, region: str) -> List[Issue]:
        """
        Instantiate a per-region client and run run_all()
        against that region.
        """
        # fresh EC2 client per region
        session = boto3.Session(
            aws_access_key_id = self.aws_key,
            aws_secret_access_key = self.aws_secret,
            region_name = region
        )
        regional_scanner = AWSEC2Scanner(
            aws_key = self.aws_key,
            aws_secret = self.aws_secret,
            region = region
        )
        regional_scanner.ec2 = session.client("ec2")  # override client
        return regional_scanner.run_all()
    
    def run_all_regions(self) -> Tuple[List[Issue], List[str]]:
        issues = []
        active_regions = []
        # Run default encryption scan for the account
        issues += self.ec2_ebs_encryption_scan()
        # Discover regions
        all_regions = self.ec2.describe_regions(AllRegions=False)
        region_list = [r["RegionName"] for r in all_regions["Regions"]]

        # In parallel, spin up a scanner per region
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            # schedule scans
            futures = {
                pool.submit(self.scan_region, region): region
                for region in region_list
            }
            # collect results
            for fut in concurrent.futures.as_completed(futures):
                region = futures[fut]
                try:
                    regional_issues = fut.result()
                    if regional_issues:
                        active_regions.append(region)
                    issues.extend(regional_issues)
                except Exception as e:
                    print(f"Error scanning {region}: {e}")
        
        return issues, active_regions
