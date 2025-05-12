import boto3
from typing import Dict, List

class AWSInventory:
    """
    Inventory common AWS resources via individual service calls.
    """
    def __init__(self, aws_key: str, aws_secret: str, region: str = "us-east-1"):
        session = boto3.Session(
            aws_access_key_id=aws_key,
            aws_secret_access_key=aws_secret,
            region_name=region
        )
        self.ec2 = session.client("ec2")
        self.s3  = session.client("s3")
        self.rds = session.client("rds")
        self.lmb = session.client("lambda")
        self.iam = session.client("iam")
        self.eks = session.client("eks")

    def list_s3_buckets(self) -> List[str]:
        resp = self.s3.list_buckets()
        return [b["Name"] for b in resp.get("Buckets", [])]

    def list_ec2_instances(self) -> List[str]:
        instances = []
        paginator = self.ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for res in page.get("Reservations", []):
                for inst in res.get("Instances", []):
                    instances.append(inst["InstanceId"])
        return instances

    def list_rds_instances(self) -> List[str]:
        resp = self.rds.describe_db_instances()
        return [db["DBInstanceIdentifier"] for db in resp.get("DBInstances", [])]

    def list_lambda_functions(self) -> List[str]:
        funcs = []
        paginator = self.lmb.get_paginator("list_functions")
        for page in paginator.paginate():
            funcs.extend(f["FunctionName"] for f in page.get("Functions", []))
        return funcs

    def list_iam_users(self) -> List[str]:
        resp = self.iam.list_users()
        return [u["UserName"] for u in resp.get("Users", [])]
    
    def list_eks_clusters(self) -> List[str]:
        response = self.eks.list_clusters(
            maxResults=123,
            nextToken='string',
            include=['string']
        )
        return response["clusters"]

    def list_all(self) -> Dict[str, List[str]]:
        return {
            "s3_buckets":           self.list_s3_buckets(),
            "ec2_instances":        self.list_ec2_instances(),
            "rds_instances":        self.list_rds_instances(),
            "lambda_functions":     self.list_lambda_functions(),
            "iam_users":            self.list_iam_users(),
            "eks_clusters":         self.list_eks_clusters(),
        }