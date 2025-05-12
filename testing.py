import os
import boto3

from scans.aws_scanner import scan_s3_buckets

def main():
    aws_key = os.getenv("AWS_ACCESS_KEY_ID")
    aws_secret = os.getenv("AWS_SECRET_ACCESS_KEY")
    buckets = scan_s3_buckets(aws_key, aws_secret)
    print("Your S3 buckets:")
    for b in buckets:
        acl = scan_s3_buckets(aws_key, aws_secret, b["Name"])
        print(f"\tBucket Owner: {acl['Owner']['ID']}")
        print("\tBucket ACL:")
        for g in acl['Grants']:
            print(f"\t\tUser: {g['Grantee']['ID']}\n\t\tType: {g['Grantee']['Type']}\n\t\tPermissions: {g['Permission']}")
    

if __name__ == "__main__":
    main()
