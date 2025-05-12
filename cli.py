import os
import argparse
from scans.aws_scanner import AWSScanner
from inventory.aws_inventory import AWSInventory
from scans.aws.ec2_scanner import AWSEC2Scanner
from issues import Issue
from colorama import init, Fore, Style

def return_issues(issues, regions = False) -> None:
    if not issues:
        print("✅ No issues found.")
        return

    print(f"\n🚨 Found {len(issues)} issue(s):\n")
    
    for issue in issues:
        # issue is an Issue instance
        sev = issue.severity.upper()
        if sev == "HIGH":
            sev_colored = f"{Fore.RED}{sev}{Style.RESET_ALL}"
        elif sev == "MEDIUM":
            sev_colored = f"{Fore.YELLOW}{sev}{Style.RESET_ALL}"
        else:
            sev_colored = f"{Fore.GREEN}{sev}{Style.RESET_ALL}"        

        print(f"[{sev_colored}] {issue.id} on {issue.resource}\n\t{issue.description}\n")
     
    if regions:
        print(f"\nActive regions: ")
        for reg in regions:
            print(reg)

def run_aws_scan(args) -> None:
    key = os.getenv("AWS_ACCESS_KEY_ID")
    secret = os.getenv("AWS_SECRET_ACCESS_KEY")
    if not key or not secret:
        print("❗ Set AWS_ACCESS_KEY_ID & AWS_SECRET_ACCESS_KEY first.")
        return

    aws = AWSScanner(
        aws_key = key,
        aws_secret = secret
    )
    
    return_issues(AWSScanner.scan_s3_buckets(aws))

def get_aws_inventory(args) -> None:
    key = os.getenv("AWS_ACCESS_KEY_ID")
    secret = os.getenv("AWS_SECRET_ACCESS_KEY")
    if not key or not secret:
        print("❗ Set AWS_ACCESS_KEY_ID & AWS_SECRET_ACCESS_KEY first.")
        return
    
    aws = AWSInventory(
        aws_key = key,
        aws_secret = secret
    )
    print(AWSInventory.list_all(aws))

def aws_ec2_scan(args) -> None:
    key = os.getenv("AWS_ACCESS_KEY_ID")
    secret = os.getenv("AWS_SECRET_ACCESS_KEY")
    if not key or not secret:
        print("❗ Set AWS_ACCESS_KEY_ID & AWS_SECRET_ACCESS_KEY first.")
        return
    
    ec2 = AWSEC2Scanner(
        aws_key = key,
        aws_secret = secret
    )
    issues, regions = AWSEC2Scanner.run_all_regions(ec2)
    return_issues(issues, regions)

def main() -> None:
    parser = argparse.ArgumentParser(
        prog='Argus',
        description="Argus AWS S3 Misconfiguration Scanner",
        epilog='This is a work in progress'
    )
    sub = parser.add_subparsers(dest="command")

    aws_p = sub.add_parser("aws-s3", help="Scan AWS S3 buckets")
    aws_inventory = sub.add_parser("aws-inventory", help="Inventory AWS assets")
    aws_ec2 = sub.add_parser("aws-ec2", help="Scan AWS EC2 instances" )

    aws_p.set_defaults(func=run_aws_scan)
    aws_inventory.set_defaults(func=get_aws_inventory)
    aws_ec2.set_defaults(func=aws_ec2_scan)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return
    args.func(args)

if __name__ == "__main__":
    main()