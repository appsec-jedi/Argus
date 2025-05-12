from dataclasses import dataclass

@dataclass
class Issue:
    """
    Represents a security issue found in a resource.
    """
    id: str             # e.g. "S3_PUBLIC_BUCKET"
    resource: str       # e.g. bucket name or ARN
    description: str    # human-readable description
    severity: str       # e.g. "LOW", "MEDIUM", "HIGH"