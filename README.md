# Argus: Multi-Cloud Misconfiguration Scanner

**Argus** is a standalone CLI tool for auditing AWS (and soon, other clouds) for common security misconfigurations. It currently supports:

* **S3 scanner**: public ACLs, default encryption, public-access-block, server access logging, cross-account ACLs
* **EC2 scanner**: public exposure, monitoring, AMI age, security-group ingress/egress, EBS encryption, volume-level encryption, tag checks
* **Multi-region scanning**: discover all enabled AWS regions and scan them in parallel

---

## 🚀 Features

* **Modular architecture**: each cloud/resource gets its own `scanner` module
* **Extensible**: add new checks by implementing `scan_*` methods returning `Issue` objects
* **Credential flexibility**: environment variables, named CLI profiles, OS keyring, or interactive OAuth/SSO
* **Parallel execution**: speeds up multi-region scans via `ThreadPoolExecutor`
* **Rich reporting**: JSON or terminal output, with colorized severity labels

---

## 🔧 Installation

```bash
# Clone the repo
git clone https://github.com/your-org/argus.git
cd argus

# (Optional) create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install Argus as a CLI tool
pip install .
```

After install, the `argus` command will be available globally.

---

## ⚙️ Prerequisites

1. **Python 3.9+**
2. **AWS account credentials** — see below for methods
3. **Dependencies**: listed in `requirements.txt` (e.g. `boto3`, `colorama` or `rich`)

---

## 🔑 Credential Methods

Argus supports multiple ways to authenticate against AWS:

1. **Environment variables** (default):

   ```bash
   export AWS_ACCESS_KEY_ID=YOURKEY
   export AWS_SECRET_ACCESS_KEY=YOURSECRET
   ```

2. **CLI profile**:

   ```bash
   argus scan aws-s3 --credential-method profile --profile myprofile
   ```

3. **OS keyring** (via `argus configure`):

   ```bash
   argus configure --provider aws
   # enter key, secret interactively
   argus scan aws-ec2 --credential-method keyring
   ```

4. **Interactive OAuth/SSO**:

   ```bash
   argus scan aws-ec2 --credential-method interactive --profile my-sso-profile
   ```

---

## 📖 Usage

### Common commands

```bash
# Scan S3 buckets in default region
argus scan aws-s3

# Scan EC2 instances across all regions
argus scan aws-ec2 --regions all

# Combined scan
argus scan aws-s3 aws-ec2
```

### Options

```
--credential-method [env|profile|keyring|interactive]
--profile               (for profile or SSO flows)
--regions               (comma-separated region list or `all` for auto-discovery)
--output [json|cli|html]
```

### Example output

```bash
$ argus scan aws-s3
🔍 Scanning S3 buckets...
Found 2 issues:
- [RED][HIGH] S3_PUBLIC_BUCKET on my-bucket
    Bucket has a public ACL allowing global access.
- [YELLOW][MEDIUM] S3_UNENCRYPTED_BUCKET on logs-bucket
    Bucket does not have default encryption enabled.
```

---

## 🛠️ Development & Testing

* **Run tests**: `pytest`
* **Lint**: `flake8`
* **Add a new check**:

  1. Create a `scan_<thing>` method in the appropriate scanner class
  2. Return a list of `Issue(...)`
  3. Wire it into `run_all()` or `run_all_regions()`

---

## 🤝 Contributing

1. Fork the repo and create your feature branch.
2. Write tests and ensure coverage.
3. Submit a PR against `main`.

---

## 📜 License

MIT © Your Name or Org
