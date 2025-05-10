# AWS Vault Lite

A simple graphical tool for managing secrets using the Single Secret Design (SSD) pattern in AWS Secrets Manager.

## Features

- Graphical interface for managing AWS Secrets Manager secrets
- Implements the Single Secret Design (SSD) pattern
- Password hiding/showing functionality
- Easy creation, editing, and deletion of secrets
- Flexible attribute management

## Installation

### Prerequisites

- Python 3.8 or higher
- AWS credentials with permissions to access Secrets Manager
- Tkinter (for the GUI)

### macOS

1. Clone this repository:
```bash
git clone https://github.com/yourusername/aws-vault-lite.git
cd aws-vault-lite
```

2. Install Tkinter if not already installed:
```bash
# Using Homebrew
brew install python-tk@3.13  # Replace with your Python version
```

3. Create and activate a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate
```

4. Install dependencies:
```bash
pip install -r requirements.txt
```

### Linux/WSL

1. Clone this repository:
```bash
git clone https://github.com/yourusername/aws-vault-lite.git
cd aws-vault-lite
```

2. Install Tkinter if not already installed:
```bash
# For Debian/Ubuntu
sudo apt-get update
sudo apt-get install python3-tk

# For Fedora
sudo dnf install python3-tkinter

# For CentOS/RHEL
sudo yum install python3-tkinter
```

3. Create and activate a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate
```

4. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

1. Set your AWS credentials as environment variables:
```bash
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_SESSION_TOKEN=your_session_token  # if using temporary credentials
```

2. Activate the virtual environment (if not already activated):
```bash
source venv/bin/activate
```

3. Run the application:
```bash
python3 aws-vault-lite.py
```

4. If the secret `/aws-vault-lite/vault` doesn't exist, you'll be prompted to create it.

## FAQ

### Q: I'm getting an error about missing '_tkinter' module
**A:** This means Tkinter is not installed. Follow the installation instructions for your operating system above to install Tkinter.

### Q: The application says "AWS Credentials Missing"
**A:** Make sure you've set the AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables before running the application.

### Q: I'm getting a region error
**A:** The application uses 'us-east-1' as the default region. If you need to use a different region, you can modify the code in `aws-vault-lite.py` to specify your preferred region.

### Q: How do I mark a field as a password?
**A:** When adding or editing an attribute, click the 🔒 checkbox next to the value field to mark it as a password field.

### Q: Can I use AWS profiles instead of environment variables?
**A:** The current version only supports environment variables. Support for AWS profiles may be added in future versions.

## Single Secret Design (SSD) Pattern

### Overview:
The Single Secret Design (SSD) is a cost-effective and flexible strategy for managing secrets in AWS Secrets Manager. Instead of creating individual secrets for every credential or config item, SSD consolidates all secrets for a single department (e.g., CloudOps, Networking, Infra) into one structured JSON secret, significantly reducing monthly costs and improving manageability.

### Structure:
Each secret entry is a key-value pair, where:
- The key is a unique identifier for a system, tool, or integration (e.g., argocd-staging, terraform-provisioner)
- The value is a flexible object (dictionary) with user-defined attributes like user, password, url, token, etc.

```json
{
  "argocd-staging": {
    "user": "admin",
    "password": "s3cret",
    "url": "https://argocd.staging.company.com"
  },
  "terraform-provisioner": {
    "user": "terraform",
    "password": "p@ssw0rd"
  },
  "site-xyz": {
    "url": "https://xyz.company.com",
    "user": "john",
    "password": "abc123"
  }
}
```

### Benefits:
- Security: Centralized, encrypted storage with IAM-based access control.
- Cost efficiency: Only one secret per department, reducing the $0.40/secret/month pricing overhead.
- Flexibility: No rigid schema—each secret can contain freely defined fields.
- Simplicity: Easy to read, update, and integrate with applications using standard AWS SDKs or CLI.
- Scalable: Can support dozens or even hundreds of secrets per department, up to 64 KB.

### Use Cases:
- CloudOps teams managing tools like ArgoCD, Terraform, CI/CD tokens
- Infra teams storing VPN, database, and software license credentials
- Networking teams handling router/switch admin logins, webhook keys, etc.

## Single Secret Design (SSD) Pattern

### Overview:
The Single Secret Design (SSD) is a cost-effective and flexible strategy for managing secrets in AWS Secrets Manager. Instead of creating individual secrets for every credential or config item, SSD consolidates all secrets for a single department (e.g., CloudOps, Networking, Infra) into one structured JSON secret, significantly reducing monthly costs and improving manageability.

### Structure:
Each secret entry is a key-value pair, where:
- The key is a unique identifier for a system, tool, or integration (e.g., argocd-staging, terraform-provisioner)
- The value is a flexible object (dictionary) with user-defined attributes like user, password, url, token, etc.

```json
{
  "argocd-staging": {
    "user": "admin",
    "password": "s3cret",
    "url": "https://argocd.staging.company.com"
  },
  "terraform-provisioner": {
    "user": "terraform",
    "password": "p@ssw0rd"
  },
  "site-xyz": {
    "url": "https://xyz.company.com",
    "user": "john",
    "password": "abc123"
  }
}
```

### Benefits:
- Security: Centralized, encrypted storage with IAM-based access control.
- Cost efficiency: Only one secret per department, reducing the $0.40/secret/month pricing overhead.
- Flexibility: No rigid schema—each secret can contain freely defined fields.
- Simplicity: Easy to read, update, and integrate with applications using standard AWS SDKs or CLI.
- Scalable: Can support dozens or even hundreds of secrets per department, up to 64 KB.

### Use Cases:
- CloudOps teams managing tools like ArgoCD, Terraform, CI/CD tokens
- Infra teams storing VPN, database, and software license credentials
- Networking teams handling router/switch admin logins, webhook keys, etc.
