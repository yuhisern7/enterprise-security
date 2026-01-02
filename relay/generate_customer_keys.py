#!/usr/bin/env python3
"""
Customer Key Generator
Generates unique crypto keys for each customer installation
"""

import os
import sys
import json
import secrets
import hashlib
from datetime import datetime
from pathlib import Path

def generate_customer_id(company_name: str) -> str:
    """Generate unique customer ID from company name"""
    # Sanitize company name
    clean_name = "".join(c.lower() if c.isalnum() else "-" for c in company_name)
    clean_name = clean_name.strip("-")
    
    # Add random suffix for uniqueness
    random_suffix = secrets.token_hex(4)
    
    return f"{clean_name}-{random_suffix}"

def generate_shared_secret() -> bytes:
    """Generate cryptographically secure 256-bit shared secret"""
    return secrets.token_bytes(32)

def create_customer_package(company_name: str, output_dir: str = "customer_keys"):
    """
    Create complete key package for a new customer
    
    Args:
        company_name: Company/customer name
        output_dir: Directory to store customer packages
    """
    # Generate customer ID
    customer_id = generate_customer_id(company_name)
    
    # Generate shared secret for HMAC
    shared_secret = generate_shared_secret()
    
    # Create output directory structure
    package_dir = Path(output_dir) / customer_id
    package_dir.mkdir(parents=True, exist_ok=True)
    
    # Save shared secret
    secret_file = package_dir / "shared_secret.key"
    with open(secret_file, 'wb') as f:
        f.write(shared_secret)
    
    # Calculate fingerprint
    fingerprint = hashlib.sha256(shared_secret).hexdigest()
    
    # Create customer info file
    customer_info = {
        "customer_id": customer_id,
        "company_name": company_name,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "key_fingerprint": fingerprint,
        "installation_instructions": [
            "1. Clone the repository: git clone https://github.com/yuhisern7/battle-hardened-ai.git",
            "2. Copy 'shared_secret.key' to: relay/ai_training_materials/crypto_keys/",
            f"3. Set environment variable: CUSTOMER_ID={customer_id}",
            "4. Build and run: cd server && docker compose up -d --build"
        ]
    }
    
    info_file = package_dir / "customer_info.json"
    with open(info_file, 'w') as f:
        json.dump(customer_info, f, indent=2)
    
    # Create .env snippet
    env_file = package_dir / ".env.customer"
    with open(env_file, 'w') as f:
        f.write(f"# Customer Configuration\n")
        f.write(f"CUSTOMER_ID={customer_id}\n")
        f.write(f"RELAY_ENABLED=true\n")
        f.write(f"RELAY_CRYPTO_ENABLED=true\n")
        f.write(f"RELAY_URL=wss://165.22.108.8:60001\n")
    
    # Add to authorized customers registry
    registry_file = Path(output_dir) / "authorized_customers.json"
    if registry_file.exists():
        with open(registry_file, 'r') as f:
            registry = json.load(f)
    else:
        registry = {}
    
    registry[customer_id] = {
        "company_name": company_name,
        "key_fingerprint": fingerprint,
        "created_at": datetime.utcnow().isoformat() + "Z",
        "status": "active"
    }
    
    with open(registry_file, 'w') as f:
        json.dump(registry, f, indent=2)
    
    print(f"✅ Customer package created successfully!")
    print(f"")
    print(f"📋 Customer Details:")
    print(f"   Company: {company_name}")
    print(f"   Customer ID: {customer_id}")
    print(f"   Key Fingerprint: {fingerprint[:16]}...")
    print(f"")
    print(f"📁 Package Location: {package_dir}/")
    print(f"   ├── shared_secret.key      (32 bytes) - HMAC key")
    print(f"   ├── customer_info.json     - Installation guide")
    print(f"   └── .env.customer          - Environment config")
    print(f"")
    print(f"📤 Next Steps:")
    print(f"   1. Send package to customer securely (encrypted email/USB)")
    print(f"   2. Deploy {registry_file} to relay server")
    print(f"   3. Restart relay server to load new customer")
    print(f"")
    print(f"🔐 Security: Customer has unique credentials - revocable independently")
    
    return customer_id, fingerprint

def revoke_customer(customer_id: str, output_dir: str = "customer_keys"):
    """Mark a customer as revoked"""
    registry_file = Path(output_dir) / "authorized_customers.json"
    
    if not registry_file.exists():
        print(f"❌ No customer registry found")
        return
    
    with open(registry_file, 'r') as f:
        registry = json.load(f)
    
    if customer_id not in registry:
        print(f"❌ Customer {customer_id} not found")
        return
    
    registry[customer_id]["status"] = "revoked"
    registry[customer_id]["revoked_at"] = datetime.utcnow().isoformat() + "Z"
    
    with open(registry_file, 'w') as f:
        json.dump(registry, f, indent=2)
    
    print(f"✅ Customer {customer_id} revoked")
    print(f"   Deploy updated {registry_file} to relay server")

def list_customers(output_dir: str = "customer_keys"):
    """List all registered customers"""
    registry_file = Path(output_dir) / "authorized_customers.json"
    
    if not registry_file.exists():
        print(f"❌ No customer registry found")
        return
    
    with open(registry_file, 'r') as f:
        registry = json.load(f)
    
    print(f"📋 Registered Customers ({len(registry)} total)")
    print(f"")
    
    for customer_id, info in registry.items():
        status_icon = "✅" if info.get("status") == "active" else "🚫"
        print(f"{status_icon} {info['company_name']}")
        print(f"   ID: {customer_id}")
        print(f"   Status: {info.get('status', 'active')}")
        print(f"   Created: {info['created_at']}")
        print(f"")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Manage customer crypto keys")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    
    # Create customer
    create_parser = subparsers.add_parser("create", help="Create new customer keys")
    create_parser.add_argument("company_name", help="Company/customer name")
    create_parser.add_argument("--output", default="customer_keys", help="Output directory")
    
    # Revoke customer
    revoke_parser = subparsers.add_parser("revoke", help="Revoke customer access")
    revoke_parser.add_argument("customer_id", help="Customer ID to revoke")
    revoke_parser.add_argument("--output", default="customer_keys", help="Output directory")
    
    # List customers
    list_parser = subparsers.add_parser("list", help="List all customers")
    list_parser.add_argument("--output", default="customer_keys", help="Output directory")
    
    args = parser.parse_args()
    
    if args.command == "create":
        create_customer_package(args.company_name, args.output)
    elif args.command == "revoke":
        revoke_customer(args.customer_id, args.output)
    elif args.command == "list":
        list_customers(args.output)
    else:
        parser.print_help()
