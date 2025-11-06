#!/usr/bin/env python3
"""
Credential Setup Script

Securely stores API keys and credentials for the analyzer.
"""

import sys
from pathlib import Path
from getpass import getpass

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from security.credential_manager import CredentialManager


def main():
    """Main setup function"""
    print("=" * 70)
    print("Microsoft Logs AI Analyzer - Credential Setup")
    print("=" * 70)
    print()

    # Initialize credential manager
    config_dir = Path(__file__).parent.parent / 'config'
    cred_manager = CredentialManager(storage_method='auto', config_dir=config_dir)

    print(f"Using storage method: {cred_manager.storage_method}")
    print()

    # Get LLM provider choice
    print("Select your LLM provider:")
    print("  1. Claude (Anthropic)")
    print("  2. ChatGPT (OpenAI)")
    print("  3. Google Gemini")
    print("  4. All of the above")
    print()

    choice = input("Enter choice (1-4): ").strip()

    providers = []
    if choice == '1':
        providers = ['claude']
    elif choice == '2':
        providers = ['openai']
    elif choice == '3':
        providers = ['gemini']
    elif choice == '4':
        providers = ['claude', 'openai', 'gemini']
    else:
        print("Invalid choice")
        sys.exit(1)

    print()

    # Get API keys
    for provider in providers:
        print(f"\n{provider.upper()} API Key Setup")
        print("-" * 40)

        if provider == 'claude':
            print("Get your API key from: https://console.anthropic.com/")
        elif provider == 'openai':
            print("Get your API key from: https://platform.openai.com/api-keys")
        elif provider == 'gemini':
            print("Get your API key from: https://makersuite.google.com/app/apikey")

        api_key = getpass(f"Enter {provider.upper()} API key (input hidden): ").strip()

        if api_key:
            success = cred_manager.store_credential(f'{provider}_api_key', api_key)

            if success:
                print(f"✓ {provider.upper()} API key stored securely")
            else:
                print(f"✗ Failed to store {provider.upper()} API key")
        else:
            print(f"Skipped {provider.upper()} API key")

    print()

    # Optional: Email credentials
    setup_email = input("\nSetup email credentials for alerts? (y/n): ").strip().lower()

    if setup_email == 'y':
        print("\nEmail Credentials Setup")
        print("-" * 40)

        smtp_user = input("SMTP username/email: ").strip()
        smtp_pass = getpass("SMTP password (input hidden): ").strip()

        if smtp_user and smtp_pass:
            cred_manager.store_credential('smtp_username', smtp_user)
            cred_manager.store_credential('smtp_password', smtp_pass)
            print("✓ Email credentials stored securely")

    print()
    print("=" * 70)
    print("Credential setup complete!")
    print()
    print("Stored credentials:")

    for cred in cred_manager.list_credentials():
        print(f"  - {cred}")

    print()
    print("Next steps:")
    print("  1. Edit config/config.yaml to customize your settings")
    print("  2. Run: python main.py --mode test  # Test configuration")
    print("  3. Run: python main.py --mode analyze  # Run analysis")
    print("=" * 70)


if __name__ == '__main__':
    main()
