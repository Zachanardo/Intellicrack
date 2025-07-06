#!/usr/bin/env python3
"""
This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

"""
Migrate existing API keys and secrets to the centralized secrets manager.

This script will:
1. Find existing API keys in configuration files
2. Move them to the secure secrets manager
3. Update configuration files to remove plain text secrets
"""

import json
import sys
from pathlib import Path

from intellicrack.utils.logger import get_logger
from intellicrack.utils.secrets_manager import get_secrets_manager

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))


logger = get_logger(__name__)


def migrate_llm_configs():
    """Migrate LLM configuration API keys."""
    llm_config_path = Path.home() / ".intellicrack" / "llm_configs" / "models.json"

    if not llm_config_path.exists():
        logger.info("No LLM configuration found to migrate")
        return

    logger.info(f"Migrating LLM configs from {llm_config_path}")
    secrets_manager = get_secrets_manager()

    try:
        with open(llm_config_path, 'r') as f:
            config = json.load(f)

        migrated_count = 0

        # Process each model configuration
        for model_id, model_config in config.items():
            if 'api_key' in model_config and model_config['api_key']:
                api_key = model_config['api_key']

                # Determine the appropriate secret key based on provider
                provider = model_config.get('provider', '').lower()
                if provider == 'openai':
                    secret_key = 'OPENAI_API_KEY'
                elif provider == 'anthropic':
                    secret_key = 'ANTHROPIC_API_KEY'
                elif provider == 'google':
                    secret_key = 'GOOGLE_API_KEY'
                elif provider == 'cohere':
                    secret_key = 'COHERE_API_KEY'
                elif provider == 'groq':
                    secret_key = 'GROQ_API_KEY'
                else:
                    secret_key = f"{provider.upper()}_API_KEY"

                # Store in secrets manager
                secrets_manager.set(secret_key, api_key)

                # Remove from config
                model_config['api_key'] = ""

                logger.info(f"Migrated API key for {model_id} to {secret_key}")
                migrated_count += 1

        if migrated_count > 0:
            # Save updated config without API keys
            backup_path = llm_config_path.with_suffix('.json.backup')
            llm_config_path.rename(backup_path)
            logger.info(f"Created backup at {backup_path}")

            with open(llm_config_path, 'w') as f:
                json.dump(config, f, indent=2)

            logger.info(f"Migrated {migrated_count} API keys to secure storage")
        else:
            logger.info("No API keys found to migrate")

    except Exception as e:
        logger.error(f"Failed to migrate LLM configs: {e}")


def migrate_env_files():
    """Check for .env files and provide guidance."""
    env_files = ['.env', '.env.local', '.env.production']
    project_root = Path.cwd()

    found_env_files = []
    for env_file in env_files:
        env_path = project_root / env_file
        if env_path.exists():
            found_env_files.append(env_path)

    if found_env_files:
        logger.info("\nFound environment files:")
        for env_file in found_env_files:
            logger.info(f"  - {env_file}")

        logger.info("\nThese files are already supported by the secrets manager.")
        logger.info("API keys in .env files will be automatically loaded.")
        logger.info("\nBest practices:")
        logger.info("1. Use .env.example for template (no real secrets)")
        logger.info("2. Use .env.local for your personal API keys")
        logger.info("3. Ensure .env files are in .gitignore")


def check_code_for_secrets():
    """Scan code for potential hardcoded secrets."""
    logger.info("\nScanning for potential hardcoded secrets...")

    patterns = [
        ('api_key = "', 'API key assignment'),
        ('API_KEY = "', 'API key constant'),
        ('secret = "', 'Secret assignment'),
        ('token = "', 'Token assignment'),
        ('password = "', 'Password assignment'),
    ]

    issues_found = []

    # Scan Python files
    for py_file in Path("intellicrack").rglob("*.py"):
        try:
            content = py_file.read_text()
            for pattern, description in patterns:
                if pattern in content and pattern + '"' not in content:  # Not empty string
                    line_no = content[:content.index(pattern)].count('\n') + 1
                    issues_found.append(f"{py_file}:{line_no} - {description}")
        except Exception as e:
            logger.debug(f"Failed to scan file {py_file}: {e}")

    if issues_found:
        logger.warning("\nPotential hardcoded secrets found:")
        for issue in issues_found[:10]:  # Show first 10
            logger.warning(f"  {issue}")
        if len(issues_found) > 10:
            logger.warning(f"  ... and {len(issues_found) - 10} more")
        logger.warning("\nPlease review these and move to environment variables!")
    else:
        logger.info("No obvious hardcoded secrets found in code.")


def show_usage_examples():
    """Show how to use the secrets manager in code."""
    logger.info("\n" + "=" * 60)
    logger.info("HOW TO USE THE SECRETS MANAGER")
    logger.info("=" * 60)

    print("""
1. Import the secrets manager:
   ```python
   from intellicrack.utils.secrets_manager import get_secret, get_api_key
   ```

2. Get a secret (will check env vars, keychain, and encrypted storage):
   ```python
   api_key = get_secret('OPENAI_API_KEY')
   # or
   api_key = get_api_key('openai')
   ```

3. Set a secret programmatically:
   ```python
   from intellicrack.utils.secrets_manager import set_secret
   set_secret('MY_API_KEY', 'secret-value-here')
   ```

4. In your .env.local file:
   ```
   OPENAI_API_KEY=sk-...
   ANTHROPIC_API_KEY=sk-ant-...
   ```

5. Update existing code:
   OLD: api_key = os.getenv('OPENAI_API_KEY')
   NEW: api_key = get_secret('OPENAI_API_KEY')

   OLD: config['api_key'] = 'hardcoded-key'
   NEW: config['api_key'] = get_secret('API_KEY')
""")


def main():
    """Main migration function."""
    logger.info("Intellicrack Secrets Migration Tool")
    logger.info("=" * 40)

    # Initialize secrets manager
    secrets_manager = get_secrets_manager()

    # Show current status
    existing_secrets = secrets_manager.list_keys()
    if existing_secrets:
        logger.info(f"\nCurrently managed secrets: {len(existing_secrets)}")
        for key in existing_secrets:
            logger.info(f"  - {key}")
    else:
        logger.info("\nNo secrets currently managed")

    # Run migrations
    logger.info("\nStarting migration...")

    # 1. Migrate LLM configs
    migrate_llm_configs()

    # 2. Check for env files
    migrate_env_files()

    # 3. Scan for hardcoded secrets
    check_code_for_secrets()

    # 4. Show usage examples
    show_usage_examples()

    logger.info("\nMigration complete!")
    logger.info("\nNext steps:")
    logger.info("1. Review any warnings above")
    logger.info("2. Update your code to use get_secret() instead of os.getenv()")
    logger.info("3. Add your API keys to .env.local (create if needed)")
    logger.info("4. Ensure .env* files are in .gitignore")


if __name__ == "__main__":
    main()
