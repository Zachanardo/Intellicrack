"""Configuration manager for Intellicrack CLI.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import json
import sys
from pathlib import Path

# Add parent directories to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from intellicrack.config import CONFIG
from intellicrack.utils.logger import get_logger

logger = get_logger(__name__)


class ConfigManager:
    """Manage Intellicrack configuration settings."""

    def __init__(self):
        """Initialize configuration manager."""
        self.config = CONFIG
        self.config_file = Path.home() / ".intellicrack" / "config.json"

    def load_config(self):
        """Load configuration from file."""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    user_config = json.load(f)
                    self.config.update(user_config)
                    logger.info(f"Loaded configuration from {self.config_file}")
            except Exception as e:
                logger.error(f"Failed to load config: {e}")

    def save_config(self):
        """Save configuration to file."""
        try:
            self.config_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
            logger.info(f"Saved configuration to {self.config_file}")
        except Exception as e:
            logger.error(f"Failed to save config: {e}")

    def get(self, key, default=None):
        """Get configuration value."""
        return self.config.get(key, default)

    def set(self, key, value):
        """Set configuration value."""
        self.config[key] = value

    def list_settings(self):
        """List all configuration settings."""
        return self.config.copy()


def main():
    """Configuration management CLI."""
    import argparse

    parser = argparse.ArgumentParser(description="Intellicrack Configuration Manager")
    parser.add_argument("action", choices=["get", "set", "list"], help="Action to perform")
    parser.add_argument("key", nargs="?", help="Configuration key")
    parser.add_argument("value", nargs="?", help="Configuration value (for set)")

    args = parser.parse_args()

    manager = ConfigManager()
    manager.load_config()

    if args.action == "list":
        settings = manager.list_settings()
        for key, value in settings.items():
            print(f"{key}: {value}")

    elif args.action == "get":
        if not args.key:
            print("Error: Key required for get operation")
            return 1
        value = manager.get(args.key)
        print(f"{args.key}: {value}")

    elif args.action == "set":
        if not args.key or args.value is None:
            print("Error: Key and value required for set operation")
            return 1
        manager.set(args.key, args.value)
        manager.save_config()
        print(f"Set {args.key} = {args.value}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
