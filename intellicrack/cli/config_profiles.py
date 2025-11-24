#!/usr/bin/env python3
"""Configuration Profile System for Intellicrack CLI Allows saving and loading of analysis configurations.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.

PRODUCTION-READY: Uses central configuration system as single source of truth.
Legacy profile files are migrated on first run, then only central config is used.
"""

# Standard library imports
import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import Any

# Third-party imports
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

# Internal imports
from intellicrack.core.config_manager import IntellicrackConfig
from intellicrack.utils.logger import get_logger


logger = get_logger(__name__)

"""
Configuration Profile System for Intellicrack CLI
Allows saving and loading of analysis configurations
"""


class ConfigProfile:
    """Represents a saved configuration profile."""

    def __init__(self, name: str, description: str = "") -> None:
        """Initialize configuration profile with settings and metadata."""
        self.name = name
        self.description = description
        self.created_at = datetime.now()
        self.last_used = None
        self.settings = {}
        self.analysis_options = []
        self.output_format = "json"
        self.plugins_enabled = []
        self.custom_scripts = []

    def to_dict(self) -> dict[str, Any]:
        """Convert profile to dictionary."""
        return {
            "name": self.name,
            "description": self.description,
            "created_at": self.created_at.isoformat(),
            "last_used": self.last_used.isoformat() if self.last_used else None,
            "settings": self.settings,
            "analysis_options": self.analysis_options,
            "output_format": self.output_format,
            "plugins_enabled": self.plugins_enabled,
            "custom_scripts": self.custom_scripts,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ConfigProfile":
        """Create profile from dictionary."""
        profile = cls(data["name"], data.get("description", ""))
        profile.created_at = datetime.fromisoformat(data["created_at"])
        if data.get("last_used"):
            profile.last_used = datetime.fromisoformat(data["last_used"])
        profile.settings = data.get("settings", {})
        profile.analysis_options = data.get("analysis_options", [])
        profile.output_format = data.get("output_format", "json")
        profile.plugins_enabled = data.get("plugins_enabled", [])
        profile.custom_scripts = data.get("custom_scripts", [])
        return profile


class ProfileManager:
    """Production-ready profile manager using central IntellicrackConfig.

    This class provides profile management while storing all data in the
    central config.json file. Legacy profile files are only read during
    migration, never written to. Single source of truth: central config.
    """

    def __init__(self, profile_dir: str | None = None) -> None:
        """Initialize profile manager with central config delegation."""
        self.console = Console()
        self.central_config = IntellicrackConfig()

        # Set profile directory for migration purposes only
        if profile_dir:
            self.profile_dir = Path(profile_dir)
        else:
            # Default to ~/.intellicrack/profiles
            self.profile_dir = Path.home() / ".intellicrack" / "profiles"

        # Migrate existing profiles if needed
        self._migrate_if_needed()

        # Load profiles from central config
        self.profiles = self._load_profiles()

    def _migrate_if_needed(self) -> None:
        """One-time migration from old profile files to central config."""
        # Check if migration is needed
        if not self.profile_dir.exists() or self.central_config.get("cli_configuration.profiles_migrated", False):
            return
        try:
            logger.info(f"Migrating CLI profiles from {self.profile_dir} to central config")

            # Get current profiles from central config
            cli_config = self.central_config.get("cli_configuration", {})
            current_profiles = cli_config.get("profiles", {})

            # Load and migrate each profile file
            for profile_file in self.profile_dir.glob("*.json"):
                try:
                    with open(profile_file) as f:
                        data = json.load(f)
                        profile_name = data.get("name", profile_file.stem)
                        # Store profile data in central config
                        current_profiles[profile_name] = data
                        logger.info(f"Migrated profile: {profile_name}")
                except Exception as e:
                    logger.error(f"Failed to migrate profile {profile_file}: {e}")

            # Update central config with all profiles
            cli_config["profiles"] = current_profiles
            cli_config["profiles_migrated"] = True
            self.central_config.set("cli_configuration", cli_config)
            self.central_config.save()

            logger.info("Successfully migrated all CLI profiles to central config")

            # Rename old profile directory to .backup
            backup_dir = self.profile_dir.with_suffix(".backup")
            if not backup_dir.exists():
                self.profile_dir.rename(backup_dir)
                logger.info(f"Renamed old profile directory to {backup_dir}")

        except Exception as e:
            logger.error(f"Failed to migrate CLI profiles: {e}")

    def _load_profiles(self) -> dict[str, ConfigProfile]:
        """Load all profiles from central config."""
        profiles = {}

        # Get profiles from central config
        cli_config = self.central_config.get("cli_configuration", {})
        profiles_data = cli_config.get("profiles", {})

        for profile_name, profile_data in profiles_data.items():
            try:
                # Skip migration marker
                if profile_name == "default" and isinstance(profile_data, dict) and "output_format" in profile_data:
                    # This is the default profile structure, not a user profile
                    continue

                profile = ConfigProfile.from_dict(profile_data)
                profiles[profile_name] = profile
            except Exception as e:
                logger.error(f"Error loading profile {profile_name}: {e}")

        return profiles

    def save_profile(self, profile: ConfigProfile) -> None:
        """Save profile to central config."""
        # Get current CLI config
        cli_config = self.central_config.get("cli_configuration", {})
        profiles_data = cli_config.get("profiles", {})

        # Update profile data
        profiles_data[profile.name] = profile.to_dict()

        # Save to central config
        cli_config["profiles"] = profiles_data
        self.central_config.set("cli_configuration", cli_config)
        self.central_config.save()

        # Update local cache
        self.profiles[profile.name] = profile
        self.console.print(f"[green]Profile '{profile.name}' saved successfully![/green]")

    def delete_profile(self, name: str) -> bool:
        """Delete a profile from central config."""
        if name not in self.profiles:
            return False

        # Remove from central config
        cli_config = self.central_config.get("cli_configuration", {})
        profiles_data = cli_config.get("profiles", {})

        if name in profiles_data:
            del profiles_data[name]
            cli_config["profiles"] = profiles_data
            self.central_config.set("cli_configuration", cli_config)
            self.central_config.save()

        # Remove from local cache
        del self.profiles[name]
        return True

    def get_profile(self, name: str) -> ConfigProfile | None:
        """Get a profile by name."""
        profile = self.profiles.get(name)
        if profile:
            profile.last_used = datetime.now()
            self.save_profile(profile)  # Update last used time in central config
        return profile

    def list_profiles(self) -> None:
        """Display all profiles in a table."""
        if not self.profiles:
            self.console.print("[yellow]No profiles found.[/yellow]")
            return

        table = Table(title="Configuration Profiles", box=box.ROUNDED)
        table.add_column("Name", style="cyan")
        table.add_column("Description", style="white")
        table.add_column("Created", style="green")
        table.add_column("Last Used", style="yellow")
        table.add_column("Analysis Options", style="blue")

        for profile in self.profiles.values():
            table.add_row(
                profile.name,
                (f"{profile.description[:30]}..." if len(profile.description) > 30 else profile.description),
                profile.created_at.strftime("%Y-%m-%d"),
                (profile.last_used.strftime("%Y-%m-%d") if profile.last_used else "Never"),
                f"{len(profile.analysis_options)} options",
            )

        self.console.print(table)

    def create_profile_interactive(self) -> ConfigProfile:
        """Create a new profile interactively."""
        self.console.print("\n[bold cyan]Create New Configuration Profile[/bold cyan]\n")

        # Get basic info
        name = Prompt.ask("Profile name")
        while name in self.profiles:
            self.console.print("[red]Profile already exists![/red]")
            name = Prompt.ask("Profile name")

        description = Prompt.ask("Description", default="")

        profile = ConfigProfile(name, description)

        # Select analysis options
        self.console.print("\n[bold]Select analysis options:[/bold]")

        available_options = [
            ("static", "Static Analysis"),
            ("dynamic", "Dynamic Analysis"),
            ("vulnerability", "Vulnerability Scan"),
            ("protection", "Protection Detection"),
            ("network", "Network Analysis"),
            ("license", "License Analysis"),
            ("strings", "String Extraction"),
            ("entropy", "Entropy Analysis"),
            ("signature", "Signature Matching"),
            ("ml_predict", "ML Prediction"),
        ]

        for opt_id, opt_name in available_options:
            if Confirm.ask(f"  Include {opt_name}?", default=False):
                profile.analysis_options.append(opt_id)

        # Configure output format
        self.console.print("\n[bold]Output format:[/bold]")
        formats = ["json", "html", "pdf", "csv", "xml"]
        profile.output_format = Prompt.ask(
            "Choose format",
            choices=formats,
            default="json",
        )

        # Advanced settings
        if Confirm.ask("\nConfigure advanced settings?", default=False):
            profile.settings["timeout"] = int(Prompt.ask("Analysis timeout (seconds)", default="300"))
            profile.settings["max_memory"] = int(Prompt.ask("Max memory (MB)", default="2048"))
            profile.settings["threads"] = int(Prompt.ask("Number of threads", default="4"))

            if Confirm.ask("Enable verbose output?", default=False):
                profile.settings["verbose"] = True

            if Confirm.ask("Enable debug mode?", default=False):
                profile.settings["debug"] = True

        # Save profile to central config
        self.save_profile(profile)

        return profile

    def apply_profile(self, profile_name: str, args: argparse.Namespace) -> argparse.Namespace:
        """Apply a profile to command-line arguments.

        Args:
            profile_name: Name of the profile to apply.
            args: Namespace object containing command-line arguments to modify.

        Returns:
            Modified namespace object with profile settings applied.

        """
        profile = self.get_profile(profile_name)
        if not profile:
            self.console.print(f"[red]Profile '{profile_name}' not found![/red]")
            return args

        # Apply analysis options
        for option in profile.analysis_options:
            setattr(args, option, True)

        # Apply output format
        args.output_format = profile.output_format

        # Apply settings
        for key, value in profile.settings.items():
            if hasattr(args, key):
                setattr(args, key, value)

        # Apply plugins
        if profile.plugins_enabled and hasattr(args, "plugins"):
            args.plugins = profile.plugins_enabled

        self.console.print(f"[green]Applied profile '{profile_name}'[/green]")

        return args


def create_default_profiles() -> ProfileManager:
    """Create some default profiles for common use cases.

    Creates and saves four predefined profiles to the central configuration:
    - quick_scan: Fast basic analysis with minimal options
    - full_analysis: Comprehensive analysis with all analysis features
    - bypass_analysis: Specialized profile for license bypass analysis
    - license_check: Focused profile for license and protection mechanisms

    Returns:
        ProfileManager instance with default profiles created and saved.

    """
    manager = ProfileManager()

    # Quick scan profile
    quick_scan = ConfigProfile("quick_scan", "Fast basic analysis")
    quick_scan.analysis_options = ["static", "strings", "entropy"]
    quick_scan.settings = {"timeout": 60, "threads": 2}
    manager.save_profile(quick_scan)

    # Full analysis profile
    full_analysis = ConfigProfile("full_analysis", "Comprehensive analysis with all features")
    full_analysis.analysis_options = [
        "static",
        "dynamic",
        "vulnerability",
        "protection",
        "network",
        "license",
        "strings",
        "entropy",
        "signature",
        "ml_predict",
    ]
    full_analysis.settings = {"timeout": 600, "threads": 8, "verbose": True}
    full_analysis.output_format = "html"
    manager.save_profile(full_analysis)

    # Protection bypass analysis profile
    bypass_analysis = ConfigProfile("bypass_analysis", "Specialized license bypass analysis")
    bypass_analysis.analysis_options = [
        "static",
        "dynamic",
        "strings",
        "network",
        "protection",
        "signature",
    ]
    bypass_analysis.settings = {
        "timeout": 300,
        "sandbox": True,
        "network_monitoring": True,
        "behavioral_analysis": True,
    }
    manager.save_profile(bypass_analysis)

    # License analysis profile
    license_check = ConfigProfile("license_check", "Focus on license and protection mechanisms")
    license_check.analysis_options = ["static", "license", "protection", "strings"]
    license_check.settings = {"deep_scan": True, "check_dongles": True}
    manager.save_profile(license_check)

    return manager


# pylint: disable=too-many-branches,too-many-statements
def main() -> None:
    """Demo the profile system."""
    console = Console()

    console.print(
        Panel(
            "[bold cyan]Intellicrack Configuration Profile Manager[/bold cyan]",
            box=box.DOUBLE,
        ),
    )

    manager = ProfileManager()

    while True:
        console.print("\n[bold]Options:[/bold]")
        console.print("1. List profiles")
        console.print("2. Create new profile")
        console.print("3. View profile details")
        console.print("4. Delete profile")
        console.print("5. Create default profiles")
        console.print("6. Exit")

        choice = Prompt.ask("\nSelect option", choices=["1", "2", "3", "4", "5", "6"])

        if choice == "1":
            manager.list_profiles()

        elif choice == "2":
            manager.create_profile_interactive()

        elif choice == "3":
            if not manager.profiles:
                console.print("[yellow]No profiles available.[/yellow]")
                continue

            profile_name = Prompt.ask("Profile name", choices=list(manager.profiles.keys()))
            if profile := manager.get_profile(profile_name):
                # Display profile details
                details = Panel(
                    f"[bold]Name:[/bold] {profile.name}\n"
                    f"[bold]Description:[/bold] {profile.description}\n"
                    f"[bold]Created:[/bold] {profile.created_at.strftime('%Y-%m-%d %H:%M')}\n"
                    f"[bold]Last Used:[/bold] {profile.last_used.strftime('%Y-%m-%d %H:%M') if profile.last_used else 'Never'}\n"
                    f"[bold]Analysis Options:[/bold] {', '.join(profile.analysis_options)}\n"
                    f"[bold]Output Format:[/bold] {profile.output_format}\n"
                    f"[bold]Settings:[/bold] {json.dumps(profile.settings, indent=2)}",
                    title=f"Profile: {profile.name}",
                    box=box.ROUNDED,
                )
                console.print(details)

        elif choice == "4":
            if not manager.profiles:
                console.print("[yellow]No profiles available.[/yellow]")
                continue

            profile_name = Prompt.ask("Profile name to delete", choices=list(manager.profiles.keys()))
            if Confirm.ask(f"Delete profile '{profile_name}'?", default=False):
                if manager.delete_profile(profile_name):
                    console.print(f"[green]Profile '{profile_name}' deleted.[/green]")
                else:
                    console.print("[red]Failed to delete profile.[/red]")

        elif choice == "5":
            create_default_profiles()
            console.print("[green]Default profiles created![/green]")

        elif choice == "6":
            break

    console.print("\n[cyan]Goodbye![/cyan]")


# Alias for easier importing
ConfigProfileManager = ProfileManager


if __name__ == "__main__":
    main()
