#!/usr/bin/env python3
"""
Configuration Profile System for Intellicrack CLI
Allows saving and loading of analysis configurations
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
import yaml

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich import box


class ConfigProfile:
    """Represents a saved configuration profile"""
    
    def __init__(self, name: str, description: str = ""):
        self.name = name
        self.description = description
        self.created_at = datetime.now()
        self.last_used = None
        self.settings = {}
        self.analysis_options = []
        self.output_format = "json"
        self.plugins_enabled = []
        self.custom_scripts = []
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert profile to dictionary"""
        return {
            "name": self.name,
            "description": self.description,
            "created_at": self.created_at.isoformat(),
            "last_used": self.last_used.isoformat() if self.last_used else None,
            "settings": self.settings,
            "analysis_options": self.analysis_options,
            "output_format": self.output_format,
            "plugins_enabled": self.plugins_enabled,
            "custom_scripts": self.custom_scripts
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ConfigProfile':
        """Create profile from dictionary"""
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
    """Manages configuration profiles"""
    
    def __init__(self, profile_dir: Optional[str] = None):
        self.console = Console()
        
        # Set profile directory
        if profile_dir:
            self.profile_dir = Path(profile_dir)
        else:
            # Default to ~/.intellicrack/profiles
            self.profile_dir = Path.home() / ".intellicrack" / "profiles"
        
        # Create directory if it doesn't exist
        self.profile_dir.mkdir(parents=True, exist_ok=True)
        
        # Load existing profiles
        self.profiles = self._load_profiles()
    
    def _load_profiles(self) -> Dict[str, ConfigProfile]:
        """Load all profiles from disk"""
        profiles = {}
        
        for profile_file in self.profile_dir.glob("*.json"):
            try:
                with open(profile_file, 'r') as f:
                    data = json.load(f)
                    profile = ConfigProfile.from_dict(data)
                    profiles[profile.name] = profile
            except Exception as e:
                self.console.print(f"[red]Error loading profile {profile_file}: {e}[/red]")
        
        return profiles
    
    def save_profile(self, profile: ConfigProfile) -> None:
        """Save profile to disk"""
        profile_path = self.profile_dir / f"{profile.name}.json"
        
        with open(profile_path, 'w') as f:
            json.dump(profile.to_dict(), f, indent=2)
        
        self.profiles[profile.name] = profile
        self.console.print(f"[green]Profile '{profile.name}' saved successfully![/green]")
    
    def delete_profile(self, name: str) -> bool:
        """Delete a profile"""
        if name not in self.profiles:
            return False
        
        profile_path = self.profile_dir / f"{name}.json"
        if profile_path.exists():
            profile_path.unlink()
        
        del self.profiles[name]
        return True
    
    def get_profile(self, name: str) -> Optional[ConfigProfile]:
        """Get a profile by name"""
        profile = self.profiles.get(name)
        if profile:
            profile.last_used = datetime.now()
            self.save_profile(profile)  # Update last used time
        return profile
    
    def list_profiles(self) -> None:
        """Display all profiles in a table"""
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
                profile.description[:30] + "..." if len(profile.description) > 30 else profile.description,
                profile.created_at.strftime("%Y-%m-%d"),
                profile.last_used.strftime("%Y-%m-%d") if profile.last_used else "Never",
                f"{len(profile.analysis_options)} options"
            )
        
        self.console.print(table)
    
    def create_profile_interactive(self) -> ConfigProfile:
        """Create a new profile interactively"""
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
            ("ml_predict", "ML Prediction")
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
            default="json"
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
        
        # Save profile
        self.save_profile(profile)
        
        return profile
    
    def apply_profile(self, profile_name: str, args: Any) -> Any:
        """Apply a profile to command-line arguments"""
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
        if profile.plugins_enabled and hasattr(args, 'plugins'):
            args.plugins = profile.plugins_enabled
        
        self.console.print(f"[green]Applied profile '{profile_name}'[/green]")
        
        return args


def create_default_profiles():
    """Create some default profiles for common use cases"""
    manager = ProfileManager()
    
    # Quick scan profile
    quick_scan = ConfigProfile("quick_scan", "Fast basic analysis")
    quick_scan.analysis_options = ["static", "strings", "entropy"]
    quick_scan.settings = {"timeout": 60, "threads": 2}
    manager.save_profile(quick_scan)
    
    # Full analysis profile
    full_analysis = ConfigProfile("full_analysis", "Comprehensive analysis with all features")
    full_analysis.analysis_options = [
        "static", "dynamic", "vulnerability", "protection",
        "network", "license", "strings", "entropy", "signature", "ml_predict"
    ]
    full_analysis.settings = {"timeout": 600, "threads": 8, "verbose": True}
    full_analysis.output_format = "html"
    manager.save_profile(full_analysis)
    
    # Malware analysis profile
    malware = ConfigProfile("malware_analysis", "Specialized malware analysis")
    malware.analysis_options = [
        "static", "dynamic", "strings", "network", "protection", "signature"
    ]
    malware.settings = {
        "timeout": 300,
        "sandbox": True,
        "network_monitoring": True,
        "behavioral_analysis": True
    }
    manager.save_profile(malware)
    
    # License analysis profile
    license_check = ConfigProfile("license_check", "Focus on license and protection mechanisms")
    license_check.analysis_options = ["static", "license", "protection", "strings"]
    license_check.settings = {"deep_scan": True, "check_dongles": True}
    manager.save_profile(license_check)
    
    return manager


def main():
    """Demo the profile system"""
    console = Console()
    
    console.print(Panel(
        "[bold cyan]Intellicrack Configuration Profile Manager[/bold cyan]",
        box=box.DOUBLE
    ))
    
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
            profile = manager.get_profile(profile_name)
            
            if profile:
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
                    box=box.ROUNDED
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
                    console.print(f"[red]Failed to delete profile.[/red]")
        
        elif choice == "5":
            create_default_profiles()
            console.print("[green]Default profiles created![/green]")
        
        elif choice == "6":
            break
    
    console.print("\n[cyan]Goodbye![/cyan]")


if __name__ == "__main__":
    main()