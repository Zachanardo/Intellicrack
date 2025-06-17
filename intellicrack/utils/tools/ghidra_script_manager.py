"""
Ghidra Script Manager for Intellicrack

This module provides automatic discovery, management, and execution of Ghidra scripts.
Supports both Java and Python scripts with metadata extraction.

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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

import json
import logging
import os
import re
import shutil
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class GhidraScript:
    """Represents a single Ghidra script with metadata."""
    
    def __init__(self, path: str):
        self.path = os.path.abspath(path)
        self.filename = os.path.basename(path)
        self.name = os.path.splitext(self.filename)[0]
        self.extension = os.path.splitext(self.filename)[1].lower()
        self.type = 'java' if self.extension == '.java' else 'python'
        self.directory = os.path.dirname(path)
        
        # Metadata from script
        self.description = "No description available"
        self.author = "Unknown"
        self.category = "User Scripts"
        self.version = "1.0"
        self.min_ghidra_version = None
        self.tags = []
        
        # Runtime info
        self.last_modified = datetime.fromtimestamp(os.path.getmtime(path))
        self.size = os.path.getsize(path)
        self.is_valid = False
        self.validation_errors = []
        
        # Extract metadata
        self._extract_metadata()
        self._validate()
    
    def _extract_metadata(self):
        """Extract metadata from script comments."""
        try:
            with open(self.path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Java-style comments
            if self.type == 'java':
                # Look for @description, @author, @category tags
                desc_match = re.search(r'@description\s+(.+?)(?:\n|$)', content)
                if desc_match:
                    self.description = desc_match.group(1).strip()
                
                author_match = re.search(r'@author\s+(.+?)(?:\n|$)', content)
                if author_match:
                    self.author = author_match.group(1).strip()
                
                category_match = re.search(r'@category\s+(.+?)(?:\n|$)', content)
                if category_match:
                    self.category = category_match.group(1).strip()
                
                # Also check for /* */ style description
                block_match = re.search(r'/\*\s*\n\s*\*\s*(.+?)\n', content)
                if block_match and self.description == "No description available":
                    self.description = block_match.group(1).strip('* ')
            
            # Python-style docstrings
            elif self.type == 'python':
                # Triple quotes docstring
                docstring_match = re.search(r'"""(.+?)"""', content, re.DOTALL)
                if docstring_match:
                    lines = docstring_match.group(1).strip().split('\n')
                    if lines:
                        self.description = lines[0].strip()
                
                # Look for # @metadata comments
                for line in content.split('\n'):
                    if line.strip().startswith('# @author'):
                        self.author = line.split('@author', 1)[1].strip()
                    elif line.strip().startswith('# @category'):
                        self.category = line.split('@category', 1)[1].strip()
                    elif line.strip().startswith('# @version'):
                        self.version = line.split('@version', 1)[1].strip()
            
            # Extract tags from description or special tag line
            tag_match = re.search(r'@tags?\s+(.+?)(?:\n|$)', content)
            if tag_match:
                self.tags = [t.strip() for t in tag_match.group(1).split(',')]
            
        except Exception as e:
            logger.warning(f"Failed to extract metadata from {self.filename}: {e}")
    
    def _validate(self):
        """Validate the script for basic requirements."""
        self.validation_errors = []
        
        try:
            with open(self.path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            if self.type == 'java':
                # Check for required imports
                if 'ghidra.app.script.GhidraScript' not in content:
                    self.validation_errors.append("Missing GhidraScript import")
                
                # Check for class extending GhidraScript
                if not re.search(r'class\s+\w+\s+extends\s+GhidraScript', content):
                    self.validation_errors.append("Class must extend GhidraScript")
                
                # Check for run() method
                if not re.search(r'public\s+void\s+run\s*\(\s*\)', content):
                    self.validation_errors.append("Missing public void run() method")
            
            elif self.type == 'python':
                # Python scripts are more flexible, just check if it's not empty
                if len(content.strip()) < 10:
                    self.validation_errors.append("Script appears to be empty")
            
            self.is_valid = len(self.validation_errors) == 0
            
        except Exception as e:
            self.validation_errors.append(f"Failed to validate: {e}")
            self.is_valid = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert script info to dictionary."""
        return {
            'path': self.path,
            'filename': self.filename,
            'name': self.name,
            'type': self.type,
            'description': self.description,
            'author': self.author,
            'category': self.category,
            'version': self.version,
            'tags': self.tags,
            'last_modified': self.last_modified.isoformat(),
            'size': self.size,
            'is_valid': self.is_valid,
            'validation_errors': self.validation_errors,
            'directory': self.directory
        }


class GhidraScriptManager:
    """Manages Ghidra script discovery, validation, and execution."""
    
    # Centralized script directory
    DEFAULT_SCRIPT_DIRS = [
        os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "scripts", "ghidra")
    ]
    
    # Script metadata cache file
    CACHE_FILE = "ghidra_scripts_cache.json"
    
    def __init__(self, additional_dirs: Optional[List[str]] = None):
        """
        Initialize the script manager.
        
        Args:
            additional_dirs: Extra directories to search for scripts
        """
        self.script_dirs = self.DEFAULT_SCRIPT_DIRS.copy()
        if additional_dirs:
            self.script_dirs.extend(additional_dirs)
        
        self.scripts: Dict[str, GhidraScript] = {}
        self.categories: Dict[str, List[str]] = {}
        self.last_scan = None
        
        # Create default directories if they don't exist
        self._create_default_directories()
        
        # Load cache if available
        self._load_cache()
    
    def _create_default_directories(self):
        """Create default script directories if they don't exist."""
        # Create main directory and subdirectories
        base_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "scripts", "ghidra")
        subdirs = ["default", "user", "examples", "community"]
        
        # Create base directory
        if not os.path.exists(base_dir):
            try:
                os.makedirs(base_dir, exist_ok=True)
                logger.info(f"Created script directory: {base_dir}")
            except Exception as e:
                logger.warning(f"Failed to create directory {base_dir}: {e}")
        
        # Create subdirectories
        for subdir in subdirs:
            dir_path = os.path.join(base_dir, subdir)
            if not os.path.exists(dir_path):
                try:
                    os.makedirs(dir_path, exist_ok=True)
                    logger.info(f"Created script subdirectory: {dir_path}")
                except Exception as e:
                    logger.warning(f"Failed to create directory {dir_path}: {e}")
    
    def scan_scripts(self, force_rescan: bool = False) -> Dict[str, GhidraScript]:
        """
        Scan all directories for Ghidra scripts.
        
        Args:
            force_rescan: Force rescan even if cache is recent
            
        Returns:
            Dictionary of script path -> GhidraScript objects
        """
        # Check if we need to rescan
        if not force_rescan and self.scripts and self.last_scan:
            # If scanned within last 5 minutes, use cache
            if (datetime.now() - self.last_scan).seconds < 300:
                return self.scripts
        
        logger.info("Scanning for Ghidra scripts...")
        self.scripts.clear()
        self.categories.clear()
        
        for script_dir in self.script_dirs:
            if not os.path.exists(script_dir):
                continue
            
            # Walk directory tree
            for root, dirs, files in os.walk(script_dir):
                # Skip hidden directories
                dirs[:] = [d for d in dirs if not d.startswith('.')]
                
                for file in files:
                    if file.endswith(('.java', '.py')):
                        # Skip backup files
                        if file.endswith(('.bak', '.tmp', '~')):
                            continue
                        
                        script_path = os.path.join(root, file)
                        try:
                            script = GhidraScript(script_path)
                            self.scripts[script_path] = script
                            
                            # Organize by category
                            if script.category not in self.categories:
                                self.categories[script.category] = []
                            self.categories[script.category].append(script_path)
                            
                            logger.debug(f"Found script: {script.name} ({script.category})")
                            
                        except Exception as e:
                            logger.warning(f"Failed to load script {file}: {e}")
        
        self.last_scan = datetime.now()
        logger.info(f"Found {len(self.scripts)} Ghidra scripts in {len(self.categories)} categories")
        
        # Save cache
        self._save_cache()
        
        return self.scripts
    
    def get_scripts_by_category(self) -> Dict[str, List[GhidraScript]]:
        """Get scripts organized by category."""
        if not self.scripts:
            self.scan_scripts()
        
        result = {}
        for category, paths in self.categories.items():
            result[category] = [self.scripts[path] for path in paths if path in self.scripts]
        
        return result
    
    def get_script(self, identifier: str) -> Optional[GhidraScript]:
        """
        Get a script by path, filename, or name.
        
        Args:
            identifier: Script path, filename, or name
            
        Returns:
            GhidraScript object or None
        """
        if not self.scripts:
            self.scan_scripts()
        
        # Try direct path lookup
        if identifier in self.scripts:
            return self.scripts[identifier]
        
        # Try by filename or name
        for path, script in self.scripts.items():
            if script.filename == identifier or script.name == identifier:
                return script
        
        return None
    
    def validate_script(self, script_path: str) -> Tuple[bool, List[str]]:
        """
        Validate a specific script.
        
        Args:
            script_path: Path to the script
            
        Returns:
            Tuple of (is_valid, error_messages)
        """
        try:
            script = GhidraScript(script_path)
            return script.is_valid, script.validation_errors
        except Exception as e:
            return False, [str(e)]
    
    def copy_script_for_execution(self, script: GhidraScript, destination_dir: str) -> str:
        """
        Copy script to destination directory for execution.
        
        Args:
            script: GhidraScript object
            destination_dir: Where to copy the script
            
        Returns:
            Path to the copied script
        """
        os.makedirs(destination_dir, exist_ok=True)
        dest_path = os.path.join(destination_dir, script.filename)
        
        # Copy the script
        shutil.copy2(script.path, dest_path)
        
        # If Java script, check for accompanying class files
        if script.type == 'java':
            class_file = script.name + ".class"
            class_path = os.path.join(script.directory, class_file)
            if os.path.exists(class_path):
                shutil.copy2(class_path, os.path.join(destination_dir, class_file))
        
        return dest_path
    
    def search_scripts(self, query: str) -> List[GhidraScript]:
        """
        Search scripts by name, description, or tags.
        
        Args:
            query: Search query
            
        Returns:
            List of matching scripts
        """
        if not self.scripts:
            self.scan_scripts()
        
        query_lower = query.lower()
        results = []
        
        for script in self.scripts.values():
            # Search in various fields
            if any(query_lower in field.lower() for field in [
                script.name,
                script.description,
                script.author,
                script.category,
                ' '.join(script.tags)
            ]):
                results.append(script)
        
        return results
    
    def add_user_script(self, source_path: str, category: str = "User Scripts") -> Optional[GhidraScript]:
        """
        Add a user script to the user scripts directory.
        
        Args:
            source_path: Path to the script to add
            category: Category for the script
            
        Returns:
            GhidraScript object if successful
        """
        base_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "scripts", "ghidra")
        user_dir = os.path.join(base_dir, "user")
        os.makedirs(user_dir, exist_ok=True)
        
        filename = os.path.basename(source_path)
        dest_path = os.path.join(user_dir, filename)
        
        # Check if already exists
        if os.path.exists(dest_path):
            base, ext = os.path.splitext(filename)
            counter = 1
            while os.path.exists(dest_path):
                filename = f"{base}_{counter}{ext}"
                dest_path = os.path.join(user_dir, filename)
                counter += 1
        
        try:
            # Copy the script
            shutil.copy2(source_path, dest_path)
            
            # Create and validate script object
            script = GhidraScript(dest_path)
            if not script.is_valid:
                os.remove(dest_path)
                raise ValueError(f"Invalid script: {', '.join(script.validation_errors)}")
            
            # Add to our collection
            self.scripts[dest_path] = script
            if category not in self.categories:
                self.categories[category] = []
            self.categories[category].append(dest_path)
            
            # Save cache
            self._save_cache()
            
            logger.info(f"Added user script: {script.name}")
            return script
            
        except Exception as e:
            logger.error(f"Failed to add user script: {e}")
            if os.path.exists(dest_path):
                os.remove(dest_path)
            return None
    
    def _load_cache(self):
        """Load script cache from disk."""
        cache_path = os.path.join("cache", self.CACHE_FILE)
        if not os.path.exists(cache_path):
            return
        
        try:
            with open(cache_path, 'r') as f:
                data = json.load(f)
            
            # Check cache version
            if data.get('version', 1) != 2:
                return
            
            # Load scripts
            for script_data in data.get('scripts', []):
                path = script_data['path']
                if os.path.exists(path):
                    # Check if file hasn't changed
                    mtime = os.path.getmtime(path)
                    cached_mtime = datetime.fromisoformat(script_data['last_modified']).timestamp()
                    
                    if abs(mtime - cached_mtime) < 1:  # Within 1 second
                        # Use cached data
                        script = GhidraScript(path)
                        script.description = script_data.get('description', script.description)
                        script.author = script_data.get('author', script.author)
                        script.category = script_data.get('category', script.category)
                        script.tags = script_data.get('tags', script.tags)
                        
                        self.scripts[path] = script
                        if script.category not in self.categories:
                            self.categories[script.category] = []
                        self.categories[script.category].append(path)
            
            self.last_scan = datetime.fromisoformat(data.get('last_scan', datetime.now().isoformat()))
            logger.info(f"Loaded {len(self.scripts)} scripts from cache")
            
        except Exception as e:
            logger.warning(f"Failed to load script cache: {e}")
    
    def _save_cache(self):
        """Save script cache to disk."""
        cache_dir = "cache"
        os.makedirs(cache_dir, exist_ok=True)
        cache_path = os.path.join(cache_dir, self.CACHE_FILE)
        
        try:
            data = {
                'version': 2,
                'last_scan': self.last_scan.isoformat() if self.last_scan else None,
                'scripts': [script.to_dict() for script in self.scripts.values()]
            }
            
            with open(cache_path, 'w') as f:
                json.dump(data, f, indent=2)
            
        except Exception as e:
            logger.warning(f"Failed to save script cache: {e}")


# Global instance
_script_manager: Optional[GhidraScriptManager] = None


def get_script_manager() -> GhidraScriptManager:
    """Get or create the global script manager instance."""
    global _script_manager
    if _script_manager is None:
        _script_manager = GhidraScriptManager()
    return _script_manager


def add_script_directory(directory: str):
    """Add a directory to search for scripts."""
    manager = get_script_manager()
    if directory not in manager.script_dirs:
        manager.script_dirs.append(directory)
        logger.info(f"Added script directory: {directory}")