"""
Enhanced Installation Directory Discovery for Intellicrack.

This module provides comprehensive installation directory discovery capabilities
using markers, heuristics, and directory structure analysis to identify software
installation roots and key subdirectories.

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

import logging
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

IS_WINDOWS = sys.platform.startswith('win')
IS_LINUX = sys.platform.startswith('linux')
IS_MACOS = sys.platform.startswith('darwin')


@dataclass
class InstallationMarker:
    """Information about an installation marker file."""
    file_name: str
    pattern: str
    weight: float
    description: str
    marker_type: str


@dataclass
class DirectoryStructure:
    """Information about directory structure and its purpose."""
    name: str
    patterns: List[str]
    weight: float
    description: str
    structure_type: str


@dataclass
class InstallationCandidate:
    """Candidate installation directory with confidence scoring."""
    path: str
    confidence_score: float
    markers_found: List[InstallationMarker]
    directories_found: List[DirectoryStructure]
    total_size: int
    file_count: int
    executable_count: int
    depth_level: int
    is_root_candidate: bool
    parent_confidence: float
    subdirectories: Dict[str, 'InstallationCandidate']


class InstallationDiscoveryEngine:
    """Engine for discovering software installation directories using markers and heuristics."""

    # Installation marker definitions with weights
    INSTALLATION_MARKERS = [
        # Uninstaller markers (highest confidence)
        InstallationMarker("unins000.exe", r"unins\d{3}\.exe", 10.0, "Inno Setup Uninstaller", "uninstaller"),
        InstallationMarker("uninstall.exe", r"uninstall\.exe", 9.5, "Generic Uninstaller", "uninstaller"),
        InstallationMarker("uninst.exe", r"uninst\.exe", 9.0, "Legacy Uninstaller", "uninstaller"),
        InstallationMarker("unwise.exe", r"unwise\.exe", 9.0, "Wise Uninstaller", "uninstaller"),
        InstallationMarker("st6unst.exe", r"st6unst\.exe", 8.5, "Setup Factory Uninstaller", "uninstaller"),
        
        # License files (high confidence)
        InstallationMarker("license.txt", r"licen[sc]e\.(txt|rtf|pdf|htm)", 8.0, "License Agreement", "legal"),
        InstallationMarker("eula.txt", r"eula\.(txt|rtf|pdf|htm)", 8.5, "End User License Agreement", "legal"),
        InstallationMarker("copying.txt", r"copying\.(txt|rtf|pdf)", 7.5, "GNU Copying License", "legal"),
        InstallationMarker("terms.txt", r"terms\.(txt|rtf|pdf|htm)", 7.0, "Terms of Service", "legal"),
        InstallationMarker("copyright.txt", r"copyright\.(txt|rtf|pdf)", 7.0, "Copyright Notice", "legal"),
        
        # Version and product info (medium-high confidence)
        InstallationMarker("version.txt", r"version\.(txt|ini|dat)", 6.5, "Version Information", "version"),
        InstallationMarker("readme.txt", r"readme\.(txt|rtf|md|htm)", 6.0, "Read Me File", "documentation"),
        InstallationMarker("product.inf", r"product\.(inf|ini)", 7.0, "Product Information", "product"),
        InstallationMarker("version.ini", r"version\.ini", 6.5, "Version Configuration", "version"),
        
        # Configuration markers (medium confidence)
        InstallationMarker("config.ini", r"config\.(ini|cfg|conf)", 5.5, "Configuration File", "config"),
        InstallationMarker("settings.ini", r"settings\.(ini|cfg|dat)", 5.0, "Settings File", "config"),
        InstallationMarker("preferences.cfg", r"preferences\.(cfg|ini|plist)", 5.0, "Preferences File", "config"),
        
        # Registry files (Windows-specific, medium confidence)
        InstallationMarker("install.reg", r"install\.reg", 6.0, "Registry Installation", "registry"),
        InstallationMarker("uninstall.reg", r"uninstall\.reg", 6.5, "Registry Uninstallation", "registry"),
        
        # Installer artifacts (medium confidence)
        InstallationMarker("setup.exe", r"setup\.exe", 5.5, "Setup Executable", "installer"),
        InstallationMarker("install.exe", r"install\.exe", 5.5, "Install Executable", "installer"),
        InstallationMarker("msiexec.exe", r"msiexec\.exe", 4.0, "MSI Executor", "installer"),
        
        # Application-specific markers (variable confidence)
        InstallationMarker("manifest.xml", r"manifest\.(xml|json)", 4.5, "Application Manifest", "manifest"),
        InstallationMarker("app.config", r"app\.config", 4.0, ".NET Application Config", "config"),
        InstallationMarker("Info.plist", r"Info\.plist", 7.0, "macOS Info Property List", "macos"),
        
        # Development/Debug markers (lower confidence but important)
        InstallationMarker("debug.log", r"debug\.(log|txt)", 3.0, "Debug Log File", "debug"),
        InstallationMarker("error.log", r"error\.(log|txt)", 3.0, "Error Log File", "debug"),
        
        # Licensing/Protection markers (high importance for Intellicrack)
        InstallationMarker("license.key", r"licen[sc]e\.(key|lic|dat)", 9.0, "License Key File", "licensing"),
        InstallationMarker("activation.dat", r"activation\.(dat|bin|key)", 8.5, "Activation Data", "licensing"),
        InstallationMarker("serial.txt", r"serial\.(txt|dat|key)", 8.0, "Serial Number", "licensing"),
        InstallationMarker("unlock.key", r"unlock\.(key|dat|bin)", 8.0, "Unlock Key", "licensing"),
        
        # Protection scheme markers
        InstallationMarker("hasp_rt.exe", r"hasp_.*\.exe", 9.5, "HASP Protection", "protection"),
        InstallationMarker("sentinel.sys", r"sentinel.*\.(sys|exe|dll)", 9.5, "Sentinel Protection", "protection"),
        InstallationMarker("wibu.dll", r"wibu.*\.(dll|sys|exe)", 9.5, "WIBU Protection", "protection"),
        InstallationMarker("flexlm.exe", r"flexlm.*\.exe", 9.0, "FlexLM License Manager", "protection"),
        InstallationMarker("codemeter.exe", r"codemeter.*\.exe", 9.0, "CodeMeter Protection", "protection"),
    ]

    # Key directory structures with patterns and weights
    DIRECTORY_STRUCTURES = [
        # Core application directories
        DirectoryStructure("bin", [r"^bin$"], 8.0, "Binary/Executable Directory", "executable"),
        DirectoryStructure("lib", [r"^lib$", r"^libs$"], 7.5, "Library Directory", "library"),
        DirectoryStructure("data", [r"^data$"], 6.5, "Data Directory", "data"),
        DirectoryStructure("resources", [r"^resources$", r"^res$"], 6.0, "Resources Directory", "resource"),
        DirectoryStructure("assets", [r"^assets$"], 6.0, "Assets Directory", "resource"),
        
        # Plugin and extension directories
        DirectoryStructure("plugins", [r"^plugins$", r"^plugin$"], 7.0, "Plugins Directory", "plugin"),
        DirectoryStructure("extensions", [r"^extensions$", r"^ext$"], 6.5, "Extensions Directory", "plugin"),
        DirectoryStructure("addons", [r"^addons$", r"^addon$"], 6.5, "Add-ons Directory", "plugin"),
        DirectoryStructure("modules", [r"^modules$", r"^module$"], 6.0, "Modules Directory", "plugin"),
        
        # Configuration directories
        DirectoryStructure("config", [r"^config$", r"^conf$", r"^cfg$"], 6.0, "Configuration Directory", "config"),
        DirectoryStructure("settings", [r"^settings$"], 5.5, "Settings Directory", "config"),
        DirectoryStructure("preferences", [r"^preferences$", r"^prefs$"], 5.5, "Preferences Directory", "config"),
        
        # Documentation directories
        DirectoryStructure("docs", [r"^docs?$", r"^documentation$"], 5.0, "Documentation Directory", "docs"),
        DirectoryStructure("help", [r"^help$"], 5.0, "Help Directory", "docs"),
        DirectoryStructure("manual", [r"^manual$", r"^manuals$"], 5.0, "Manual Directory", "docs"),
        
        # Language and localization
        DirectoryStructure("lang", [r"^lang$", r"^languages?$"], 5.5, "Language Directory", "localization"),
        DirectoryStructure("locale", [r"^locale$", r"^locales$"], 5.5, "Locale Directory", "localization"),
        DirectoryStructure("i18n", [r"^i18n$"], 5.5, "Internationalization Directory", "localization"),
        
        # Media and UI directories
        DirectoryStructure("images", [r"^images?$", r"^img$"], 4.5, "Images Directory", "media"),
        DirectoryStructure("icons", [r"^icons?$"], 4.5, "Icons Directory", "media"),
        DirectoryStructure("sounds", [r"^sounds?$", r"^audio$"], 4.0, "Audio Directory", "media"),
        DirectoryStructure("themes", [r"^themes?$"], 4.5, "Themes Directory", "ui"),
        DirectoryStructure("skins", [r"^skins?$"], 4.5, "Skins Directory", "ui"),
        
        # Cache and temporary directories
        DirectoryStructure("cache", [r"^cache$"], 3.0, "Cache Directory", "cache"),
        DirectoryStructure("temp", [r"^temp$", r"^tmp$"], 3.0, "Temporary Directory", "cache"),
        DirectoryStructure("logs", [r"^logs?$"], 3.5, "Log Directory", "logs"),
        
        # Database directories
        DirectoryStructure("database", [r"^database$", r"^db$"], 5.0, "Database Directory", "database"),
        DirectoryStructure("sqlite", [r"^sqlite$"], 4.5, "SQLite Directory", "database"),
        
        # Security and licensing directories (high importance)
        DirectoryStructure("security", [r"^security$"], 8.0, "Security Directory", "security"),
        DirectoryStructure("licensing", [r"^licen[sc]ing$"], 8.5, "Licensing Directory", "security"),
        DirectoryStructure("protection", [r"^protection$"], 8.5, "Protection Directory", "security"),
        DirectoryStructure("keys", [r"^keys?$"], 7.5, "Keys Directory", "security"),
        DirectoryStructure("certificates", [r"^certificates?$", r"^certs?$"], 7.0, "Certificates Directory", "security"),
        
        # Development directories (when found in installed software)
        DirectoryStructure("src", [r"^src$", r"^source$"], 3.5, "Source Code Directory", "development"),
        DirectoryStructure("include", [r"^include$"], 4.0, "Include Directory", "development"),
        DirectoryStructure("headers", [r"^headers?$"], 4.0, "Headers Directory", "development"),
        
        # Platform-specific directories
        DirectoryStructure("win32", [r"^win32$", r"^windows$"], 5.0, "Windows Directory", "platform"),
        DirectoryStructure("win64", [r"^win64$", r"^x64$"], 5.0, "Windows 64-bit Directory", "platform"),
        DirectoryStructure("linux", [r"^linux$"], 5.0, "Linux Directory", "platform"),
        DirectoryStructure("macos", [r"^macos$", r"^darwin$"], 5.0, "macOS Directory", "platform"),
    ]

    # Common installation patterns by platform
    PLATFORM_INSTALLATION_PATTERNS = {
        'windows': [
            r"C:\\Program Files\\.*",
            r"C:\\Program Files \(x86\)\\.*", 
            r"C:\\ProgramData\\.*",
            r"C:\\Users\\.*\\AppData\\Local\\.*",
            r"C:\\Users\\.*\\AppData\\Roaming\\.*",
            r"C:\\.*",  # Root drive installations
        ],
        'linux': [
            r"/opt/.*",
            r"/usr/local/.*",
            r"/usr/share/.*", 
            r"/home/.*/\..*",  # Hidden directories in home
            r"/home/.*",
        ],
        'macos': [
            r"/Applications/.*",
            r"/Users/.*/Applications/.*",
            r"/opt/.*",
            r"/usr/local/.*",
        ]
    }

    def __init__(self, max_depth: int = 4, min_confidence: float = 2.0):
        """
        Initialize the installation discovery engine.
        
        Args:
            max_depth: Maximum depth to traverse when discovering
            min_confidence: Minimum confidence score for installation candidates
        """
        self.max_depth = max_depth
        self.min_confidence = min_confidence
        self.logger = logger
        self._marker_cache = {}
        self._directory_cache = {}

    def discover_installation_roots(self, start_path: str, 
                                  include_subdirs: bool = True) -> List[InstallationCandidate]:
        """
        Discover installation root directories starting from a given path.
        
        Args:
            start_path: Starting path for discovery
            include_subdirs: Whether to include subdirectory analysis
            
        Returns:
            List of installation candidates sorted by confidence
        """
        candidates = []
        start_path = Path(start_path)
        
        if not start_path.exists():
            self.logger.warning(f"Start path does not exist: {start_path}")
            return candidates
            
        self.logger.info(f"Starting installation discovery from: {start_path}")
        
        try:
            # Analyze the starting directory itself
            root_candidate = self._analyze_directory(start_path, 0, True)
            if root_candidate and root_candidate.confidence_score >= self.min_confidence:
                candidates.append(root_candidate)
            
            # Traverse subdirectories if requested
            if include_subdirs:
                candidates.extend(self._traverse_directory_tree(start_path, 1))
                
        except Exception as e:
            self.logger.error(f"Error during installation discovery: {e}")
            
        # Sort by confidence score (highest first)
        candidates.sort(key=lambda c: c.confidence_score, reverse=True)
        
        # Remove duplicates and handle parent-child relationships
        candidates = self._deduplicate_candidates(candidates)
        
        self.logger.info(f"Found {len(candidates)} installation candidates")
        return candidates

    def analyze_installation_markers(self, directory_path: str) -> Tuple[List[InstallationMarker], float]:
        """
        Analyze a directory for installation markers and calculate confidence.
        
        Args:
            directory_path: Path to analyze
            
        Returns:
            Tuple of (found_markers, total_confidence_score)
        """
        directory_path = Path(directory_path)
        found_markers = []
        total_confidence = 0.0
        
        if not directory_path.exists() or not directory_path.is_dir():
            return found_markers, total_confidence
            
        try:
            # Check cache first
            cache_key = str(directory_path.absolute())
            if cache_key in self._marker_cache:
                return self._marker_cache[cache_key]
                
            # Get all files in directory (non-recursive for markers)
            files = []
            try:
                files = [f.name.lower() for f in directory_path.iterdir() if f.is_file()]
            except (PermissionError, OSError) as e:
                self.logger.debug(f"Permission denied accessing {directory_path}: {e}")
                return found_markers, total_confidence
                
            # Check each marker pattern
            for marker in self.INSTALLATION_MARKERS:
                pattern = re.compile(marker.pattern, re.IGNORECASE)
                
                for file_name in files:
                    if pattern.search(file_name):
                        found_markers.append(marker)
                        
                        # Apply platform-specific weighting
                        weight_multiplier = self._get_platform_weight_multiplier(marker, directory_path)
                        adjusted_weight = marker.weight * weight_multiplier
                        total_confidence += adjusted_weight
                        
                        self.logger.debug(f"Found marker {marker.file_name} in {directory_path} "
                                        f"(weight: {adjusted_weight:.1f})")
                        break  # Only count each marker type once
                        
            # Cache the result
            result = (found_markers, total_confidence)
            self._marker_cache[cache_key] = result
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error analyzing markers in {directory_path}: {e}")
            return found_markers, total_confidence

    def analyze_directory_structure(self, directory_path: str) -> Tuple[List[DirectoryStructure], float]:
        """
        Analyze directory structure and identify key subdirectories.
        
        Args:
            directory_path: Path to analyze
            
        Returns:
            Tuple of (found_structures, confidence_boost)
        """
        directory_path = Path(directory_path)
        found_structures = []
        structure_confidence = 0.0
        
        if not directory_path.exists() or not directory_path.is_dir():
            return found_structures, structure_confidence
            
        try:
            # Check cache first
            cache_key = str(directory_path.absolute())
            if cache_key in self._directory_cache:
                return self._directory_cache[cache_key]
                
            # Get subdirectories
            subdirs = []
            try:
                subdirs = [d.name.lower() for d in directory_path.iterdir() if d.is_dir()]
            except (PermissionError, OSError) as e:
                self.logger.debug(f"Permission denied accessing subdirs in {directory_path}: {e}")
                return found_structures, structure_confidence
                
            # Check each structure pattern
            for structure in self.DIRECTORY_STRUCTURES:
                for pattern in structure.patterns:
                    regex = re.compile(pattern, re.IGNORECASE)
                    
                    for subdir in subdirs:
                        if regex.match(subdir):
                            found_structures.append(structure)
                            
                            # Apply contextual weighting
                            context_multiplier = self._get_structure_context_multiplier(
                                structure, directory_path, subdirs
                            )
                            adjusted_weight = structure.weight * context_multiplier
                            structure_confidence += adjusted_weight
                            
                            self.logger.debug(f"Found structure {structure.name} in {directory_path} "
                                            f"(weight: {adjusted_weight:.1f})")
                            break  # Only count each structure type once
                            
            # Cache the result
            result = (found_structures, structure_confidence)
            self._directory_cache[cache_key] = result
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error analyzing directory structure in {directory_path}: {e}")
            return found_structures, structure_confidence

    def identify_key_subdirectories(self, installation_root: str) -> Dict[str, List[str]]:
        """
        Identify and categorize key subdirectories in an installation.
        
        Args:
            installation_root: Root installation directory
            
        Returns:
            Dictionary mapping category to list of subdirectory paths
        """
        categorized_dirs = {
            'executable': [],
            'library': [],
            'data': [],
            'config': [],
            'plugin': [],
            'resource': [],
            'security': [],
            'documentation': [],
            'localization': [],
            'media': [],
            'cache': [],
            'logs': [],
            'development': [],
            'platform': [],
            'other': []
        }
        
        installation_root = Path(installation_root)
        
        if not installation_root.exists() or not installation_root.is_dir():
            return categorized_dirs
            
        try:
            # Recursively analyze subdirectories
            for root, dirs, files in os.walk(installation_root):
                # Limit depth to prevent excessive traversal
                current_depth = len(Path(root).relative_to(installation_root).parts)
                if current_depth > self.max_depth:
                    dirs.clear()  # Prevent further traversal
                    continue
                    
                for dir_name in dirs:
                    dir_path = os.path.join(root, dir_name)
                    
                    # Find matching structure
                    category = self._categorize_directory(dir_name, dir_path)
                    categorized_dirs[category].append(dir_path)
                    
        except Exception as e:
            self.logger.error(f"Error identifying subdirectories in {installation_root}: {e}")
            
        return categorized_dirs

    def score_installation_confidence(self, directory_path: str, 
                                    markers: List[InstallationMarker],
                                    structures: List[DirectoryStructure],
                                    additional_factors: Dict[str, float] = None) -> float:
        """
        Calculate comprehensive confidence score for an installation directory.
        
        Args:
            directory_path: Path being evaluated
            markers: Found installation markers
            structures: Found directory structures
            additional_factors: Additional scoring factors
            
        Returns:
            Confidence score (0-100)
        """
        directory_path = Path(directory_path)
        
        # Base scores from markers and structures
        marker_score = sum(marker.weight for marker in markers)
        structure_score = sum(structure.weight for structure in structures)
        
        # Additional factors
        additional_score = 0.0
        if additional_factors:
            additional_score = sum(additional_factors.values())
            
        # Platform-specific adjustments
        platform_bonus = self._calculate_platform_bonus(directory_path)
        
        # Directory depth penalty (deeper = less likely to be root)
        depth_penalty = self._calculate_depth_penalty(directory_path)
        
        # Size and file count heuristics
        size_bonus = self._calculate_size_bonus(directory_path)
        
        # Executable presence bonus
        executable_bonus = self._calculate_executable_bonus(directory_path)
        
        # Calculate final score
        raw_score = (marker_score + structure_score + additional_score + 
                    platform_bonus + size_bonus + executable_bonus - depth_penalty)
        
        # Normalize to 0-100 scale with logarithmic scaling for high values
        if raw_score <= 0:
            return 0.0
        elif raw_score <= 10:
            return raw_score * 4  # Linear scaling up to 40
        elif raw_score <= 20:
            return 40 + (raw_score - 10) * 3  # 40-70 range
        elif raw_score <= 30:
            return 70 + (raw_score - 20) * 2  # 70-90 range
        else:
            return min(90 + (raw_score - 30) * 0.5, 100)  # 90-100 range with diminishing returns
            
    def handle_multiple_installations(self, candidates: List[InstallationCandidate]) -> List[InstallationCandidate]:
        """
        Handle cases where multiple installation roots are detected.
        
        Args:
            candidates: List of installation candidates
            
        Returns:
            Filtered and prioritized list of candidates
        """
        if len(candidates) <= 1:
            return candidates
            
        # Group by parent-child relationships
        grouped = self._group_by_hierarchy(candidates)
        
        # For each group, select the best candidate
        final_candidates = []
        
        for group in grouped:
            if len(group) == 1:
                final_candidates.extend(group)
            else:
                # Multiple candidates in same hierarchy
                # Choose based on confidence and other factors
                best_candidate = self._select_best_from_group(group)
                final_candidates.append(best_candidate)
                
        return sorted(final_candidates, key=lambda c: c.confidence_score, reverse=True)

    def _analyze_directory(self, directory_path: Path, depth: int, 
                          is_root: bool = False) -> Optional[InstallationCandidate]:
        """Analyze a single directory for installation characteristics."""
        try:
            # Check permissions and existence
            if not directory_path.exists() or not directory_path.is_dir():
                return None
                
            # Get basic directory info
            total_size = 0
            file_count = 0
            executable_count = 0
            
            try:
                for item in directory_path.iterdir():
                    if item.is_file():
                        file_count += 1
                        try:
                            total_size += item.stat().st_size
                            if self._is_executable(item):
                                executable_count += 1
                        except (OSError, PermissionError):
                            continue
            except (PermissionError, OSError) as e:
                self.logger.debug(f"Limited access to {directory_path}: {e}")
                
            # Analyze markers and structures
            markers, marker_confidence = self.analyze_installation_markers(str(directory_path))
            structures, structure_confidence = self.analyze_directory_structure(str(directory_path))
            
            # Calculate confidence score
            additional_factors = {
                'file_count_bonus': min(file_count / 100, 2.0),  # Bonus for having files
                'executable_bonus': min(executable_count * 0.5, 3.0),  # Bonus for executables
            }
            
            confidence_score = self.score_installation_confidence(
                str(directory_path), markers, structures, additional_factors
            )
            
            # Only create candidate if it meets minimum confidence
            if confidence_score < self.min_confidence:
                return None
                
            candidate = InstallationCandidate(
                path=str(directory_path),
                confidence_score=confidence_score,
                markers_found=markers,
                directories_found=structures,
                total_size=total_size,
                file_count=file_count,
                executable_count=executable_count,
                depth_level=depth,
                is_root_candidate=is_root,
                parent_confidence=0.0,
                subdirectories={}
            )
            
            return candidate
            
        except Exception as e:
            self.logger.error(f"Error analyzing directory {directory_path}: {e}")
            return None

    def _traverse_directory_tree(self, start_path: Path, current_depth: int) -> List[InstallationCandidate]:
        """Traverse directory tree and find installation candidates."""
        candidates = []
        
        if current_depth > self.max_depth:
            return candidates
            
        try:
            for item in start_path.iterdir():
                if item.is_dir():
                    # Analyze this directory
                    candidate = self._analyze_directory(item, current_depth)
                    if candidate:
                        candidates.append(candidate)
                        
                    # Recurse into subdirectory
                    if current_depth < self.max_depth:
                        sub_candidates = self._traverse_directory_tree(item, current_depth + 1)
                        candidates.extend(sub_candidates)
                        
        except (PermissionError, OSError) as e:
            self.logger.debug(f"Cannot traverse {start_path}: {e}")
            
        return candidates

    def _deduplicate_candidates(self, candidates: List[InstallationCandidate]) -> List[InstallationCandidate]:
        """Remove duplicate candidates and handle parent-child relationships."""
        if len(candidates) <= 1:
            return candidates
            
        # Sort by path length (parents first)
        candidates.sort(key=lambda c: len(c.path))
        
        filtered = []
        seen_paths = set()
        
        for candidate in candidates:
            candidate_path = Path(candidate.path)
            
            # Check if this is a subdirectory of an already seen path
            is_subdirectory = False
            for seen_path in seen_paths:
                try:
                    candidate_path.relative_to(seen_path)
                    is_subdirectory = True
                    break
                except ValueError:
                    continue
                    
            if not is_subdirectory:
                filtered.append(candidate)
                seen_paths.add(candidate_path)
                
        return filtered

    def _get_platform_weight_multiplier(self, marker: InstallationMarker, 
                                      directory_path: Path) -> float:
        """Get platform-specific weight multiplier for a marker."""
        multiplier = 1.0
        
        # Platform-specific marker adjustments
        if IS_WINDOWS:
            if marker.marker_type in ['uninstaller', 'registry']:
                multiplier = 1.2
            elif marker.file_name.endswith('.exe'):
                multiplier = 1.1
        elif IS_LINUX:
            if marker.marker_type in ['legal', 'documentation']:
                multiplier = 1.1
        elif IS_MACOS:
            if marker.marker_type == 'macos':
                multiplier = 1.3
                
        # Path-based adjustments
        path_str = str(directory_path).lower()
        
        if IS_WINDOWS:
            if 'program files' in path_str:
                multiplier *= 1.2
            elif 'programdata' in path_str:
                multiplier *= 1.1
        elif IS_LINUX:
            if path_str.startswith('/opt/'):
                multiplier *= 1.2
            elif path_str.startswith('/usr/local/'):
                multiplier *= 1.1
        elif IS_MACOS:
            if '/applications/' in path_str:
                multiplier *= 1.2
                
        return multiplier

    def _get_structure_context_multiplier(self, structure: DirectoryStructure,
                                        directory_path: Path, subdirs: List[str]) -> float:
        """Get context-based multiplier for directory structure weight."""
        multiplier = 1.0
        
        # Boost certain structures when found together
        structure_synergies = {
            'executable': ['lib', 'data', 'config'],
            'library': ['bin', 'include'],
            'security': ['licensing', 'keys', 'certificates'],
            'plugin': ['data', 'config'],
        }
        
        synergy_dirs = structure_synergies.get(structure.structure_type, [])
        synergy_count = sum(1 for synergy_dir in synergy_dirs if synergy_dir in subdirs)
        
        if synergy_count > 0:
            multiplier += synergy_count * 0.1
            
        # Penalize certain structures in wrong contexts
        if structure.structure_type == 'cache' and len(subdirs) < 3:
            multiplier *= 0.8  # Cache dirs in small installations are less significant
            
        return multiplier

    def _calculate_platform_bonus(self, directory_path: Path) -> float:
        """Calculate platform-specific location bonus."""
        path_str = str(directory_path).lower()
        
        if IS_WINDOWS:
            if 'program files' in path_str:
                return 2.0
            elif 'programdata' in path_str:
                return 1.5
            elif path_str.startswith('c:\\') and len(Path(path_str).parts) <= 3:
                return 1.0  # Direct C: drive installation
        elif IS_LINUX:
            if path_str.startswith('/opt/'):
                return 2.0
            elif path_str.startswith('/usr/local/'):
                return 1.5
            elif path_str.startswith('/usr/share/'):
                return 1.0
        elif IS_MACOS:
            if '/applications/' in path_str:
                return 2.0
            elif '/opt/' in path_str:
                return 1.5
                
        return 0.0

    def _calculate_depth_penalty(self, directory_path: Path) -> float:
        """Calculate penalty for directory depth."""
        try:
            # Count path components
            parts = directory_path.parts
            depth = len(parts)
            
            # Apply penalty for deep paths
            if depth <= 3:
                return 0.0
            elif depth <= 5:
                return (depth - 3) * 0.5
            else:
                return 1.0 + (depth - 5) * 0.3
        except Exception:
            return 0.0

    def _calculate_size_bonus(self, directory_path: Path) -> float:
        """Calculate bonus based on directory size heuristics."""
        try:
            # Quick size estimation (don't recurse deeply)
            total_size = 0
            file_count = 0
            
            for item in directory_path.iterdir():
                if item.is_file():
                    try:
                        total_size += item.stat().st_size
                        file_count += 1
                        
                        # Limit sampling to avoid performance issues
                        if file_count > 100:
                            break
                    except (OSError, PermissionError):
                        continue
                        
            # Size-based bonus (larger installations are more likely to be real)
            size_mb = total_size / (1024 * 1024)
            if size_mb > 100:
                return min(2.0, size_mb / 100)
            elif size_mb > 10:
                return size_mb / 50
            else:
                return 0.0
                
        except Exception:
            return 0.0

    def _calculate_executable_bonus(self, directory_path: Path) -> float:
        """Calculate bonus for presence of executable files."""
        try:
            executable_count = 0
            
            for item in directory_path.iterdir():
                if item.is_file() and self._is_executable(item):
                    executable_count += 1
                    
                    # Limit sampling
                    if executable_count >= 10:
                        break
                        
            return min(executable_count * 0.3, 2.0)
            
        except Exception:
            return 0.0

    def _is_executable(self, file_path: Path) -> bool:
        """Check if a file is likely an executable."""
        if IS_WINDOWS:
            return file_path.suffix.lower() in ['.exe', '.bat', '.cmd', '.com', '.scr']
        else:
            # Unix-like systems
            try:
                return os.access(file_path, os.X_OK)
            except (OSError, PermissionError):
                return False

    def _categorize_directory(self, dir_name: str, dir_path: str) -> str:
        """Categorize a directory based on its name and content."""
        dir_name_lower = dir_name.lower()
        
        # Check against known structure patterns
        for structure in self.DIRECTORY_STRUCTURES:
            for pattern in structure.patterns:
                if re.match(pattern, dir_name_lower, re.IGNORECASE):
                    return structure.structure_type
                    
        # Default category
        return 'other'

    def _group_by_hierarchy(self, candidates: List[InstallationCandidate]) -> List[List[InstallationCandidate]]:
        """Group candidates by parent-child hierarchy."""
        groups = []
        processed = set()
        
        for candidate in candidates:
            if candidate.path in processed:
                continue
                
            # Find all candidates in the same hierarchy
            hierarchy_group = [candidate]
            candidate_path = Path(candidate.path)
            
            for other_candidate in candidates:
                if other_candidate.path == candidate.path or other_candidate.path in processed:
                    continue
                    
                other_path = Path(other_candidate.path)
                
                # Check if they're in parent-child relationship
                try:
                    candidate_path.relative_to(other_path)
                    hierarchy_group.append(other_candidate)
                except ValueError:
                    try:
                        other_path.relative_to(candidate_path)
                        hierarchy_group.append(other_candidate)
                    except ValueError:
                        continue
                        
            # Mark all as processed
            for group_candidate in hierarchy_group:
                processed.add(group_candidate.path)
                
            groups.append(hierarchy_group)
            
        return groups

    def _select_best_from_group(self, group: List[InstallationCandidate]) -> InstallationCandidate:
        """Select the best candidate from a hierarchy group."""
        # Prefer candidates with higher confidence
        group.sort(key=lambda c: c.confidence_score, reverse=True)
        
        # If top candidates have similar confidence, prefer less deep ones
        best = group[0]
        for candidate in group[1:3]:  # Check top 3
            if (abs(candidate.confidence_score - best.confidence_score) < 2.0 and
                candidate.depth_level < best.depth_level):
                best = candidate
                
        return best


# Global instance for easy access
installation_discovery_engine = InstallationDiscoveryEngine()