#!/usr/bin/env python3
"""
Massive Real Licensing Data Collector

Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

Collects thousands of real licensing binaries from multiple comprehensive sources
to build a production-grade training dataset.
"""

import os
import sys
import json
import shutil
import hashlib
import logging
import requests
import subprocess
import threading
import time
import numpy as np
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Set
from collections import defaultdict
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)


class MassiveDataCollector:
    """Collect thousands of real licensing binaries for robust training"""
    
    def __init__(self, output_dir: str, target_samples: int = 5000):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.target_samples = target_samples
        
        # Create comprehensive category structure
        self.categories = {
            # Commercial software with different licensing types
            'commercial_trial_software': self.output_dir / 'commercial_trial_software',
            'commercial_licensed_full': self.output_dir / 'commercial_licensed_full',
            'commercial_node_locked': self.output_dir / 'commercial_node_locked',
            'commercial_floating_license': self.output_dir / 'commercial_floating_license',
            'commercial_subscription': self.output_dir / 'commercial_subscription',
            
            # Shareware and demo software
            'shareware_time_limited': self.output_dir / 'shareware_time_limited',
            'shareware_feature_limited': self.output_dir / 'shareware_feature_limited',
            'shareware_nagware': self.output_dir / 'shareware_nagware',
            
            # Protection schemes
            'flexlm_protected': self.output_dir / 'flexlm_protected',
            'sentinel_hasp_protected': self.output_dir / 'sentinel_hasp_protected',
            'codemeter_protected': self.output_dir / 'codemeter_protected',
            'dongle_protected': self.output_dir / 'dongle_protected',
            'software_passport': self.output_dir / 'software_passport',
            'custom_protection': self.output_dir / 'custom_protection',
            
            # Cracked/bypassed versions
            'cracked_software': self.output_dir / 'cracked_software',
            'keygen_tools': self.output_dir / 'keygen_tools',
            'patch_tools': self.output_dir / 'patch_tools',
            'license_bypass_tools': self.output_dir / 'license_bypass_tools',
            
            # Open source with licensing checks
            'opensource_license_check': self.output_dir / 'opensource_license_check',
            'opensource_commercial_dual': self.output_dir / 'opensource_commercial_dual',
            
            # System and framework licensing
            'system_licensing_components': self.output_dir / 'system_licensing_components',
            'framework_licensing': self.output_dir / 'framework_licensing',
            
            # No licensing (control group)
            'no_licensing_opensource': self.output_dir / 'no_licensing_opensource',
            'no_licensing_system': self.output_dir / 'no_licensing_system'
        }
        
        for category_dir in self.categories.values():
            category_dir.mkdir(exist_ok=True)
        
        # Comprehensive software vendor database
        self.software_vendors = {
            'cad_engineering': {
                'autodesk': ['AutoCAD', 'Maya', '3ds Max', 'Revit', 'Inventor', 'Fusion 360'],
                'solidworks': ['SolidWorks', 'PDM', 'Simulation', 'Composer'],
                'ansys': ['Fluent', 'Maxwell', 'HFSS', 'Mechanical', 'CFX'],
                'bentley': ['MicroStation', 'STAAD', 'RAM', 'OpenRoads'],
                'ptc': ['Creo', 'Windchill', 'ThingWorx', 'Mathcad'],
                'siemens': ['NX', 'Solid Edge', 'Teamcenter', 'Simcenter']
            },
            'creative_media': {
                'adobe': ['Photoshop', 'Illustrator', 'After Effects', 'Premiere Pro', 'InDesign'],
                'corel': ['CorelDRAW', 'PaintShop Pro', 'VideoStudio'],
                'maxon': ['Cinema 4D', 'BodyPaint 3D', 'TeamRender'],
                'foundry': ['Nuke', 'Mari', 'Modo', 'Katana']
            },
            'development_tools': {
                'jetbrains': ['IntelliJ IDEA', 'PyCharm', 'WebStorm', 'ReSharper'],
                'microsoft': ['Visual Studio', 'SQL Server', 'Office', 'Teams'],
                'embarcadero': ['Delphi', 'C++Builder', 'RAD Studio'],
                'unity': ['Unity Pro', 'Unity Enterprise'],
                'epic': ['Unreal Engine']
            },
            'scientific_analysis': {
                'mathworks': ['MATLAB', 'Simulink', 'Toolboxes'],
                'wolfram': ['Mathematica', 'Wolfram Alpha Pro'],
                'sas': ['SAS Base', 'SAS Enterprise'],
                'spss': ['SPSS Statistics', 'SPSS Modeler'],
                'origin': ['OriginPro', 'OriginLab']
            },
            'security_backup': {
                'symantec': ['Norton', 'Endpoint Protection', 'Backup Exec'],
                'kaspersky': ['Anti-Virus', 'Internet Security', 'Endpoint Security'],
                'acronis': ['True Image', 'Backup & Recovery', 'Cyber Protect'],
                'malwarebytes': ['Premium', 'Endpoint Protection'],
                'mcafee': ['Total Protection', 'Endpoint Security']
            },
            'virtualization': {
                'vmware': ['Workstation Pro', 'vSphere', 'vCenter', 'Horizon'],
                'parallels': ['Desktop', 'RAS', 'Toolbox'],
                'citrix': ['XenApp', 'XenDesktop', 'NetScaler']
            },
            'productivity': {
                'microsoft': ['Office 365', 'Project', 'Visio', 'Publisher'],
                'corel': ['WordPerfect Office', 'Presentations'],
                'mindjet': ['MindManager'],
                'techsmith': ['Camtasia', 'Snagit']
            }
        }
        
        # GitHub repositories with licensing examples
        self.github_licensing_repos = [
            'flexlm/flexlm-examples',
            'sentinel/hasp-examples', 
            'wibu/codemeter-samples',
            'keygen-tools/license-crackers',
            'protection-research/licensing-analysis',
            'commercial-software/trial-versions',
            'licensing-systems/implementations',
            'software-protection/analysis-tools',
            'reverse-engineering/license-bypass',
            'security-research/protection-analysis'
        ]
        
        # Download sites for trial software
        self.trial_download_sites = [
            'https://download.cnet.com',
            'https://www.softpedia.com', 
            'https://filehippo.com',
            'https://www.majorgeeks.com',
            'https://sourceforge.net',
            'https://www.fosshub.com'
        ]
        
        # Statistics
        self.collection_stats = defaultdict(int)
        self.collected_hashes = set()
        
    def collect_massive_dataset(self) -> Dict[str, int]:
        """Collect comprehensive licensing dataset with thousands of samples"""
        logger.info(f"Starting massive data collection targeting {self.target_samples} samples...")
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            
            # 1. Collect from installed software
            futures.append(executor.submit(self._collect_installed_software))
            
            # 2. Collect from system directories
            futures.append(executor.submit(self._collect_system_binaries))
            
            # 3. Collect from package managers
            futures.append(executor.submit(self._collect_package_manager_software))
            
            # 4. Collect from GitHub releases
            futures.append(executor.submit(self._collect_github_releases))
            
            # 5. Collect from download sites
            futures.append(executor.submit(self._collect_download_sites))
            
            # 6. Collect from vendor websites
            futures.append(executor.submit(self._collect_vendor_trials))
            
            # 7. Generate licensing variations
            futures.append(executor.submit(self._generate_licensing_variations))
            
            # Wait for all collection tasks
            for future in as_completed(futures):
                try:
                    result = future.result()
                    logger.info(f"Collection task completed: {result}")
                except Exception as e:
                    logger.error(f"Collection task failed: {e}")
        
        # 8. Augment dataset with variations
        self._augment_dataset()
        
        # 9. Create comprehensive metadata
        self._create_comprehensive_metadata()
        
        total_collected = sum(self.collection_stats.values())
        logger.info(f"Massive data collection complete: {total_collected} samples collected")
        
        return dict(self.collection_stats)
    
    def _collect_installed_software(self) -> int:
        """Collect from already installed software"""
        collected = 0
        
        # Windows installation directories
        windows_dirs = [
            r"C:\Program Files",
            r"C:\Program Files (x86)",
            r"C:\ProgramData",
            r"C:\Users\Public\Desktop"
        ]
        
        # Linux installation directories  
        linux_dirs = [
            "/opt",
            "/usr/local/bin",
            "/usr/share",
            "/var/lib",
            "/home"
        ]
        
        search_dirs = []
        
        # Add existing directories
        for dir_path in windows_dirs + linux_dirs:
            if os.path.exists(dir_path):
                search_dirs.append(dir_path)
        
        # Search through installation directories
        for search_dir in search_dirs:
            try:
                collected += self._scan_directory_comprehensive(search_dir, max_depth=3)
            except Exception as e:
                logger.debug(f"Error scanning {search_dir}: {e}")
        
        self.collection_stats['installed_software'] = collected
        return collected
    
    def _scan_directory_comprehensive(self, directory: str, max_depth: int = 2) -> int:
        """Comprehensively scan directory for licensing binaries"""
        collected = 0
        current_depth = 0
        
        try:
            for root, dirs, files in os.walk(directory):
                # Control recursion depth
                level = root.replace(directory, '').count(os.sep)
                if level >= max_depth:
                    dirs[:] = []  # Don't recurse further
                    continue
                
                # Skip system directories to avoid issues
                if any(skip in root.lower() for skip in ['system32', 'syswow64', 'winsxs', 'temp', 'cache']):
                    continue
                
                for file in files:
                    if self._is_potential_licensing_binary(file):
                        file_path = os.path.join(root, file)
                        
                        try:
                            if self._analyze_and_categorize_binary(file_path):
                                collected += 1
                                
                                # Stop if we've collected enough from this directory
                                if collected > 100:  # Limit per directory
                                    return collected
                        except Exception as e:
                            logger.debug(f"Error analyzing {file_path}: {e}")
                            continue
        
        except (PermissionError, OSError) as e:
            logger.debug(f"Permission error scanning {directory}: {e}")
        
        return collected
    
    def _is_potential_licensing_binary(self, filename: str) -> bool:
        """Check if file might contain licensing logic"""
        filename_lower = filename.lower()
        
        # File extensions that might contain licensing logic
        licensing_extensions = ['.exe', '.dll', '.so', '.dylib', '.app', '.msi']
        if not any(filename_lower.endswith(ext) for ext in licensing_extensions):
            return False
        
        # Licensing indicators in filename
        licensing_indicators = [
            'license', 'licen', 'serial', 'key', 'activation', 'register',
            'trial', 'demo', 'eval', 'crack', 'patch', 'keygen',
            'flexlm', 'hasp', 'sentinel', 'dongle', 'protection',
            'setup', 'install', 'uninstall', 'updater'
        ]
        
        # Vendor-specific indicators
        vendor_indicators = [
            'autodesk', 'adobe', 'microsoft', 'vmware', 'jetbrains',
            'mathworks', 'ansys', 'solidworks', 'corel', 'symantec'
        ]
        
        # Check filename for indicators
        return any(indicator in filename_lower for indicator in licensing_indicators + vendor_indicators)
    
    def _analyze_and_categorize_binary(self, file_path: str) -> bool:
        """Analyze binary and categorize it appropriately"""
        try:
            # Check if already processed
            file_hash = self._calculate_file_hash(file_path)
            if file_hash in self.collected_hashes:
                return False
            
            # Quick licensing logic check
            if not self._has_licensing_indicators(file_path):
                # Only collect some non-licensing samples for control group
                if np.random.random() < 0.1:  # 10% chance
                    category = 'no_licensing_system'
                else:
                    return False
            else:
                # Determine licensing category based on analysis
                category = self._determine_licensing_category(file_path)
            
            # Copy to appropriate category
            if self._copy_to_category(file_path, category, file_hash):
                self.collected_hashes.add(file_hash)
                return True
        
        except Exception as e:
            logger.debug(f"Error categorizing {file_path}: {e}")
        
        return False
    
    def _has_licensing_indicators(self, file_path: str) -> bool:
        """Enhanced check for licensing indicators"""
        try:
            with open(file_path, 'rb') as f:
                # Read larger sample for better detection
                data = f.read(2 * 1024 * 1024)  # 2MB
            
            # Convert to searchable format
            data_lower = data.lower()
            
            # Comprehensive licensing indicators
            licensing_patterns = [
                # Basic licensing terms
                b'license', b'licence', b'licensed', b'licensing',
                b'serial', b'product key', b'activation', b'registration',
                b'trial', b'expire', b'evaluation', b'demo',
                
                # Protection schemes
                b'flexlm', b'lmgrd', b'hasp', b'sentinel', b'safenet',
                b'codemeter', b'wibu', b'armadillo', b'asprotect',
                b'themida', b'winlicense', b'securom', b'safedisc',
                
                # Licensing APIs
                b'cryptacquirecontext', b'cryptencrypt', b'regqueryvalue',
                b'regsetvalue', b'getsystemtime', b'getcomputername',
                b'getvolumeinfo', b'internetopen', b'httpsendrequest',
                
                # Common licensing strings
                b'days remaining', b'trial period', b'unlock code',
                b'hardware id', b'machine code', b'node locked',
                b'floating license', b'concurrent users',
                
                # Crack/bypass indicators
                b'crack', b'patch', b'keygen', b'bypass', b'reset trial',
                b'remove trial', b'unlimited', b'full version'
            ]
            
            # Count matches
            matches = sum(1 for pattern in licensing_patterns if pattern in data_lower)
            
            # Require multiple indicators for higher confidence
            return matches >= 3
        
        except Exception:
            return False
    
    def _determine_licensing_category(self, file_path: str) -> str:
        """Determine specific licensing category based on detailed analysis"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read(1024 * 1024).lower()
            
            filename = os.path.basename(file_path).lower()
            
            # Category determination logic
            if b'flexlm' in data or b'lmgrd' in data:
                return 'flexlm_protected'
            elif b'hasp' in data or b'sentinel' in data:
                return 'sentinel_hasp_protected' 
            elif b'codemeter' in data or b'wibu' in data:
                return 'codemeter_protected'
            elif b'dongle' in data or b'hardware key' in data:
                return 'dongle_protected'
            elif b'armadillo' in data or b'asprotect' in data:
                return 'software_passport'
            elif any(term in data for term in [b'crack', b'patch', b'keygen']):
                if 'keygen' in filename:
                    return 'keygen_tools'
                elif 'patch' in filename:
                    return 'patch_tools'
                else:
                    return 'cracked_software'
            elif b'trial' in data or b'demo' in data or b'evaluation' in data:
                if b'time' in data or b'days' in data or b'expire' in data:
                    return 'shareware_time_limited'
                elif b'feature' in data or b'limited' in data:
                    return 'shareware_feature_limited'
                else:
                    return 'commercial_trial_software'
            elif b'subscription' in data or b'monthly' in data or b'annual' in data:
                return 'commercial_subscription'
            elif b'node' in data or b'machine' in data or b'hardware' in data:
                return 'commercial_node_locked'
            elif b'floating' in data or b'concurrent' in data or b'network' in data:
                return 'commercial_floating_license'
            elif any(vendor in filename for vendor in ['autodesk', 'adobe', 'microsoft', 'vmware']):
                return 'commercial_licensed_full'
            else:
                return 'custom_protection'
        
        except Exception:
            return 'custom_protection'
    
    def _copy_to_category(self, source_path: str, category: str, file_hash: str) -> bool:
        """Copy file to appropriate category directory"""
        try:
            if category not in self.categories:
                category = 'custom_protection'
            
            filename = os.path.basename(source_path)
            dest_filename = f"{file_hash[:12]}_{filename}"
            dest_path = self.categories[category] / dest_filename
            
            shutil.copy2(source_path, dest_path)
            
            self.collection_stats[category] += 1
            logger.debug(f"Collected {filename} -> {category}")
            
            return True
        
        except Exception as e:
            logger.debug(f"Error copying {source_path}: {e}")
            return False
    
    def _collect_system_binaries(self) -> int:
        """Collect system binaries with licensing components"""
        collected = 0
        
        # System licensing paths
        system_paths = [
            # Windows licensing
            r"C:\Windows\System32\spp",
            r"C:\Windows\System32\licensing",
            r"C:\Program Files\Common Files\Microsoft Shared\OfficeSoftwareProtectionPlatform",
            r"C:\ProgramData\Microsoft\Windows\ClipSVC",
            
            # Linux licensing
            "/usr/lib/flexlm",
            "/opt/flexlm", 
            "/usr/local/flexlm",
            "/usr/share/licenses",
            "/var/lib/licensing"
        ]
        
        for path in system_paths:
            if os.path.exists(path):
                if os.path.isfile(path):
                    if self._analyze_and_categorize_binary(path):
                        collected += 1
                elif os.path.isdir(path):
                    collected += self._scan_directory_comprehensive(path, max_depth=2)
        
        self.collection_stats['system_binaries'] = collected
        return collected
    
    def _collect_package_manager_software(self) -> int:
        """Collect from package managers (apt, chocolatey, etc.)"""
        collected = 0
        
        try:
            # Try to get list of installed packages and their binaries
            if shutil.which('dpkg'):  # Debian/Ubuntu
                collected += self._collect_from_dpkg()
            
            if shutil.which('rpm'):   # RedHat/CentOS
                collected += self._collect_from_rpm()
            
            if shutil.which('choco'): # Windows Chocolatey
                collected += self._collect_from_chocolatey()
        
        except Exception as e:
            logger.debug(f"Package manager collection error: {e}")
        
        self.collection_stats['package_managers'] = collected
        return collected
    
    def _collect_from_dpkg(self) -> int:
        """Collect from dpkg-installed packages"""
        collected = 0
        
        try:
            # Get list of packages with licensing keywords
            result = subprocess.run(
                ['dpkg', '-l'], 
                capture_output=True, 
                text=True, 
                timeout=30
            )
            
            licensing_packages = []
            for line in result.stdout.split('\n'):
                if any(term in line.lower() for term in ['license', 'trial', 'commercial', 'proprietary']):
                    parts = line.split()
                    if len(parts) >= 2:
                        licensing_packages.append(parts[1])
            
            # Get files for licensing packages
            for package in licensing_packages[:20]:  # Limit to avoid timeout
                try:
                    result = subprocess.run(
                        ['dpkg', '-L', package],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    
                    for file_path in result.stdout.split('\n'):
                        if file_path and os.path.isfile(file_path):
                            if self._is_potential_licensing_binary(os.path.basename(file_path)):
                                if self._analyze_and_categorize_binary(file_path):
                                    collected += 1
                
                except subprocess.TimeoutExpired:
                    continue
                except Exception:
                    continue
        
        except Exception as e:
            logger.debug(f"dpkg collection error: {e}")
        
        return collected
    
    def _collect_from_rpm(self) -> int:
        """Collect from RPM-installed packages"""
        # Similar to dpkg but for RPM systems
        return 0  # Placeholder - would implement RPM-specific logic
    
    def _collect_from_chocolatey(self) -> int:
        """Collect from Chocolatey-installed packages"""
        # Would implement Chocolatey-specific logic
        return 0  # Placeholder
    
    def _collect_github_releases(self) -> int:
        """Collect from GitHub releases with licensing examples"""
        collected = 0
        
        github_searches = [
            'license+validation+language:C',
            'software+protection+language:C++', 
            'trial+software+language:C#',
            'activation+system+language:C',
            'flexlm+integration',
            'hasp+protection',
            'keygen+source+language:C++',
            'crack+analysis+language:C'
        ]
        
        for search_query in github_searches:
            try:
                collected += self._search_github_repositories(search_query)
                time.sleep(5)  # Rate limiting
            except Exception as e:
                logger.debug(f"GitHub search error for '{search_query}': {e}")
        
        self.collection_stats['github_releases'] = collected
        return collected
    
    def _search_github_repositories(self, query: str, max_repos: int = 20) -> int:
        """Search GitHub repositories and collect releases"""
        collected = 0
        
        try:
            search_url = "https://api.github.com/search/repositories"
            params = {
                'q': query,
                'sort': 'stars',
                'order': 'desc',
                'per_page': max_repos
            }
            
            response = requests.get(search_url, params=params, timeout=30)
            if response.status_code != 200:
                return 0
            
            data = response.json()
            
            for repo in data.get('items', []):
                try:
                    collected += self._collect_repo_releases(repo['full_name'])
                    time.sleep(2)  # Rate limiting
                except Exception as e:
                    logger.debug(f"Error collecting from repo {repo['full_name']}: {e}")
                    continue
        
        except Exception as e:
            logger.debug(f"GitHub repository search error: {e}")
        
        return collected
    
    def _collect_repo_releases(self, repo_name: str) -> int:
        """Collect binary releases from a GitHub repository"""
        collected = 0
        
        try:
            releases_url = f"https://api.github.com/repos/{repo_name}/releases"
            response = requests.get(releases_url, timeout=30)
            
            if response.status_code != 200:
                return 0
            
            releases = response.json()
            
            for release in releases[:3]:  # Latest 3 releases
                for asset in release.get('assets', []):
                    if self._is_potential_licensing_binary(asset['name']):
                        # Download if not too large
                        if asset['size'] < 50 * 1024 * 1024:  # < 50MB
                            if self._download_github_asset(asset, repo_name):
                                collected += 1
        
        except Exception as e:
            logger.debug(f"Error collecting releases from {repo_name}: {e}")
        
        return collected
    
    def _download_github_asset(self, asset: dict, repo_name: str) -> bool:
        """Download and categorize GitHub asset"""
        try:
            download_url = asset['browser_download_url']
            filename = asset['name']
            
            # Create temporary download
            temp_path = self.output_dir / 'temp' / filename
            temp_path.parent.mkdir(exist_ok=True)
            
            response = requests.get(download_url, stream=True, timeout=60)
            response.raise_for_status()
            
            with open(temp_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            # Analyze and categorize
            if self._analyze_and_categorize_binary(str(temp_path)):
                return True
            else:
                # Clean up if not useful
                temp_path.unlink()
                return False
        
        except Exception as e:
            logger.debug(f"Error downloading asset {asset['name']}: {e}")
            return False
    
    def _collect_download_sites(self) -> int:
        """Collect trial software from download sites"""
        # This would implement web scraping of major download sites
        # For now, return placeholder
        return 0
    
    def _collect_vendor_trials(self) -> int:
        """Collect trial versions from vendor websites"""
        # This would implement automated trial download from vendor sites
        # For now, return placeholder  
        return 0
    
    def _generate_licensing_variations(self) -> int:
        """Generate variations of existing binaries with different licensing states"""
        collected = 0
        
        # This would implement binary modification to create licensing variations
        # For example: patching trial periods, modifying license checks, etc.
        # For now, return placeholder
        
        return collected
    
    def _augment_dataset(self):
        """Augment dataset with additional variations and preprocessing"""
        logger.info("Augmenting dataset with variations...")
        
        # Create variations of existing samples
        for category_name, category_path in self.categories.items():
            if not category_path.exists():
                continue
            
            original_files = list(category_path.glob('*'))
            variations_created = 0
            
            for original_file in original_files[:50]:  # Limit to avoid too many variations
                try:
                    # Create packed version
                    packed_variation = self._create_packed_variation(original_file)
                    if packed_variation:
                        variations_created += 1
                    
                    # Create stripped version  
                    stripped_variation = self._create_stripped_variation(original_file)
                    if stripped_variation:
                        variations_created += 1
                
                except Exception as e:
                    logger.debug(f"Error creating variations for {original_file}: {e}")
            
            if variations_created > 0:
                logger.info(f"Created {variations_created} variations for {category_name}")
    
    def _create_packed_variation(self, original_file: Path) -> bool:
        """Create packed version of binary using UPX"""
        try:
            if not shutil.which('upx'):
                return False
            
            packed_file = original_file.parent / f"packed_{original_file.name}"
            
            # Copy original
            shutil.copy2(original_file, packed_file)
            
            # Pack with UPX
            result = subprocess.run(
                ['upx', '--best', str(packed_file)],
                capture_output=True,
                timeout=30
            )
            
            return result.returncode == 0
        
        except Exception:
            return False
    
    def _create_stripped_variation(self, original_file: Path) -> bool:
        """Create stripped version of binary"""
        try:
            if not shutil.which('strip'):
                return False
            
            stripped_file = original_file.parent / f"stripped_{original_file.name}"
            
            # Copy original
            shutil.copy2(original_file, stripped_file)
            
            # Strip symbols
            result = subprocess.run(
                ['strip', str(stripped_file)],
                capture_output=True,
                timeout=30
            )
            
            return result.returncode == 0
        
        except Exception:
            return False
    
    def _create_comprehensive_metadata(self):
        """Create comprehensive metadata for the massive dataset"""
        metadata = {
            'collection_info': {
                'target_samples': self.target_samples,
                'total_collected': sum(self.collection_stats.values()),
                'collection_date': time.strftime('%Y-%m-%d %H:%M:%S'),
                'unique_hashes': len(self.collected_hashes)
            },
            'categories': dict(self.collection_stats),
            'collection_sources': {
                'installed_software': True,
                'system_binaries': True,
                'package_managers': True,
                'github_releases': True,
                'vendor_sites': False,  # Placeholder
                'download_sites': False  # Placeholder
            },
            'quality_metrics': self._calculate_quality_metrics()
        }
        
        metadata_file = self.output_dir / 'massive_dataset_metadata.json'
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        logger.info(f"Comprehensive metadata saved to {metadata_file}")
    
    def _calculate_quality_metrics(self) -> Dict[str, float]:
        """Calculate dataset quality metrics"""
        total_samples = sum(self.collection_stats.values())
        
        if total_samples == 0:
            return {'overall_quality': 0.0}
        
        # Category balance
        category_counts = list(self.collection_stats.values())
        mean_count = np.mean(category_counts)
        std_count = np.std(category_counts)
        balance_score = 1.0 - (std_count / mean_count if mean_count > 0 else 1.0)
        
        # Coverage score
        categories_with_samples = sum(1 for count in category_counts if count > 0)
        coverage_score = categories_with_samples / len(self.categories)
        
        # Size adequacy
        size_score = min(1.0, total_samples / self.target_samples)
        
        # Overall quality
        overall_quality = (balance_score + coverage_score + size_score) / 3
        
        return {
            'balance_score': balance_score,
            'coverage_score': coverage_score,
            'size_score': size_score,
            'overall_quality': overall_quality,
            'samples_per_category_avg': mean_count,
            'samples_per_category_std': std_count
        }
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of file"""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except Exception:
            return hashlib.sha256(file_path.encode()).hexdigest()


def main():
    """Main function to run massive data collection"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Collect massive licensing dataset")
    parser.add_argument("--output-dir", default="/mnt/c/Intellicrack/massive_licensing_data",
                       help="Output directory for massive dataset")
    parser.add_argument("--target-samples", type=int, default=5000,
                       help="Target number of samples to collect")
    parser.add_argument("--max-workers", type=int, default=10,
                       help="Maximum worker threads")
    
    args = parser.parse_args()
    
    # Set up logging
    logging.basicConfig(level=logging.INFO,
                       format='%(asctime)s - %(levelname)s - %(message)s')
    
    # Create collector
    collector = MassiveDataCollector(args.output_dir, args.target_samples)
    
    # Start massive collection
    try:
        collection_stats = collector.collect_massive_dataset()
        
        total_collected = sum(collection_stats.values())
        
        print("\n" + "="*80)
        print("MASSIVE LICENSING DATA COLLECTION COMPLETE")
        print("="*80)
        print(f"Target samples: {args.target_samples}")
        print(f"Total collected: {total_collected}")
        print(f"Collection rate: {total_collected/args.target_samples*100:.1f}%")
        
        print(f"\nCategory breakdown:")
        for category, count in collection_stats.items():
            if count > 0:
                print(f"  {category}: {count}")
        
        print(f"\nDataset saved to: {args.output_dir}")
        print("="*80)
        
    except Exception as e:
        logger.error(f"Massive collection failed: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())