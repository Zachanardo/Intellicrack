#!/usr/bin/env python3
"""
Focused Licensing Data Collector

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

Collects real licensing binaries from available Windows and Linux programs
for robust model training.
"""

import os
import sys
import json
import shutil
import hashlib
import logging
import subprocess
import threading
import time
import numpy as np
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Set
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

class FocusedLicensingCollector:
    """Collect licensing binaries from available system resources"""
    
    def __init__(self, output_dir: str, target_samples: int = 1000):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.target_samples = target_samples
        
        # Create category structure
        self.categories = {
            'commercial_adobe': self.output_dir / 'commercial_adobe',
            'commercial_microsoft': self.output_dir / 'commercial_microsoft', 
            'commercial_java': self.output_dir / 'commercial_java',
            'commercial_maxon': self.output_dir / 'commercial_maxon',
            'commercial_office': self.output_dir / 'commercial_office',
            'commercial_git': self.output_dir / 'commercial_git',
            'commercial_nodejs': self.output_dir / 'commercial_nodejs',
            'commercial_parsec': self.output_dir / 'commercial_parsec',
            'system_windows': self.output_dir / 'system_windows',
            'system_linux': self.output_dir / 'system_linux',
            'security_tools': self.output_dir / 'security_tools',
            'dev_tools': self.output_dir / 'dev_tools',
            'no_licensing': self.output_dir / 'no_licensing'
        }
        
        for category_dir in self.categories.values():
            category_dir.mkdir(exist_ok=True)
        
        # Windows program directories with licensing
        self.windows_licensing_dirs = [
            '/mnt/c/Program Files/Adobe',
            '/mnt/c/Program Files (x86)/Adobe', 
            '/mnt/c/Program Files/Microsoft Office',
            '/mnt/c/Program Files (x86)/Microsoft',
            '/mnt/c/Program Files/Java',
            '/mnt/c/Program Files (x86)/Java',
            '/mnt/c/Program Files/Maxon Cinema 4D 2025',
            '/mnt/c/Program Files/Git',
            '/mnt/c/Program Files/nodejs',
            '/mnt/c/Program Files/Parsec',
            '/mnt/c/Program Files/LM Studio',
            '/mnt/c/Program Files/Docker',
            '/mnt/c/Program Files/Ghidra'
        ]
        
        # Linux system directories
        self.linux_dirs = [
            '/usr/bin',
            '/usr/local/bin',
            '/bin',
            '/sbin',
            '/usr/sbin'
        ]
        
        self.collection_stats = defaultdict(int)
        self.collected_hashes = set()
        
    def collect_focused_dataset(self) -> Dict[str, int]:
        """Collect focused licensing dataset from available resources"""
        logger.info(f"Starting focused data collection targeting {self.target_samples} samples...")
        
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = []
            
            # Collect from Windows commercial software
            futures.append(executor.submit(self._collect_windows_commercial))
            
            # Collect from Linux system binaries
            futures.append(executor.submit(self._collect_linux_binaries))
            
            # Collect from security tools
            futures.append(executor.submit(self._collect_security_tools))
            
            # Collect from development tools
            futures.append(executor.submit(self._collect_dev_tools))
            
            # Wait for completion
            for future in as_completed(futures):
                try:
                    result = future.result()
                    logger.info(f"Collection task completed: {result} samples")
                except Exception as e:
                    logger.error(f"Collection task failed: {e}")
        
        # Create metadata
        self._create_metadata()
        
        total_collected = sum(self.collection_stats.values())
        logger.info(f"Focused data collection complete: {total_collected} samples collected")
        
        return dict(self.collection_stats)
    
    def _collect_windows_commercial(self) -> int:
        """Collect from Windows commercial software with licensing"""
        collected = 0
        
        for program_dir in self.windows_licensing_dirs:
            if not os.path.exists(program_dir):
                continue
                
            logger.info(f"Scanning Windows directory: {program_dir}")
            
            try:
                for root, dirs, files in os.walk(program_dir):
                    # Limit depth to avoid excessive scanning
                    level = root.replace(program_dir, '').count(os.sep)
                    if level >= 3:
                        dirs[:] = []
                        continue
                    
                    for file in files:
                        if collected >= self.target_samples // 2:  # Half from Windows
                            return collected
                            
                        if self._is_licensing_binary(file):
                            file_path = os.path.join(root, file)
                            
                            try:
                                if self._analyze_and_categorize_windows(file_path):
                                    collected += 1
                                    if collected % 10 == 0:
                                        logger.info(f"Windows collection progress: {collected}")
                            except Exception as e:
                                logger.debug(f"Error analyzing {file_path}: {e}")
            
            except (PermissionError, OSError) as e:
                logger.debug(f"Access error for {program_dir}: {e}")
        
        return collected
    
    def _collect_linux_binaries(self) -> int:
        """Collect from Linux system binaries"""
        collected = 0
        
        for linux_dir in self.linux_dirs:
            if not os.path.exists(linux_dir):
                continue
                
            logger.info(f"Scanning Linux directory: {linux_dir}")
            
            try:
                files = os.listdir(linux_dir)
                for file in files[:100]:  # Limit per directory
                    if collected >= self.target_samples // 4:  # Quarter from Linux
                        return collected
                        
                    file_path = os.path.join(linux_dir, file)
                    
                    if os.path.isfile(file_path) and os.access(file_path, os.X_OK):
                        try:
                            if self._analyze_and_categorize_linux(file_path):
                                collected += 1
                                if collected % 10 == 0:
                                    logger.info(f"Linux collection progress: {collected}")
                        except Exception as e:
                            logger.debug(f"Error analyzing {file_path}: {e}")
            
            except (PermissionError, OSError) as e:
                logger.debug(f"Access error for {linux_dir}: {e}")
        
        return collected
    
    def _collect_security_tools(self) -> int:
        """Collect from security tools"""
        collected = 0
        
        security_paths = [
            '/mnt/c/Program Files/Npcap',
            '/mnt/c/Program Files/Wireshark',
            '/mnt/c/Program Files (x86)/Nmap',
            '/mnt/c/Program Files/Windows Defender',
            '/mnt/c/Program Files/Windows Defender Advanced Threat Protection'
        ]
        
        for path in security_paths:
            if os.path.exists(path):
                collected += self._scan_directory_limited(path, 'security_tools', max_files=20)
        
        return collected
    
    def _collect_dev_tools(self) -> int:
        """Collect from development tools"""
        collected = 0
        
        dev_paths = [
            '/mnt/c/Program Files/PowerShell',
            '/mnt/c/Program Files (x86)/Microsoft Visual Studio',
            '/mnt/c/Program Files/dotnet',
            '/mnt/c/Program Files (x86)/dotnet',
            '/mnt/c/Program Files/WSL'
        ]
        
        for path in dev_paths:
            if os.path.exists(path):
                collected += self._scan_directory_limited(path, 'dev_tools', max_files=30)
        
        return collected
    
    def _scan_directory_limited(self, directory: str, category: str, max_files: int = 50) -> int:
        """Scan directory with limits"""
        collected = 0
        
        try:
            for root, dirs, files in os.walk(directory):
                level = root.replace(directory, '').count(os.sep)
                if level >= 2:
                    dirs[:] = []
                    continue
                
                for file in files[:max_files]:
                    if collected >= max_files:
                        return collected
                        
                    if self._is_licensing_binary(file):
                        file_path = os.path.join(root, file)
                        
                        try:
                            if self._copy_to_category_direct(file_path, category):
                                collected += 1
                        except Exception as e:
                            logger.debug(f"Error copying {file_path}: {e}")
        
        except Exception as e:
            logger.debug(f"Error scanning {directory}: {e}")
        
        return collected
    
    def _is_licensing_binary(self, filename: str) -> bool:
        """Check if file might contain licensing logic"""
        filename_lower = filename.lower()
        
        # File extensions
        licensing_extensions = ['.exe', '.dll', '.so', '.dylib', '.jar', '.msi']
        if not any(filename_lower.endswith(ext) for ext in licensing_extensions):
            return False
        
        # Size check - skip very small files
        return True
    
    def _analyze_and_categorize_windows(self, file_path: str) -> bool:
        """Analyze and categorize Windows binary"""
        try:
            file_hash = self._calculate_file_hash(file_path)
            if file_hash in self.collected_hashes:
                return False
            
            # Determine category based on path
            path_lower = file_path.lower()
            
            if 'adobe' in path_lower:
                category = 'commercial_adobe'
            elif 'microsoft' in path_lower or 'office' in path_lower:
                category = 'commercial_microsoft'
            elif 'java' in path_lower:
                category = 'commercial_java'
            elif 'maxon' in path_lower or 'cinema' in path_lower:
                category = 'commercial_maxon'
            elif 'git' in path_lower:
                category = 'commercial_git'
            elif 'nodejs' in path_lower or 'node' in path_lower:
                category = 'commercial_nodejs'
            elif 'parsec' in path_lower:
                category = 'commercial_parsec'
            else:
                category = 'system_windows'
            
            # Enhanced licensing detection
            if self._has_strong_licensing_indicators(file_path):
                return self._copy_to_category(file_path, category, file_hash)
            elif np.random.random() < 0.05:  # 5% of others for control group
                return self._copy_to_category(file_path, 'no_licensing', file_hash)
            
            return False
        
        except Exception as e:
            logger.debug(f"Error categorizing {file_path}: {e}")
            return False
    
    def _analyze_and_categorize_linux(self, file_path: str) -> bool:
        """Analyze and categorize Linux binary"""
        try:
            file_hash = self._calculate_file_hash(file_path)
            if file_hash in self.collected_hashes:
                return False
            
            # Most Linux system binaries don't have licensing
            if self._has_licensing_indicators(file_path):
                return self._copy_to_category(file_path, 'system_linux', file_hash)
            elif np.random.random() < 0.1:  # 10% for control group
                return self._copy_to_category(file_path, 'no_licensing', file_hash)
            
            return False
        
        except Exception as e:
            logger.debug(f"Error categorizing {file_path}: {e}")
            return False
    
    def _has_strong_licensing_indicators(self, file_path: str) -> bool:
        """Strong licensing indicator check for commercial software"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read(1024 * 1024).lower()  # 1MB sample
            
            # Strong commercial licensing patterns
            strong_patterns = [
                b'license', b'serial', b'activation', b'registration', b'trial',
                b'subscription', b'adobe', b'microsoft', b'autodesk', b'java',
                b'oracle', b'flexlm', b'hasp', b'sentinel', b'codemeter',
                b'product key', b'unlock', b'expire', b'evaluation'
            ]
            
            matches = sum(1 for pattern in strong_patterns if pattern in data)
            return matches >= 2  # Require multiple indicators
        
        except Exception:
            return False
    
    def _has_licensing_indicators(self, file_path: str) -> bool:
        """Basic licensing indicator check"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read(512 * 1024).lower()  # 512KB sample
            
            patterns = [
                b'license', b'licence', b'serial', b'key', b'activation',
                b'trial', b'demo', b'evaluation', b'expire'
            ]
            
            return any(pattern in data for pattern in patterns)
        
        except Exception:
            return False
    
    def _copy_to_category(self, source_path: str, category: str, file_hash: str) -> bool:
        """Copy file to category with hash prefix"""
        try:
            if category not in self.categories:
                category = 'no_licensing'
            
            filename = os.path.basename(source_path)
            dest_filename = f"{file_hash[:12]}_{filename}"
            dest_path = self.categories[category] / dest_filename
            
            shutil.copy2(source_path, dest_path)
            
            self.collection_stats[category] += 1
            self.collected_hashes.add(file_hash)
            logger.debug(f"Collected {filename} -> {category}")
            
            return True
        
        except Exception as e:
            logger.debug(f"Error copying {source_path}: {e}")
            return False
    
    def _copy_to_category_direct(self, source_path: str, category: str) -> bool:
        """Direct copy to category"""
        file_hash = self._calculate_file_hash(source_path)
        if file_hash in self.collected_hashes:
            return False
        
        return self._copy_to_category(source_path, category, file_hash)
    
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
    
    def _create_metadata(self):
        """Create collection metadata"""
        metadata = {
            'collection_info': {
                'target_samples': self.target_samples,
                'total_collected': sum(self.collection_stats.values()),
                'collection_date': time.strftime('%Y-%m-%d %H:%M:%S'),
                'unique_hashes': len(self.collected_hashes),
                'collection_type': 'focused_real_licensing'
            },
            'categories': dict(self.collection_stats),
            'quality_metrics': self._calculate_quality_metrics()
        }
        
        metadata_file = self.output_dir / 'focused_dataset_metadata.json'
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        logger.info(f"Metadata saved to {metadata_file}")
    
    def _calculate_quality_metrics(self) -> Dict[str, float]:
        """Calculate quality metrics"""
        total_samples = sum(self.collection_stats.values())
        
        if total_samples == 0:
            return {'overall_quality': 0.0}
        
        category_counts = list(self.collection_stats.values())
        coverage_score = sum(1 for count in category_counts if count > 0) / len(self.categories)
        size_score = min(1.0, total_samples / self.target_samples)
        
        return {
            'coverage_score': coverage_score,
            'size_score': size_score,
            'overall_quality': (coverage_score + size_score) / 2,
            'total_samples': total_samples
        }


def main():
    """Main collection function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Focused licensing data collection")
    parser.add_argument("--output-dir", default="/mnt/c/Intellicrack/focused_licensing_data",
                       help="Output directory")
    parser.add_argument("--target-samples", type=int, default=1000,
                       help="Target number of samples")
    
    args = parser.parse_args()
    
    logging.basicConfig(level=logging.INFO,
                       format='%(asctime)s - %(levelname)s - %(message)s')
    
    collector = FocusedLicensingCollector(args.output_dir, args.target_samples)
    
    try:
        collection_stats = collector.collect_focused_dataset()
        
        total_collected = sum(collection_stats.values())
        
        print("\n" + "="*80)
        print("FOCUSED LICENSING DATA COLLECTION COMPLETE")
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
        
        return 0
    
    except Exception as e:
        logger.error(f"Collection failed: {e}")
        return 1


if __name__ == "__main__":
    exit(main())