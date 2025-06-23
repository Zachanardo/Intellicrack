#!/usr/bin/env python3
"""
Data Collection Tools for Building Training Dataset
"""

import os
import requests
import hashlib
import zipfile
import json
from typing import List, Dict
import logging

logger = logging.getLogger(__name__)

class BinaryCollector:
    """Collect binaries from various sources"""
    
    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
    def collect_from_github(self, search_terms: List[str]):
        """Collect vulnerable samples from GitHub security advisories"""
        # GitHub API endpoint for security advisories
        headers = {
            'Accept': 'application/vnd.github.v3+json',
            # Add your GitHub token here for higher rate limits
            # 'Authorization': 'token YOUR_GITHUB_TOKEN'
        }
        
        collected = []
        
        for term in search_terms:
            try:
                # Search for repositories with security issues
                url = f"https://api.github.com/search/repositories?q={term}+license+bypass+vulnerability"
                response = requests.get(url, headers=headers)
                
                if response.status_code == 200:
                    data = response.json()
                    for repo in data.get('items', [])[:5]:  # Limit to 5 per search
                        # Get releases
                        releases_url = f"https://api.github.com/repos/{repo['full_name']}/releases"
                        releases_resp = requests.get(releases_url, headers=headers)
                        
                        if releases_resp.status_code == 200:
                            releases = releases_resp.json()
                            for release in releases[:2]:  # Get last 2 releases
                                for asset in release.get('assets', []):
                                    if any(ext in asset['name'] for ext in ['.exe', '.dll', '.so']):
                                        # Download the binary
                                        self._download_file(
                                            asset['browser_download_url'],
                                            os.path.join(self.output_dir, 'vulnerable', asset['name'])
                                        )
                                        collected.append(asset['name'])
                                        
            except Exception as e:
                logger.error(f"Error collecting from GitHub: {e}")
                
        return collected
    
    def collect_from_virustotal_academic(self, api_key: str, hashes: List[str]):
        """Collect samples using VirusTotal Academic API"""
        headers = {'x-apikey': api_key}
        collected = []
        
        for file_hash in hashes:
            try:
                # Get file info
                url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
                response = requests.get(url, headers=headers)
                
                if response.status_code == 200:
                    data = response.json()
                    # Check if it's a legitimate software with licensing
                    tags = data.get('data', {}).get('attributes', {}).get('tags', [])
                    if any('license' in tag or 'crack' in tag for tag in tags):
                        # Download URL would be provided in academic access
                        download_url = data.get('data', {}).get('attributes', {}).get('download_url')
                        if download_url:
                            filename = f"{file_hash}.exe"
                            self._download_file(
                                download_url,
                                os.path.join(self.output_dir, 'protected', filename)
                            )
                            collected.append(filename)
                            
            except Exception as e:
                logger.error(f"Error collecting from VirusTotal: {e}")
                
        return collected
    
    def collect_system_binaries(self):
        """Collect benign system binaries for negative samples"""
        collected = []
        
        # Windows system directories
        if os.name == 'nt':
            system_dirs = [
                r"C:\Windows\System32",
                r"C:\Windows\SysWOW64",
                r"C:\Program Files\Windows Defender",
                r"C:\Program Files\Common Files"
            ]
        else:
            # Linux/Mac
            system_dirs = [
                "/usr/bin",
                "/usr/lib",
                "/usr/local/bin"
            ]
            
        for sys_dir in system_dirs:
            if os.path.exists(sys_dir):
                for filename in os.listdir(sys_dir)[:20]:  # Limit samples
                    filepath = os.path.join(sys_dir, filename)
                    if os.path.isfile(filepath):
                        if filename.endswith(('.exe', '.dll', '.so', '.dylib')):
                            # Copy to benign folder
                            dest = os.path.join(self.output_dir, 'benign', filename)
                            try:
                                import shutil
                                shutil.copy2(filepath, dest)
                                collected.append(filename)
                            except:
                                pass
                                
        return collected
    
    def collect_from_exploit_db(self):
        """Collect samples referenced in Exploit-DB"""
        # This would require parsing exploit-db entries
        # and downloading referenced binaries
        pass
    
    def collect_trial_software(self):
        """Collect trial versions of commercial software"""
        trial_urls = [
            # Add URLs of trial software here
            # Example: "https://example.com/software-trial.exe"
        ]
        
        collected = []
        for url in trial_urls:
            try:
                filename = url.split('/')[-1]
                self._download_file(
                    url,
                    os.path.join(self.output_dir, 'protected', filename)
                )
                collected.append(filename)
            except:
                pass
                
        return collected
    
    def _download_file(self, url: str, destination: str):
        """Download a file from URL"""
        os.makedirs(os.path.dirname(destination), exist_ok=True)
        
        response = requests.get(url, stream=True)
        response.raise_for_status()
        
        with open(destination, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
                
    def create_metadata(self):
        """Create metadata file for collected samples"""
        metadata = {
            'benign': {},
            'protected': {},
            'vulnerable': {}
        }
        
        for category in metadata.keys():
            category_dir = os.path.join(self.output_dir, category)
            if os.path.exists(category_dir):
                for filename in os.listdir(category_dir):
                    filepath = os.path.join(category_dir, filename)
                    if os.path.isfile(filepath):
                        with open(filepath, 'rb') as f:
                            file_hash = hashlib.sha256(f.read()).hexdigest()
                            
                        metadata[category][filename] = {
                            'sha256': file_hash,
                            'size': os.path.getsize(filepath),
                            'category': category
                        }
                        
        with open(os.path.join(self.output_dir, 'metadata.json'), 'w') as f:
            json.dump(metadata, f, indent=2)
            
        return metadata


class DataAugmentor:
    """Augment training data with variations"""
    
    def __init__(self):
        pass
        
    def create_packed_variants(self, binary_path: str, output_dir: str):
        """Create packed versions of binaries using different packers"""
        packers = {
            'upx': 'upx -9 {input} -o {output}',
            # Add more packers as needed
        }
        
        variants = []
        for packer_name, command in packers.items():
            try:
                output_path = os.path.join(
                    output_dir,
                    f"{os.path.basename(binary_path)}.{packer_name}"
                )
                
                import subprocess
                cmd = command.format(input=binary_path, output=output_path)
                subprocess.run(cmd.split(), check=True)
                
                variants.append(output_path)
            except:
                pass
                
        return variants
    
    def create_modified_variants(self, binary_path: str, output_dir: str):
        """Create modified versions with different protection levels"""
        # This would involve:
        # 1. Stripping symbols
        # 2. Adding fake sections
        # 3. Modifying timestamps
        # 4. Injecting benign code
        pass


def collect_training_data():
    """Main function to collect training data"""
    collector = BinaryCollector("/mnt/c/Intellicrack/training_data")
    
    print("Starting data collection...")
    
    # 1. Collect benign system binaries
    print("Collecting benign system binaries...")
    benign = collector.collect_system_binaries()
    print(f"  Collected {len(benign)} benign samples")
    
    # 2. Collect from GitHub (if API key available)
    print("Collecting from GitHub...")
    github_samples = collector.collect_from_github([
        "license bypass",
        "keygen",
        "crack",
        "trial reset"
    ])
    print(f"  Collected {len(github_samples)} samples from GitHub")
    
    # 3. Collect trial software
    print("Collecting trial software...")
    trials = collector.collect_trial_software()
    print(f"  Collected {len(trials)} trial software samples")
    
    # 4. Create metadata
    print("Creating metadata...")
    metadata = collector.create_metadata()
    
    print(f"\nTotal samples collected:")
    for category, files in metadata.items():
        print(f"  {category}: {len(files)}")
        
    print("\nData collection complete!")
    print(f"Data saved to: /mnt/c/Intellicrack/training_data")


if __name__ == "__main__":
    collect_training_data()