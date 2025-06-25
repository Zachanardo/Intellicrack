#!/usr/bin/env python3
"""
Streaming Training Data Collector for Advanced Licensing Detector

Collects real binary URLs from legitimate sources for training.
No local storage required - all processing is done via streaming.
"""

import os
import re
import json
import time
import logging
import requests
import numpy as np
from typing import List, Dict, Tuple, Optional, Set
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)


class StreamingTrainingCollector:
    """Collect binary URLs from legitimate sources for ML training"""
    
    def __init__(self):
        # User agent for web requests
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        # Known software with various protection schemes
        self.protection_examples = {
            'flexlm': [
                'matlab', 'ansys', 'cadence', 'mentor graphics', 'synopsys',
                'altium', 'comsol', 'tecplot', 'originlab', 'wolfram'
            ],
            'sentinel_hasp': [
                'autocad', 'solidworks', 'mastercam', 'zwcad', 'bricscad',
                'archicad', 'vectorworks', 'chief architect', 'sketchup pro'
            ],
            'codemeter': [
                'siemens', 'rockwell', 'schneider', 'abb', 'ge digital',
                'honeywell', 'emerson', 'yokogawa', 'mitsubishi'
            ],
            'winlicense': [
                'total commander', 'ultraedit', 'beyond compare', 'axure',
                'balsamiq', 'mockplus', 'justinmind', 'principle'
            ],
            'steam': [
                'counter-strike', 'dota', 'team fortress', 'portal', 'half-life',
                'left 4 dead', 'garry mod', 'rust', 'ark survival'
            ],
            'adobe': [
                'photoshop', 'illustrator', 'premiere', 'after effects',
                'lightroom', 'indesign', 'xd', 'animate', 'audition'
            ],
            'microsoft': [
                'office', 'windows', 'visual studio', 'sql server', 'azure',
                'dynamics', 'power bi', 'project', 'visio'
            ]
        }
    
    def collect_all_urls(self, target_count: int = 5000) -> Dict[str, List[str]]:
        """Collect URLs from all sources"""
        all_urls = {
            'trial_software': [],
            'open_source': [],
            'gaming': [],
            'enterprise': [],
            'development_tools': []
        }
        
        logger.info(f"Starting URL collection (target: {target_count} URLs)")
        
        # Collect from each source
        collectors = [
            ('trial_software', self.collect_trial_software_urls),
            ('open_source', self.collect_github_releases),
            ('gaming', self.collect_gaming_urls),
            ('enterprise', self.collect_enterprise_urls),
            ('development_tools', self.collect_dev_tools_urls)
        ]
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {
                executor.submit(collector_func, target_count // 5): (category, collector_func)
                for category, collector_func in collectors
            }
            
            for future in as_completed(futures):
                category, _ = futures[future]
                try:
                    urls = future.result()
                    all_urls[category] = urls
                    logger.info(f"Collected {len(urls)} URLs for {category}")
                except Exception as e:
                    logger.error(f"Error collecting {category}: {e}")
        
        return all_urls
    
    def collect_trial_software_urls(self, max_urls: int = 1000) -> List[str]:
        """Collect trial software download URLs"""
        urls = []
        
        # Adobe trials
        adobe_products = [
            'photoshop', 'illustrator', 'premiere-pro', 'after-effects',
            'indesign', 'lightroom', 'xd', 'animate', 'audition', 'dreamweaver'
        ]
        
        for product in adobe_products:
            try:
                # Adobe trial pages follow a pattern
                trial_url = f"https://www.adobe.com/products/{product}/free-trial-download.html"
                response = requests.get(trial_url, headers=self.headers, timeout=10)
                
                if response.status_code == 200:
                    # Parse for download links
                    soup = BeautifulSoup(response.content, 'html.parser')
                    download_links = soup.find_all('a', href=True)
                    
                    for link in download_links:
                        href = link['href']
                        if '.exe' in href or '.dmg' in href or 'download' in href.lower():
                            urls.append(urljoin(trial_url, href))
                            
            except Exception as e:
                logger.debug(f"Error collecting Adobe {product}: {e}")
        
        # Microsoft evaluation center
        ms_products = {
            'windows-server': 'https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server',
            'sql-server': 'https://www.microsoft.com/en-us/evalcenter/evaluate-sql-server',
            'office': 'https://www.microsoft.com/en-us/microsoft-365/try',
            'visual-studio': 'https://visualstudio.microsoft.com/downloads/',
            'dynamics': 'https://dynamics.microsoft.com/en-us/trials/'
        }
        
        for product, url in ms_products.items():
            try:
                response = requests.get(url, headers=self.headers, timeout=10)
                if response.status_code == 200:
                    soup = BeautifulSoup(response.content, 'html.parser')
                    
                    # Look for download buttons/links
                    for link in soup.find_all(['a', 'button']):
                        href = link.get('href', '')
                        text = link.get_text().lower()
                        
                        if any(word in text for word in ['download', 'try', 'evaluate']):
                            if href and not href.startswith('#'):
                                full_url = urljoin(url, href)
                                if '.exe' in full_url or '.iso' in full_url:
                                    urls.append(full_url)
                                    
            except Exception as e:
                logger.debug(f"Error collecting MS {product}: {e}")
        
        # Autodesk trials
        autodesk_api = "https://www.autodesk.com/products/free-trials"
        try:
            response = requests.get(autodesk_api, headers=self.headers, timeout=10)
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                
                # Find product cards
                products = soup.find_all('div', class_='product-card')
                for product in products:
                    download_link = product.find('a', string=re.compile('Download', re.I))
                    if download_link and download_link.get('href'):
                        urls.append(urljoin(autodesk_api, download_link['href']))
                        
        except Exception as e:
            logger.debug(f"Error collecting Autodesk: {e}")
        
        # JetBrains trials
        jetbrains_products = [
            'idea', 'pycharm', 'webstorm', 'phpstorm', 'clion',
            'rider', 'goland', 'datagrip', 'rubymine', 'appcode'
        ]
        
        for product in jetbrains_products:
            try:
                api_url = f"https://data.services.jetbrains.com/products/releases?code={product.upper()}&latest=true&type=release"
                response = requests.get(api_url, timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    if product.upper() in data:
                        for release in data[product.upper()]:
                            if 'downloads' in release:
                                for platform, download in release['downloads'].items():
                                    if 'link' in download:
                                        urls.append(download['link'])
                                        
            except Exception as e:
                logger.debug(f"Error collecting JetBrains {product}: {e}")
        
        # VMware trials
        vmware_products = [
            'workstation-pro', 'fusion', 'vsphere', 'vcenter', 'nsx',
            'vsan', 'horizon', 'vrealize-operations'
        ]
        
        for product in vmware_products:
            try:
                trial_url = f"https://www.vmware.com/products/{product}.html"
                response = requests.get(trial_url, headers=self.headers, timeout=10)
                
                if response.status_code == 200:
                    soup = BeautifulSoup(response.content, 'html.parser')
                    trial_links = soup.find_all('a', string=re.compile('trial|evaluate', re.I))
                    
                    for link in trial_links:
                        if link.get('href'):
                            urls.append(urljoin(trial_url, link['href']))
                            
            except Exception as e:
                logger.debug(f"Error collecting VMware {product}: {e}")
        
        return urls[:max_urls]
    
    def collect_github_releases(self, max_urls: int = 1000) -> List[str]:
        """Collect GitHub release binaries"""
        urls = []
        
        # Popular projects with binaries
        github_projects = [
            # Development tools
            'microsoft/vscode', 'atom/atom', 'notepad-plus-plus/notepad-plus-plus',
            'git-for-windows/git', 'gitextensions/gitextensions',
            
            # Database tools
            'dbeaver/dbeaver', 'sqlitebrowser/sqlitebrowser', 'phpmyadmin/phpmyadmin',
            'pgadmin-org/pgadmin4', 'mongodb-js/compass',
            
            # Security tools
            'wireshark/wireshark', 'nmap/nmap', 'zaproxy/zaproxy',
            'portswigger/burp-extensions', 'aircrack-ng/aircrack-ng',
            
            # Media tools
            'obsproject/obs-studio', 'audacity/audacity', 'HandBrake/HandBrake',
            'qbittorrent/qBittorrent', 'aria2/aria2',
            
            # System tools
            'pbatard/rufus', 'ventoy/Ventoy', 'balena-io/etcher',
            'crystaldiskinfo/crystaldiskinfo', 'henrypp/simplewall',
            
            # Productivity
            'laurent22/joplin', 'zadam/trilium', 'logseq/logseq',
            'obsidianmd/obsidian-releases', 'marktext/marktext'
        ]
        
        github_api = "https://api.github.com/repos/{}/releases/latest"
        
        for project in github_projects:
            try:
                response = requests.get(
                    github_api.format(project),
                    headers={'Accept': 'application/vnd.github.v3+json'},
                    timeout=10
                )
                
                if response.status_code == 200:
                    release_data = response.json()
                    
                    if 'assets' in release_data:
                        for asset in release_data['assets']:
                            download_url = asset.get('browser_download_url', '')
                            
                            # Filter for Windows/Linux binaries
                            if any(ext in download_url.lower() for ext in 
                                   ['.exe', '.msi', '.zip', '.tar.gz', '.deb', '.rpm', '.appimage']):
                                urls.append(download_url)
                                
            except Exception as e:
                logger.debug(f"Error collecting GitHub {project}: {e}")
            
            # Rate limiting
            time.sleep(0.1)
        
        # SourceForge projects
        sourceforge_projects = [
            'sevenzip', 'filezilla', 'keepass', 'vlc', 'gimp',
            'audacity', 'openoffice', 'codeblocks', 'mingw', 'xampp'
        ]
        
        sf_api = "https://sourceforge.net/projects/{}/rss?path=/&limit=10"
        
        for project in sourceforge_projects:
            try:
                response = requests.get(sf_api.format(project), timeout=10)
                
                if response.status_code == 200:
                    # Parse RSS feed
                    root = ET.fromstring(response.content)
                    
                    for item in root.findall('.//item'):
                        link = item.find('link')
                        if link is not None and link.text:
                            # Convert to direct download URL
                            download_url = link.text.replace('/files/', '/projects/')
                            download_url = download_url.replace('/download', '')
                            urls.append(download_url)
                            
            except Exception as e:
                logger.debug(f"Error collecting SourceForge {project}: {e}")
        
        return urls[:max_urls]
    
    def collect_gaming_urls(self, max_urls: int = 1000) -> List[str]:
        """Collect gaming platform URLs"""
        urls = []
        
        # Steam free-to-play games
        steam_f2p_url = "https://store.steampowered.com/genre/Free%20to%20Play/"
        try:
            response = requests.get(steam_f2p_url, headers=self.headers, timeout=10)
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                
                # Extract app IDs
                app_links = soup.find_all('a', href=re.compile(r'/app/\d+'))
                
                for link in app_links[:50]:  # Limit to avoid too many requests
                    app_id = re.search(r'/app/(\d+)', link['href'])
                    if app_id:
                        # Steam doesn't provide direct download links
                        # But we can construct installation URLs
                        urls.append(f"steam://install/{app_id.group(1)}")
                        
        except Exception as e:
            logger.debug(f"Error collecting Steam URLs: {e}")
        
        # Epic Games Store free games
        epic_api = "https://store-site-backend-static.ak.epicgames.com/freeGamesPromotions"
        try:
            response = requests.get(epic_api, timeout=10)
            if response.status_code == 200:
                data = response.json()
                
                if 'data' in data and 'Catalog' in data['data']:
                    elements = data['data']['Catalog'].get('searchStore', {}).get('elements', [])
                    
                    for game in elements:
                        if game.get('price', {}).get('totalPrice', {}).get('discountPrice') == 0:
                            product_slug = game.get('productSlug')
                            if product_slug:
                                urls.append(f"https://launcher.store.epicgames.com/product/{product_slug}")
                                
        except Exception as e:
            logger.debug(f"Error collecting Epic Games URLs: {e}")
        
        # GOG.com free games
        gog_api = "https://www.gog.com/games/ajax/filtered?mediaType=game&price=free"
        try:
            response = requests.get(gog_api, headers=self.headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                
                if 'products' in data:
                    for product in data['products']:
                        if 'url' in product:
                            urls.append(f"https://www.gog.com{product['url']}")
                            
        except Exception as e:
            logger.debug(f"Error collecting GOG URLs: {e}")
        
        # Battle.net free games/demos
        blizzard_games = [
            'overwatch', 'hearthstone', 'heroes-of-the-storm',
            'starcraft-2', 'warcraft-3-reforged'
        ]
        
        for game in blizzard_games:
            urls.append(f"https://www.blizzard.com/download/confirmation?product={game}")
        
        # Origin/EA free games
        ea_games = [
            'apex-legends', 'star-wars-the-old-republic', 'guild-wars-2'
        ]
        
        for game in ea_games:
            urls.append(f"https://www.ea.com/games/{game}/download")
        
        return urls[:max_urls]
    
    def collect_enterprise_urls(self, max_urls: int = 1000) -> List[str]:
        """Collect enterprise software URLs"""
        urls = []
        
        # Oracle downloads
        oracle_products = [
            'database/technologies/oracle-database-software-downloads',
            'java/technologies/javase-downloads',
            'middleware/technologies/weblogic-server-downloads',
            'virtualization/technologies/vm/downloads/virtualbox-downloads'
        ]
        
        for product in oracle_products:
            try:
                url = f"https://www.oracle.com/{product}.html"
                response = requests.get(url, headers=self.headers, timeout=10)
                
                if response.status_code == 200:
                    soup = BeautifulSoup(response.content, 'html.parser')
                    download_links = soup.find_all('a', href=re.compile(r'download\.oracle\.com'))
                    
                    for link in download_links:
                        urls.append(link['href'])
                        
            except Exception as e:
                logger.debug(f"Error collecting Oracle {product}: {e}")
        
        # IBM software trials
        ibm_products = [
            'db2', 'websphere', 'cognos', 'spss', 'rational',
            'tivoli', 'lotus', 'informix'
        ]
        
        for product in ibm_products:
            urls.append(f"https://www.ibm.com/account/reg/signup?formid=urx-{product}")
        
        # SAP trials
        sap_products = [
            'hana-express', 's4hana', 'business-one', 'analytics-cloud',
            'data-intelligence', 'integration-suite'
        ]
        
        for product in sap_products:
            urls.append(f"https://www.sap.com/products/{product}/trial.html")
        
        # Cisco downloads
        cisco_products = [
            'packet-tracer', 'anyconnect', 'webex', 'jabber',
            'prime-infrastructure', 'ise'
        ]
        
        for product in cisco_products:
            urls.append(f"https://software.cisco.com/download/home/{product}")
        
        # Docker Hub (official images)
        docker_images = [
            'mysql', 'postgres', 'mongo', 'redis', 'nginx',
            'apache', 'tomcat', 'jenkins', 'gitlab', 'sonarqube'
        ]
        
        for image in docker_images:
            urls.append(f"https://hub.docker.com/_/{image}")
        
        return urls[:max_urls]
    
    def collect_dev_tools_urls(self, max_urls: int = 1000) -> List[str]:
        """Collect development tool URLs"""
        urls = []
        
        # Package managers with binaries
        npm_packages = [
            'electron', 'puppeteer', 'playwright', 'cypress', 'webpack',
            'parcel', 'rollup', 'esbuild', 'vite', 'turbo'
        ]
        
        for package in npm_packages:
            try:
                npm_api = f"https://registry.npmjs.org/{package}/latest"
                response = requests.get(npm_api, timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    if 'dist' in data and 'tarball' in data['dist']:
                        urls.append(data['dist']['tarball'])
                        
            except Exception as e:
                logger.debug(f"Error collecting npm {package}: {e}")
        
        # Python packages with binaries
        pypi_packages = [
            'numpy', 'pandas', 'tensorflow', 'torch', 'opencv-python',
            'scikit-learn', 'matplotlib', 'pillow', 'psycopg2-binary'
        ]
        
        for package in pypi_packages:
            try:
                pypi_api = f"https://pypi.org/pypi/{package}/json"
                response = requests.get(pypi_api, timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    if 'urls' in data:
                        for file_info in data['urls']:
                            if file_info['packagetype'] == 'bdist_wheel':
                                urls.append(file_info['url'])
                                break
                                
            except Exception as e:
                logger.debug(f"Error collecting PyPI {package}: {e}")
        
        # Direct tool downloads
        dev_tools = {
            'git': 'https://github.com/git-for-windows/git/releases/latest',
            'nodejs': 'https://nodejs.org/dist/latest/',
            'python': 'https://www.python.org/downloads/',
            'rust': 'https://forge.rust-lang.org/infra/channel-layout.html',
            'go': 'https://golang.org/dl/',
            'docker': 'https://download.docker.com/',
            'kubernetes': 'https://kubernetes.io/releases/download/',
            'terraform': 'https://www.terraform.io/downloads',
            'ansible': 'https://releases.ansible.com/ansible/',
            'jenkins': 'https://www.jenkins.io/download/'
        }
        
        for tool, url in dev_tools.items():
            urls.append(url)
        
        # IDE downloads
        ide_urls = [
            'https://code.visualstudio.com/sha/download?build=stable&os=win32-x64',
            'https://download.sublimetext.com/sublime_text_build_windows_x64.zip',
            'https://atom.io/download/windows_x64',
            'https://github.com/adobe/brackets/releases/latest',
            'https://download.eclipse.org/technology/epp/downloads/release/',
            'https://netbeans.apache.org/download/index.html'
        ]
        
        urls.extend(ide_urls)
        
        return urls[:max_urls]
    
    def create_labeled_dataset(self, urls: Dict[str, List[str]]) -> Tuple[List[str], List[int]]:
        """Create labeled dataset from collected URLs"""
        all_urls = []
        all_labels = []
        
        # Label mapping based on expected protection types
        category_to_label = {
            'trial_software': {
                'adobe': 8,  # Custom Adobe protection
                'microsoft': 8,  # Microsoft Activation
                'autodesk': 2,  # FlexLM
                'jetbrains': 9,  # Custom
                'vmware': 2,  # FlexLM
            },
            'open_source': 0,  # No protection
            'gaming': {
                'steam': 6,  # Steam CEG
                'epic': 9,  # Custom Epic
                'gog': 0,  # DRM-free
                'blizzard': 9,  # Custom Blizzard
            },
            'enterprise': {
                'oracle': 2,  # FlexLM
                'ibm': 2,  # FlexLM
                'sap': 9,  # Custom SAP
                'cisco': 2,  # FlexLM
            },
            'development_tools': 0  # Usually no protection
        }
        
        for category, url_list in urls.items():
            for url in url_list:
                all_urls.append(url)
                
                # Determine label based on URL patterns
                label = 0  # Default: no protection
                
                if category == 'trial_software':
                    for vendor, protection_label in category_to_label['trial_software'].items():
                        if vendor in url.lower():
                            label = protection_label
                            break
                elif category == 'gaming':
                    for platform, protection_label in category_to_label['gaming'].items():
                        if platform in url.lower():
                            label = protection_label
                            break
                elif category == 'enterprise':
                    for vendor, protection_label in category_to_label['enterprise'].items():
                        if vendor in url.lower():
                            label = protection_label
                            break
                else:
                    label = category_to_label.get(category, 0)
                
                all_labels.append(label)
        
        return all_urls, all_labels
    
    def save_url_dataset(self, urls: Dict[str, List[str]], output_path: str):
        """Save collected URLs to JSON file"""
        dataset = {
            'metadata': {
                'collected_at': time.strftime('%Y-%m-%d %H:%M:%S'),
                'total_urls': sum(len(url_list) for url_list in urls.values()),
                'categories': list(urls.keys())
            },
            'urls': urls
        }
        
        with open(output_path, 'w') as f:
            json.dump(dataset, f, indent=2)
        
        logger.info(f"Saved {dataset['metadata']['total_urls']} URLs to {output_path}")


if __name__ == "__main__":
    # Example usage
    collector = StreamingTrainingCollector()
    
    # Collect URLs
    print("Collecting training URLs...")
    urls = collector.collect_all_urls(target_count=1000)
    
    # Create labeled dataset
    training_urls, training_labels = collector.create_labeled_dataset(urls)
    
    print(f"Collected {len(training_urls)} URLs")
    print(f"Label distribution: {dict(zip(*np.unique(training_labels, return_counts=True)))}")
    
    # Save for future use
    collector.save_url_dataset(urls, "training_urls.json")