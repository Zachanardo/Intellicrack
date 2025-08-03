"""Database updater for protection signatures with version control.

This module provides automated updating capabilities for the protection database
with version control, signature validation, and rollback functionality.

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

import hashlib
import json
import logging
import shutil
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .signature_database import (
    ArchitectureType, BinarySignature, ImportSignature, ProtectionSignature,
    ProtectionSignatureDatabase, ProtectionType, SectionSignature, StringSignature,
    MatchType
)
import logging

logger = logging.getLogger(__name__)


class DatabaseVersion:
    """Database version information."""
    
    def __init__(self, version: str, timestamp: datetime, checksum: str, description: str = ""):
        """Initialize database version.
        
        Args:
            version: Version string (e.g., "1.0.0")
            timestamp: Version timestamp
            checksum: Database content checksum
            description: Optional version description
        """
        self.version = version
        self.timestamp = timestamp
        self.checksum = checksum
        self.description = description
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'version': self.version,
            'timestamp': self.timestamp.isoformat(),
            'checksum': self.checksum,
            'description': self.description
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'DatabaseVersion':
        """Create from dictionary."""
        return cls(
            version=data['version'],
            timestamp=datetime.fromisoformat(data['timestamp']),
            checksum=data['checksum'],
            description=data.get('description', '')
        )


class DatabaseUpdater:
    """Manages protection database updates with version control."""
    
    def __init__(self, database: ProtectionSignatureDatabase):
        """Initialize the database updater.
        
        Args:
            database: Protection signature database instance
        """
        self.database = database
        self.logger = logging.getLogger(__name__)
        
        # Version control
        self.version_file = self.database.database_path / "version.json"
        self.backup_dir = self.database.database_path / "backups"
        self.backup_dir.mkdir(exist_ok=True)
        
        # Current version info
        self.current_version: Optional[DatabaseVersion] = None
        self._load_version_info()
        
        # Built-in signature definitions
        self._initialize_builtin_signatures()
    
    def _load_version_info(self):
        """Load current version information."""
        try:
            if self.version_file.exists():
                with open(self.version_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                self.current_version = DatabaseVersion.from_dict(data)
            else:
                # Initialize with version 1.0.0
                self.current_version = DatabaseVersion(
                    version="1.0.0",
                    timestamp=datetime.now(),
                    checksum="",
                    description="Initial version"
                )
                self._save_version_info()
                
        except Exception as e:
            self.logger.error(f"Failed to load version info: {e}")
            self.current_version = None
    
    def _save_version_info(self):
        """Save current version information."""
        try:
            if self.current_version:
                with open(self.version_file, 'w', encoding='utf-8') as f:
                    json.dump(self.current_version.to_dict(), f, indent=2)
                    
        except Exception as e:
            self.logger.error(f"Failed to save version info: {e}")
    
    def _initialize_builtin_signatures(self):
        """Initialize built-in protection signatures."""
        self.builtin_signatures = {}
        
        # UPX Packer signatures
        self._add_upx_signatures()
        
        # Themida signatures  
        self._add_themida_signatures()
        
        # VMProtect signatures
        self._add_vmprotect_signatures()
        
        # Denuvo signatures
        self._add_denuvo_signatures()
        
        # Generic packer signatures
        self._add_generic_packer_signatures()
        
        # Anti-debug signatures
        self._add_antidebug_signatures()
        
        # DRM system signatures
        self._add_drm_signatures()
    
    def _add_upx_signatures(self):
        """Add UPX packer signatures."""
        # UPX binary signatures
        upx_binary_sigs = [
            BinarySignature(
                name="UPX Magic",
                pattern=b"UPX!",
                description="UPX packer magic bytes"
            ),
            BinarySignature(
                name="UPX Entry Point",
                pattern=bytes.fromhex("60BE00??40008DBE00??FEFF"),
                mask=bytes.fromhex("FFFF00FFFFFFFFFF00FFFF"),
                description="UPX entry point pattern"
            ),
            BinarySignature(
                name="UPX Unpacker Stub",
                pattern=bytes.fromhex("83EC??8B??24??53565783??FC"),
                mask=bytes.fromhex("FFFF00FF00FF00FFFFFF00FF"),
                description="UPX unpacker stub pattern"
            )
        ]
        
        # UPX string signatures
        upx_string_sigs = [
            StringSignature(
                name="UPX Version String",
                pattern=r"UPX \d+\.\d+",
                match_type=MatchType.REGEX,
                description="UPX version identifier"
            ),
            StringSignature(
                name="UPX Copyright",
                pattern="$Id: UPX",
                description="UPX copyright string"
            )
        ]
        
        # UPX section signatures
        upx_section_sigs = [
            SectionSignature(
                name="UPX0 Section",
                section_name="UPX0",
                min_entropy=7.0,
                description="UPX packed section"
            ),
            SectionSignature(
                name="UPX1 Section", 
                section_name="UPX1",
                max_entropy=1.0,
                description="UPX unpacker section"
            )
        ]
        
        upx_signature = ProtectionSignature(
            id="upx_packer",
            name="UPX Packer",
            protection_type=ProtectionType.PACKER,
            confidence=0.9,
            binary_signatures=upx_binary_sigs,
            string_signatures=upx_string_sigs,
            section_signatures=upx_section_sigs,
            description="Ultimate Packer for eXecutables (UPX) - popular executable packer",
            references=["https://upx.github.io/"]
        )
        
        self.builtin_signatures["upx_packer"] = upx_signature
    
    def _add_themida_signatures(self):
        """Add Themida protection signatures."""
        themida_binary_sigs = [
            BinarySignature(
                name="Themida VM Entry",
                pattern=bytes.fromhex("68????????E8????????83C404C3"),
                mask=bytes.fromhex("FF000000000000000000FFFFFF"),
                description="Themida virtual machine entry pattern"
            ),
            BinarySignature(
                name="Themida String Encryption",
                pattern=bytes.fromhex("8B??24??33??33??33??8B??24"),
                mask=bytes.fromhex("FF00FF00FF00FF00FF00FF00FF"),
                description="Themida string encryption routine"
            )
        ]
        
        themida_string_sigs = [
            StringSignature(
                name="Themida Error Message",
                pattern="THEMIDA",
                case_sensitive=False,
                description="Themida identification string"
            ),
            StringSignature(
                name="Oreans Technologies",
                pattern="Oreans Technologies",
                description="Themida vendor string"
            )
        ]
        
        themida_import_sigs = [
            ImportSignature(
                name="Themida System APIs",
                function_names=[
                    "VirtualAlloc", "VirtualProtect", "VirtualQuery",
                    "GetCurrentProcess", "NtQueryInformationProcess"
                ],
                min_functions=3,
                description="APIs commonly used by Themida"
            )
        ]
        
        themida_signature = ProtectionSignature(
            id="themida_protection",
            name="Themida",
            protection_type=ProtectionType.CODE_PROTECTION,
            confidence=0.85,
            binary_signatures=themida_binary_sigs,
            string_signatures=themida_string_sigs,
            import_signatures=themida_import_sigs,
            description="Themida - Advanced Windows software protection system by Oreans Technologies",
            references=["https://www.oreans.com/themida.php"]
        )
        
        self.builtin_signatures["themida_protection"] = themida_signature
    
    def _add_vmprotect_signatures(self):
        """Add VMProtect signatures."""
        vmprotect_binary_sigs = [
            BinarySignature(
                name="VMProtect Entry",
                pattern=bytes.fromhex("9C60E8000000005D81ED????????8BD5"),
                mask=bytes.fromhex("FFFFFFFFFFFFFFFFFF000000FFFFFF"),
                description="VMProtect entry point pattern"
            ),
            BinarySignature(
                name="VMProtect VM Handler",
                pattern=bytes.fromhex("8B??8B??24??03??8B??FF??"),
                mask=bytes.fromhex("FF00FF00FF00FF00FF00FF00"),
                description="VMProtect virtual machine handler"
            )
        ]
        
        vmprotect_string_sigs = [
            StringSignature(
                name="VMProtect String",
                pattern="VMProtect",
                description="VMProtect identification string"
            ),
            StringSignature(
                name="VMProtect Error",
                pattern="Please restart application",
                description="VMProtect error message"
            )
        ]
        
        vmprotect_section_sigs = [
            SectionSignature(
                name="VMProtect Code Section",
                section_name=".vmp0",
                min_entropy=7.5,
                description="VMProtect virtualized code section"
            ),
            SectionSignature(
                name="VMProtect Data Section",
                section_name=".vmp1", 
                description="VMProtect data section"
            )
        ]
        
        vmprotect_signature = ProtectionSignature(
            id="vmprotect",
            name="VMProtect",
            protection_type=ProtectionType.CODE_PROTECTION,
            confidence=0.9,
            binary_signatures=vmprotect_binary_sigs,
            string_signatures=vmprotect_string_sigs,
            section_signatures=vmprotect_section_sigs,
            description="VMProtect - Code virtualization and licensing protection",
            references=["https://vmpsoft.com/"]
        )
        
        self.builtin_signatures["vmprotect"] = vmprotect_signature
    
    def _add_denuvo_signatures(self):
        """Add Denuvo Anti-Tamper signatures."""
        denuvo_string_sigs = [
            StringSignature(
                name="Denuvo String",
                pattern="denuvo",
                case_sensitive=False,
                description="Denuvo identification string"
            ),
            StringSignature(
                name="Denuvo DLL",
                pattern="denuvo_",
                case_sensitive=False,
                description="Denuvo DLL reference"
            )
        ]
        
        denuvo_import_sigs = [
            ImportSignature(
                name="Denuvo APIs",
                function_names=[
                    "CryptAcquireContext", "CryptCreateHash", "CryptHashData",
                    "GetVolumeInformation", "GetSystemInfo"
                ],
                min_functions=3,
                description="APIs typically used by Denuvo"
            )
        ]
        
        denuvo_signature = ProtectionSignature(
            id="denuvo_antitamper",
            name="Denuvo Anti-Tamper",
            protection_type=ProtectionType.DRM,
            confidence=0.8,
            string_signatures=denuvo_string_sigs,
            import_signatures=denuvo_import_sigs,
            description="Denuvo Anti-Tamper - Advanced game copy protection",
            references=["https://www.denuvo.com/"]
        )
        
        self.builtin_signatures["denuvo_antitamper"] = denuvo_signature
    
    def _add_generic_packer_signatures(self):
        """Add generic packer detection signatures."""
        generic_import_sigs = [
            ImportSignature(
                name="Packer APIs",
                function_names=[
                    "VirtualAlloc", "VirtualProtect", "LoadLibrary",
                    "GetProcAddress", "CreateThread"
                ],
                min_functions=4,
                description="Common packer API pattern"
            )
        ]
        
        generic_section_sigs = [
            SectionSignature(
                name="High Entropy Section",
                min_entropy=7.8,
                min_size=1024,
                description="Section with very high entropy (likely packed)"
            )
        ]
        
        generic_signature = ProtectionSignature(
            id="generic_packer",
            name="Generic Packer",
            protection_type=ProtectionType.PACKER,
            confidence=0.6,
            import_signatures=generic_import_sigs,
            section_signatures=generic_section_sigs,
            description="Generic packer detection based on common characteristics"
        )
        
        self.builtin_signatures["generic_packer"] = generic_signature
    
    def _add_antidebug_signatures(self):
        """Add anti-debugging signatures."""
        antidebug_binary_sigs = [
            BinarySignature(
                name="IsDebuggerPresent",
                pattern=bytes.fromhex("FF15????????85C0"),
                mask=bytes.fromhex("FFFF000000FFFFFF"),
                description="IsDebuggerPresent API call pattern"
            ),
            BinarySignature(
                name="PEB Debug Flag Check",
                pattern=bytes.fromhex("648B??30008B??0C80??02??"),
                mask=bytes.fromhex("FFFF00FFFF00FFFF00FF00"),
                description="PEB BeingDebugged flag check"
            )
        ]
        
        antidebug_import_sigs = [
            ImportSignature(
                name="Debug Detection APIs",
                function_names=[
                    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                    "NtQueryInformationProcess", "OutputDebugString"
                ],
                min_functions=2,
                description="APIs used for debugger detection"
            )
        ]
        
        antidebug_signature = ProtectionSignature(
            id="anti_debug",
            name="Anti-Debug Protection",
            protection_type=ProtectionType.ANTI_DEBUG,
            confidence=0.7,
            binary_signatures=antidebug_binary_sigs,
            import_signatures=antidebug_import_sigs,
            description="Generic anti-debugging protection techniques"
        )
        
        self.builtin_signatures["anti_debug"] = antidebug_signature
    
    def _add_drm_signatures(self):
        """Add DRM system signatures."""
        # SafeDisc signatures
        safedisc_string_sigs = [
            StringSignature(
                name="SafeDisc String",
                pattern="SafeDisc",
                description="SafeDisc DRM identifier"
            ),
            StringSignature(
                name="SafeDisc Driver",
                pattern="secdrv.sys",
                description="SafeDisc driver reference"
            )
        ]
        
        safedisc_signature = ProtectionSignature(
            id="safedisc_drm",
            name="SafeDisc",
            protection_type=ProtectionType.DRM,
            confidence=0.85,
            string_signatures=safedisc_string_sigs,
            description="SafeDisc copy protection system",
            references=["https://en.wikipedia.org/wiki/SafeDisc"]
        )
        
        # SecuROM signatures
        securom_string_sigs = [
            StringSignature(
                name="SecuROM String",
                pattern="SecuROM",
                description="SecuROM DRM identifier"
            ),
            StringSignature(
                name="SecuROM File",
                pattern="secur32.dll",
                description="SecuROM component reference"
            )
        ]
        
        securom_signature = ProtectionSignature(
            id="securom_drm",
            name="SecuROM",
            protection_type=ProtectionType.DRM,
            confidence=0.85,
            string_signatures=securom_string_sigs,
            description="SecuROM digital rights management system"
        )
        
        self.builtin_signatures["safedisc_drm"] = safedisc_signature
        self.builtin_signatures["securom_drm"] = securom_signature
    
    def install_builtin_signatures(self) -> bool:
        """Install all built-in signatures to the database.
        
        Returns:
            True if signatures installed successfully
        """
        try:
            installed_count = 0
            
            for sig_id, signature in self.builtin_signatures.items():
                if self.database.add_signature(signature):
                    installed_count += 1
                    self.logger.info(f"Installed signature: {signature.name}")
                else:
                    self.logger.warning(f"Failed to install signature: {signature.name}")
            
            if installed_count > 0:
                self._increment_version(f"Installed {installed_count} built-in signatures")
                self.logger.info(f"Successfully installed {installed_count} built-in signatures")
            
            return installed_count > 0
            
        except Exception as e:
            self.logger.error(f"Failed to install built-in signatures: {e}")
            return False
    
    def update_signature(self, signature: ProtectionSignature) -> bool:
        """Update an existing signature or add new one.
        
        Args:
            signature: Signature to update/add
            
        Returns:
            True if update successful
        """
        try:
            # Check if signature exists
            existing = self.database.get_signature_by_id(signature.id)
            is_update = existing is not None
            
            # Create backup before update
            if is_update:
                self._create_backup()
            
            # Update signature timestamp
            signature.updated_date = datetime.now()
            
            # Add/update signature
            success = self.database.add_signature(signature)
            
            if success:
                action = "Updated" if is_update else "Added"
                self._increment_version(f"{action} signature: {signature.name}")
                self.logger.info(f"{action} signature: {signature.name}")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Failed to update signature {signature.id}: {e}")
            return False
    
    def remove_signature(self, signature_id: str) -> bool:
        """Remove a signature from the database.
        
        Args:
            signature_id: ID of signature to remove
            
        Returns:
            True if removal successful
        """
        try:
            signature = self.database.get_signature_by_id(signature_id)
            if not signature:
                self.logger.warning(f"Signature not found: {signature_id}")
                return False
            
            # Create backup before removal
            self._create_backup()
            
            # Find and remove signature file
            for prot_type in ProtectionType:
                subdir = self.database.database_path / prot_type.value
                sig_file = subdir / f"{signature_id}.json"
                if sig_file.exists():
                    sig_file.unlink()
                    
                    # Remove from memory
                    if signature_id in self.database.signatures:
                        del self.database.signatures[signature_id]
                    
                    # Update index
                    if prot_type in self.database.signature_index:
                        if signature_id in self.database.signature_index[prot_type]:
                            self.database.signature_index[prot_type].remove(signature_id)
                    
                    self._increment_version(f"Removed signature: {signature.name}")
                    self.logger.info(f"Removed signature: {signature.name}")
                    return True
            
            self.logger.warning(f"Signature file not found for: {signature_id}")
            return False
            
        except Exception as e:
            self.logger.error(f"Failed to remove signature {signature_id}: {e}")
            return False
    
    def _create_backup(self) -> str:
        """Create a backup of the current database.
        
        Returns:
            Path to backup directory
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = self.backup_dir / f"backup_{timestamp}"
        
        try:
            # Copy entire database directory
            shutil.copytree(
                self.database.database_path,
                backup_path,
                ignore=shutil.ignore_patterns("backups", "*.tmp", "*.log")
            )
            
            self.logger.info(f"Created backup: {backup_path}")
            return str(backup_path)
            
        except Exception as e:
            self.logger.error(f"Failed to create backup: {e}")
            raise
    
    def restore_backup(self, backup_path: str) -> bool:
        """Restore database from backup.
        
        Args:
            backup_path: Path to backup directory
            
        Returns:
            True if restore successful
        """
        try:
            backup_path_obj = Path(backup_path)
            if not backup_path_obj.exists():
                self.logger.error(f"Backup not found: {backup_path}")
                return False
            
            # Create current backup before restore
            current_backup = self._create_backup()
            
            try:
                # Clear current database (except backups)
                for item in self.database.database_path.iterdir():
                    if item.name != "backups" and item.is_dir():
                        shutil.rmtree(item)
                    elif item.name != "backups" and item.is_file():
                        item.unlink()
                
                # Copy backup files
                for item in backup_path_obj.iterdir():
                    if item.name != "backups":
                        if item.is_dir():
                            shutil.copytree(item, self.database.database_path / item.name)
                        else:
                            shutil.copy2(item, self.database.database_path / item.name)
                
                # Reload database and version info
                self.database.load_database()
                self._load_version_info()
                
                self.logger.info(f"Database restored from backup: {backup_path}")
                return True
                
            except Exception as e:
                # Restore failed, try to restore current backup
                self.logger.error(f"Restore failed, attempting rollback: {e}")
                self.restore_backup(current_backup)
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to restore backup: {e}")
            return False
    
    def list_backups(self) -> List[Dict[str, Any]]:
        """List available backups.
        
        Returns:
            List of backup information
        """
        backups = []
        
        try:
            for backup_dir in sorted(self.backup_dir.iterdir()):
                if backup_dir.is_dir() and backup_dir.name.startswith("backup_"):
                    # Parse timestamp from directory name
                    timestamp_str = backup_dir.name.replace("backup_", "")
                    try:
                        timestamp = datetime.strptime(timestamp_str, "%Y%m%d_%H%M%S")
                        
                        # Get backup size
                        size = sum(f.stat().st_size for f in backup_dir.rglob('*') if f.is_file())
                        
                        backups.append({
                            'path': str(backup_dir),
                            'timestamp': timestamp.isoformat(),
                            'size_bytes': size,
                            'name': backup_dir.name
                        })
                        
                    except ValueError:
                        continue
                        
        except Exception as e:
            self.logger.error(f"Failed to list backups: {e}")
        
        return backups
    
    def cleanup_old_backups(self, keep_count: int = 10) -> int:
        """Clean up old backups, keeping only the most recent ones.
        
        Args:
            keep_count: Number of backups to keep
            
        Returns:
            Number of backups removed
        """
        try:
            backups = self.list_backups()
            if len(backups) <= keep_count:
                return 0
            
            # Sort by timestamp (oldest first)
            backups.sort(key=lambda x: x['timestamp'])
            
            # Remove oldest backups
            removed_count = 0
            for backup in backups[:-keep_count]:
                backup_path = Path(backup['path'])
                if backup_path.exists():
                    shutil.rmtree(backup_path)
                    removed_count += 1
                    self.logger.info(f"Removed old backup: {backup['name']}")
            
            return removed_count
            
        except Exception as e:
            self.logger.error(f"Failed to cleanup backups: {e}")
            return 0
    
    def _increment_version(self, description: str = ""):
        """Increment database version.
        
        Args:
            description: Description of changes
        """
        try:
            if not self.current_version:
                return
            
            # Parse current version
            version_parts = self.current_version.version.split('.')
            if len(version_parts) >= 3:
                # Increment patch version
                patch = int(version_parts[2]) + 1
                new_version = f"{version_parts[0]}.{version_parts[1]}.{patch}"
            else:
                new_version = "1.0.1"
            
            # Calculate new checksum
            checksum = self._calculate_database_checksum()
            
            # Update version
            self.current_version = DatabaseVersion(
                version=new_version,
                timestamp=datetime.now(),
                checksum=checksum,
                description=description
            )
            
            self._save_version_info()
            
        except Exception as e:
            self.logger.error(f"Failed to increment version: {e}")
    
    def _calculate_database_checksum(self) -> str:
        """Calculate checksum of database contents.
        
        Returns:
            SHA256 checksum of database
        """
        try:
            hasher = hashlib.sha256()
            
            # Include all signature files in checksum
            for signature_file in sorted(self.database.database_path.rglob("*.json")):
                if signature_file.name != "version.json":
                    with open(signature_file, 'rb') as f:
                        hasher.update(f.read())
            
            return hasher.hexdigest()
            
        except Exception as e:
            self.logger.error(f"Failed to calculate checksum: {e}")
            return ""
    
    def verify_database_integrity(self) -> Dict[str, Any]:
        """Verify database integrity.
        
        Returns:
            Dictionary with verification results
        """
        results = {
            'valid': True,
            'errors': [],
            'warnings': [],
            'checksum_match': False,
            'signature_count': 0,
            'corrupt_signatures': []
        }
        
        try:
            # Check version info
            if not self.current_version:
                results['errors'].append("No version information found")
                results['valid'] = False
            
            # Verify checksum
            if self.current_version:
                current_checksum = self._calculate_database_checksum()
                results['checksum_match'] = current_checksum == self.current_version.checksum
                if not results['checksum_match']:
                    results['warnings'].append("Database checksum mismatch - database may have been modified")
            
            # Load and validate signatures
            signature_count = 0
            for signature_file in self.database.database_path.rglob("*.json"):
                if signature_file.name == "version.json":
                    continue
                
                try:
                    with open(signature_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    
                    # Basic validation
                    required_fields = ['id', 'name', 'protection_type']
                    for field in required_fields:
                        if field not in data:
                            results['corrupt_signatures'].append(f"{signature_file.name}: Missing field '{field}'")
                    
                    signature_count += 1
                    
                except json.JSONDecodeError as e:
                    results['corrupt_signatures'].append(f"{signature_file.name}: Invalid JSON - {e}")
                except Exception as e:
                    results['corrupt_signatures'].append(f"{signature_file.name}: Error - {e}")
            
            results['signature_count'] = signature_count
            
            if results['corrupt_signatures']:
                results['errors'].extend(results['corrupt_signatures'])
                results['valid'] = False
            
        except Exception as e:
            results['errors'].append(f"Verification failed: {e}")
            results['valid'] = False
        
        return results
    
    def get_version_info(self) -> Optional[Dict[str, Any]]:
        """Get current version information.
        
        Returns:
            Version information dictionary
        """
        if self.current_version:
            return self.current_version.to_dict()
        return None