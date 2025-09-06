"""
Phase 6.3: Evidence Requirements Validator

This module implements comprehensive validation of evidence collection requirements,
ensuring all required forensic evidence is present and properly authenticated.
"""

import hashlib
import logging
import json
import subprocess
import time
import zipfile
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass, asdict
from pathlib import Path
from datetime import datetime
from enum import Enum
import gnupg
import mimetypes

class EvidenceResult(Enum):
    """Evidence validation result."""
    COMPLETE = "COMPLETE"
    INCOMPLETE = "INCOMPLETE"
    CORRUPTED = "CORRUPTED"
    INVALID = "INVALID"

class EvidenceType(Enum):
    """Types of required evidence."""
    MEMORY_DUMPS = "memory_dumps"
    NETWORK_CAPTURE = "network_capture"
    API_TRACE = "api_trace"
    SCREEN_RECORDING = "screen_recording"
    FILE_SYSTEM_CHANGES = "file_system_changes"
    REGISTRY_CHANGES = "registry_changes"
    PROCESS_SNAPSHOTS = "process_snapshots"
    GPG_SIGNATURE = "gpg_signature"

@dataclass
class EvidenceItem:
    """Structure for individual evidence item."""
    evidence_type: EvidenceType
    file_path: Path
    file_hash: str
    file_size: int
    timestamp: str
    description: str
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}

@dataclass
class EvidencePackage:
    """Complete evidence package structure."""
    package_id: str
    creation_timestamp: str
    evidence_items: List[EvidenceItem]
    integrity_manifest: Dict[str, str]
    gpg_signature: Optional[str] = None
    chain_of_custody: List[Dict[str, str]] = None
    
    def __post_init__(self):
        if self.chain_of_custody is None:
            self.chain_of_custody = []

class EvidenceRequirementsValidator:
    """
    Implements Phase 6.3 requirements for evidence validation.
    
    Missing ANY evidence type = automatic FAIL:
    - Memory dumps: Before, during, and after bypass (minimum 3)
    - Network capture: Full PCAP file showing no license server contact
    - API trace: Complete log of Win32 API calls during execution
    - Screen recording: Timestamped video of entire test execution
    - File system changes: Complete list of created/modified files
    - Registry changes: Diff of registry before and after
    - Process snapshots: Snapshot of all running processes during test
    - GPG signature: All evidence signed with valid GPG key
    """
    
    def __init__(self, evidence_path: Path, gpg_key_id: str = None):
        """Initialize evidence requirements validator."""
        self.evidence_path = Path(evidence_path)
        self.gpg_key_id = gpg_key_id or "intellicrack-validation@security.local"
        self.logger = logging.getLogger(__name__)
        
        # Create evidence directory if it doesn't exist
        self.evidence_path.mkdir(parents=True, exist_ok=True)
        
        # Initialize GPG for signature verification
        self.gpg = gnupg.GPG()
        
        # Define required evidence types and their criteria
        self.required_evidence = {
            EvidenceType.MEMORY_DUMPS: {
                "minimum_files": 3,
                "file_extensions": [".dmp", ".mem"],
                "min_size_mb": 1,
                "description": "Memory dumps before, during, and after bypass"
            },
            EvidenceType.NETWORK_CAPTURE: {
                "minimum_files": 1,
                "file_extensions": [".pcap", ".pcapng"],
                "min_size_mb": 0.1,
                "description": "Complete network capture showing no license server contact"
            },
            EvidenceType.API_TRACE: {
                "minimum_files": 1,
                "file_extensions": [".log", ".txt", ".json"],
                "min_size_mb": 0.1,
                "description": "Complete Win32 API call trace"
            },
            EvidenceType.SCREEN_RECORDING: {
                "minimum_files": 1,
                "file_extensions": [".mp4", ".avi", ".mkv"],
                "min_size_mb": 10,
                "description": "Timestamped video of entire test execution"
            },
            EvidenceType.FILE_SYSTEM_CHANGES: {
                "minimum_files": 1,
                "file_extensions": [".json", ".txt", ".log"],
                "min_size_mb": 0.001,
                "description": "Complete list of file system changes"
            },
            EvidenceType.REGISTRY_CHANGES: {
                "minimum_files": 1,
                "file_extensions": [".reg", ".json", ".txt"],
                "min_size_mb": 0.001,
                "description": "Registry diff before and after"
            },
            EvidenceType.PROCESS_SNAPSHOTS: {
                "minimum_files": 1,
                "file_extensions": [".json", ".txt", ".csv"],
                "min_size_mb": 0.001,
                "description": "Process snapshots during test execution"
            }
        }
    
    def validate_evidence_package(self, package_path: Path) -> Tuple[EvidenceResult, Dict[str, Any]]:
        """
        Validate complete evidence package against Phase 6.3 requirements.
        
        Args:
            package_path: Path to evidence package directory or archive
            
        Returns:
            Tuple of (EvidenceResult, detailed_report)
        """
        validation_report = {
            "timestamp": self._get_timestamp(),
            "package_path": str(package_path),
            "validation_results": {},
            "overall_result": EvidenceResult.INCOMPLETE,
            "missing_evidence": [],
            "corrupted_evidence": [],
            "integrity_violations": [],
            "evidence_summary": {}
        }
        
        try:
            # Extract or access evidence package
            evidence_items = self._extract_evidence_package(package_path)
            
            # Group evidence by type
            evidence_by_type = self._categorize_evidence(evidence_items)
            
            # Validate each required evidence type
            validation_results = {}
            all_evidence_complete = True
            
            for evidence_type, requirements in self.required_evidence.items():
                type_validation = self._validate_evidence_type(
                    evidence_type,
                    evidence_by_type.get(evidence_type, []),
                    requirements
                )
                validation_results[evidence_type.value] = type_validation
                
                if not type_validation["complete"]:
                    all_evidence_complete = False
                    validation_report["missing_evidence"].extend(type_validation.get("missing_items", []))
            
            # Validate GPG signatures
            signature_validation = self._validate_gpg_signatures(evidence_items)
            validation_results["gpg_signatures"] = signature_validation
            
            if not signature_validation["valid"]:
                all_evidence_complete = False
                validation_report["integrity_violations"].extend(signature_validation.get("invalid_signatures", []))
            
            # Validate file integrity
            integrity_validation = self._validate_file_integrity(evidence_items)
            validation_results["file_integrity"] = integrity_validation
            
            if not integrity_validation["intact"]:
                all_evidence_complete = False
                validation_report["corrupted_evidence"].extend(integrity_validation.get("corrupted_files", []))
            
            # Validate evidence completeness and consistency
            consistency_validation = self._validate_evidence_consistency(evidence_items)
            validation_results["consistency"] = consistency_validation
            
            if not consistency_validation["consistent"]:
                all_evidence_complete = False
            
            # Determine overall result
            validation_report["validation_results"] = validation_results
            
            if all_evidence_complete:
                validation_report["overall_result"] = EvidenceResult.COMPLETE
            elif validation_report["corrupted_evidence"]:
                validation_report["overall_result"] = EvidenceResult.CORRUPTED
            else:
                validation_report["overall_result"] = EvidenceResult.INCOMPLETE
            
            # Generate evidence summary
            validation_report["evidence_summary"] = self._generate_evidence_summary(evidence_items)
            
        except Exception as e:
            self.logger.error(f"Evidence validation failed: {e}")
            validation_report["overall_result"] = EvidenceResult.INVALID
            validation_report["error"] = str(e)
            
        return validation_report["overall_result"], validation_report
    
    def _extract_evidence_package(self, package_path: Path) -> List[EvidenceItem]:
        """Extract evidence items from package directory or archive."""
        evidence_items = []
        
        try:
            if package_path.is_dir():
                # Directory-based evidence package
                evidence_items = self._scan_directory_evidence(package_path)
            elif package_path.suffix.lower() in ['.zip', '.7z', '.tar', '.gz']:
                # Archived evidence package
                evidence_items = self._extract_archived_evidence(package_path)
            else:
                raise ValueError(f"Unsupported package format: {package_path}")
                
        except Exception as e:
            self.logger.error(f"Failed to extract evidence package: {e}")
            raise
            
        return evidence_items
    
    def _scan_directory_evidence(self, directory: Path) -> List[EvidenceItem]:
        """Scan directory for evidence files."""
        evidence_items = []
        
        try:
            for file_path in directory.rglob("*"):
                if file_path.is_file() and not file_path.name.startswith('.'):
                    evidence_type = self._determine_evidence_type(file_path)
                    if evidence_type:
                        evidence_item = EvidenceItem(
                            evidence_type=evidence_type,
                            file_path=file_path,
                            file_hash=self._calculate_file_hash(file_path),
                            file_size=file_path.stat().st_size,
                            timestamp=datetime.fromtimestamp(file_path.stat().st_mtime).isoformat(),
                            description=self._generate_file_description(file_path, evidence_type),
                            metadata=self._extract_file_metadata(file_path)
                        )
                        evidence_items.append(evidence_item)
                        
        except Exception as e:
            self.logger.error(f"Failed to scan directory evidence: {e}")
            raise
            
        return evidence_items
    
    def _extract_archived_evidence(self, archive_path: Path) -> List[EvidenceItem]:
        """Extract evidence from archived package."""
        evidence_items = []
        temp_dir = self.evidence_path / "temp_extraction"
        
        try:
            # Create temporary extraction directory
            temp_dir.mkdir(exist_ok=True)
            
            if archive_path.suffix.lower() == '.zip':
                with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                    zip_ref.extractall(temp_dir)
            else:
                # Use system extraction tools for other formats
                subprocess.run([
                    "7z", "x", str(archive_path), f"-o{temp_dir}", "-y"
                ], check=True, capture_output=True)
            
            # Scan extracted files
            evidence_items = self._scan_directory_evidence(temp_dir)
            
        except Exception as e:
            self.logger.error(f"Failed to extract archived evidence: {e}")
            raise
        finally:
            # Cleanup temporary directory
            if temp_dir.exists():
                import shutil
                shutil.rmtree(temp_dir, ignore_errors=True)
                
        return evidence_items
    
    def _determine_evidence_type(self, file_path: Path) -> Optional[EvidenceType]:
        """Determine evidence type from file characteristics."""
        file_name = file_path.name.lower()
        file_suffix = file_path.suffix.lower()
        
        # Memory dumps
        if file_suffix in ['.dmp', '.mem'] or 'memory' in file_name or 'dump' in file_name:
            return EvidenceType.MEMORY_DUMPS
            
        # Network captures
        elif file_suffix in ['.pcap', '.pcapng'] or 'network' in file_name or 'capture' in file_name:
            return EvidenceType.NETWORK_CAPTURE
            
        # API traces
        elif ('api' in file_name and file_suffix in ['.log', '.txt', '.json']) or 'trace' in file_name:
            return EvidenceType.API_TRACE
            
        # Screen recordings
        elif file_suffix in ['.mp4', '.avi', '.mkv', '.mov'] or 'screen' in file_name or 'video' in file_name:
            return EvidenceType.SCREEN_RECORDING
            
        # File system changes
        elif 'filesystem' in file_name or 'files' in file_name or 'changes' in file_name:
            return EvidenceType.FILE_SYSTEM_CHANGES
            
        # Registry changes
        elif file_suffix == '.reg' or 'registry' in file_name or 'reg_' in file_name:
            return EvidenceType.REGISTRY_CHANGES
            
        # Process snapshots
        elif 'process' in file_name or 'snapshot' in file_name or 'tasklist' in file_name:
            return EvidenceType.PROCESS_SNAPSHOTS
            
        # GPG signatures
        elif file_suffix in ['.sig', '.asc'] or 'signature' in file_name:
            return EvidenceType.GPG_SIGNATURE
            
        return None
    
    def _categorize_evidence(self, evidence_items: List[EvidenceItem]) -> Dict[EvidenceType, List[EvidenceItem]]:
        """Categorize evidence items by type."""
        categorized = {}
        
        for item in evidence_items:
            if item.evidence_type not in categorized:
                categorized[item.evidence_type] = []
            categorized[item.evidence_type].append(item)
            
        return categorized
    
    def _validate_evidence_type(self, evidence_type: EvidenceType, 
                              evidence_items: List[EvidenceItem], 
                              requirements: Dict[str, Any]) -> Dict[str, Any]:
        """Validate specific evidence type against requirements."""
        validation_result = {
            "evidence_type": evidence_type.value,
            "complete": False,
            "items_found": len(evidence_items),
            "minimum_required": requirements["minimum_files"],
            "valid_items": [],
            "invalid_items": [],
            "missing_items": []
        }
        
        try:
            # Check minimum file count
            if len(evidence_items) < requirements["minimum_files"]:
                missing_count = requirements["minimum_files"] - len(evidence_items)
                validation_result["missing_items"] = [
                    f"Missing {missing_count} {evidence_type.value} file(s)"
                ]
            
            # Validate each evidence item
            for item in evidence_items:
                item_validation = self._validate_evidence_item(item, requirements)
                
                if item_validation["valid"]:
                    validation_result["valid_items"].append({
                        "file_path": str(item.file_path),
                        "file_hash": item.file_hash,
                        "file_size_mb": item.file_size / (1024 * 1024)
                    })
                else:
                    validation_result["invalid_items"].append({
                        "file_path": str(item.file_path),
                        "issues": item_validation["issues"]
                    })
            
            # Determine completeness
            validation_result["complete"] = (
                len(evidence_items) >= requirements["minimum_files"] and
                len(validation_result["valid_items"]) >= requirements["minimum_files"]
            )
            
        except Exception as e:
            self.logger.error(f"Evidence type validation failed for {evidence_type.value}: {e}")
            validation_result["error"] = str(e)
            
        return validation_result
    
    def _validate_evidence_item(self, item: EvidenceItem, requirements: Dict[str, Any]) -> Dict[str, Any]:
        """Validate individual evidence item."""
        validation = {"valid": True, "issues": []}
        
        try:
            # Check file exists and is accessible
            if not item.file_path.exists():
                validation["valid"] = False
                validation["issues"].append("File does not exist")
                return validation
            
            # Check file extension
            if item.file_path.suffix.lower() not in requirements["file_extensions"]:
                validation["issues"].append(f"Invalid file extension: {item.file_path.suffix}")
            
            # Check minimum file size
            min_size_bytes = requirements["min_size_mb"] * 1024 * 1024
            if item.file_size < min_size_bytes:
                validation["issues"].append(f"File too small: {item.file_size} bytes < {min_size_bytes} bytes")
            
            # Validate file integrity (hash verification)
            current_hash = self._calculate_file_hash(item.file_path)
            if current_hash != item.file_hash:
                validation["valid"] = False
                validation["issues"].append("File hash mismatch - possible corruption")
            
            # Additional format-specific validation
            format_validation = self._validate_file_format(item)
            if not format_validation["valid"]:
                validation["issues"].extend(format_validation["issues"])
            
            # Mark as invalid if any issues found
            if validation["issues"]:
                validation["valid"] = False
                
        except Exception as e:
            validation["valid"] = False
            validation["issues"].append(f"Validation error: {str(e)}")
            
        return validation
    
    def _validate_file_format(self, item: EvidenceItem) -> Dict[str, Any]:
        """Validate file format and structure."""
        validation = {"valid": True, "issues": []}
        
        try:
            if item.evidence_type == EvidenceType.NETWORK_CAPTURE:
                # Validate PCAP file format
                validation = self._validate_pcap_format(item.file_path)
                
            elif item.evidence_type == EvidenceType.SCREEN_RECORDING:
                # Validate video file format
                validation = self._validate_video_format(item.file_path)
                
            elif item.evidence_type == EvidenceType.API_TRACE:
                # Validate API trace log format
                validation = self._validate_api_trace_format(item.file_path)
                
            elif item.evidence_type == EvidenceType.MEMORY_DUMPS:
                # Validate memory dump format
                validation = self._validate_memory_dump_format(item.file_path)
                
        except Exception as e:
            validation["valid"] = False
            validation["issues"].append(f"Format validation error: {str(e)}")
            
        return validation
    
    def _validate_pcap_format(self, file_path: Path) -> Dict[str, Any]:
        """Validate PCAP file format and content."""
        validation = {"valid": True, "issues": []}
        
        try:
            # Check PCAP magic number
            with open(file_path, 'rb') as f:
                magic = f.read(4)
                
            # PCAP magic numbers (both endianness)
            pcap_magic = [b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4']
            pcapng_magic = [b'\x0a\x0d\x0d\x0a']
            
            if magic not in pcap_magic + pcapng_magic:
                validation["valid"] = False
                validation["issues"].append("Invalid PCAP file format")
                
        except Exception as e:
            validation["valid"] = False
            validation["issues"].append(f"PCAP validation error: {str(e)}")
            
        return validation
    
    def _validate_video_format(self, file_path: Path) -> Dict[str, Any]:
        """Validate video file format and properties."""
        validation = {"valid": True, "issues": []}
        
        try:
            # Check if file can be opened as video
            import cv2
            cap = cv2.VideoCapture(str(file_path))
            
            if not cap.isOpened():
                validation["valid"] = False
                validation["issues"].append("Cannot open video file")
            else:
                # Check video properties
                frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
                fps = cap.get(cv2.CAP_PROP_FPS)
                duration = frame_count / fps if fps > 0 else 0
                
                if duration < 30:  # Minimum 30 seconds
                    validation["issues"].append(f"Video too short: {duration:.1f} seconds")
                
                cap.release()
                
        except ImportError:
            # OpenCV not available, basic format check
            mime_type, _ = mimetypes.guess_type(str(file_path))
            if not mime_type or not mime_type.startswith('video/'):
                validation["issues"].append("File does not appear to be a video")
        except Exception as e:
            validation["valid"] = False
            validation["issues"].append(f"Video validation error: {str(e)}")
            
        return validation
    
    def _validate_api_trace_format(self, file_path: Path) -> Dict[str, Any]:
        """Validate API trace log format and content."""
        validation = {"valid": True, "issues": []}
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(1024)  # Read first 1KB
                
            # Check for common API trace patterns
            api_patterns = ['CreateFile', 'RegOpenKey', 'LoadLibrary', 'VirtualAlloc', 'Process32']
            
            if not any(pattern in content for pattern in api_patterns):
                validation["issues"].append("No recognizable API call patterns found")
                
        except Exception as e:
            validation["valid"] = False
            validation["issues"].append(f"API trace validation error: {str(e)}")
            
        return validation
    
    def _validate_memory_dump_format(self, file_path: Path) -> Dict[str, Any]:
        """Validate memory dump format."""
        validation = {"valid": True, "issues": []}
        
        try:
            # Check for common memory dump signatures
            with open(file_path, 'rb') as f:
                header = f.read(16)
                
            # Windows memory dump signature
            if b'PAGEDUMP' not in header and b'PAGE' not in header:
                # Could be raw memory dump, check for PE headers
                if b'MZ' not in header[:1024]:  # Check first 1KB for PE signature
                    validation["issues"].append("Unrecognized memory dump format")
                    
        except Exception as e:
            validation["valid"] = False
            validation["issues"].append(f"Memory dump validation error: {str(e)}")
            
        return validation
    
    def _validate_gpg_signatures(self, evidence_items: List[EvidenceItem]) -> Dict[str, Any]:
        """Validate GPG signatures for all evidence."""
        validation = {
            "valid": True,
            "signed_items": 0,
            "unsigned_items": 0,
            "invalid_signatures": [],
            "signature_details": []
        }
        
        try:
            for item in evidence_items:
                if item.evidence_type == EvidenceType.GPG_SIGNATURE:
                    continue  # Skip signature files themselves
                
                # Look for corresponding signature file
                sig_file = item.file_path.with_suffix(item.file_path.suffix + '.sig')
                asc_file = item.file_path.with_suffix(item.file_path.suffix + '.asc')
                
                signature_file = None
                if sig_file.exists():
                    signature_file = sig_file
                elif asc_file.exists():
                    signature_file = asc_file
                
                if signature_file:
                    # Verify signature
                    sig_validation = self._verify_gpg_signature(item.file_path, signature_file)
                    
                    if sig_validation["valid"]:
                        validation["signed_items"] += 1
                        validation["signature_details"].append({
                            "file": str(item.file_path),
                            "signature_file": str(signature_file),
                            "signer": sig_validation.get("signer", "unknown")
                        })
                    else:
                        validation["invalid_signatures"].append({
                            "file": str(item.file_path),
                            "signature_file": str(signature_file),
                            "error": sig_validation.get("error", "unknown")
                        })
                else:
                    validation["unsigned_items"] += 1
                    validation["invalid_signatures"].append({
                        "file": str(item.file_path),
                        "error": "No signature file found"
                    })
            
            # All evidence must be signed
            if validation["unsigned_items"] > 0 or validation["invalid_signatures"]:
                validation["valid"] = False
                
        except Exception as e:
            validation["valid"] = False
            validation["error"] = str(e)
            
        return validation
    
    def _verify_gpg_signature(self, file_path: Path, signature_file: Path) -> Dict[str, Any]:
        """Verify GPG signature for a file."""
        try:
            with open(signature_file, 'rb') as sig_f:
                verification = self.gpg.verify_file(sig_f, str(file_path))
                
            if verification.valid:
                return {
                    "valid": True,
                    "signer": verification.username,
                    "key_id": verification.key_id,
                    "timestamp": verification.creation_date
                }
            else:
                return {
                    "valid": False,
                    "error": verification.status
                }
                
        except Exception as e:
            return {
                "valid": False,
                "error": str(e)
            }
    
    def _validate_file_integrity(self, evidence_items: List[EvidenceItem]) -> Dict[str, Any]:
        """Validate file integrity using hashes."""
        validation = {
            "intact": True,
            "verified_files": 0,
            "corrupted_files": [],
            "hash_mismatches": []
        }
        
        try:
            for item in evidence_items:
                current_hash = self._calculate_file_hash(item.file_path)
                
                if current_hash == item.file_hash:
                    validation["verified_files"] += 1
                else:
                    validation["intact"] = False
                    validation["corrupted_files"].append(str(item.file_path))
                    validation["hash_mismatches"].append({
                        "file": str(item.file_path),
                        "expected_hash": item.file_hash,
                        "actual_hash": current_hash
                    })
                    
        except Exception as e:
            validation["intact"] = False
            validation["error"] = str(e)
            
        return validation
    
    def _validate_evidence_consistency(self, evidence_items: List[EvidenceItem]) -> Dict[str, Any]:
        """Validate evidence consistency and timeline."""
        validation = {
            "consistent": True,
            "timeline_issues": [],
            "metadata_issues": [],
            "cross_reference_issues": []
        }
        
        try:
            # Sort evidence by timestamp
            timestamped_items = [item for item in evidence_items if item.timestamp]
            timestamped_items.sort(key=lambda x: x.timestamp)
            
            # Validate timeline consistency
            if len(timestamped_items) > 1:
                time_gaps = []
                for i in range(1, len(timestamped_items)):
                    prev_time = datetime.fromisoformat(timestamped_items[i-1].timestamp.replace('Z', '+00:00'))
                    curr_time = datetime.fromisoformat(timestamped_items[i].timestamp.replace('Z', '+00:00'))
                    
                    gap = (curr_time - prev_time).total_seconds()
                    if gap > 3600:  # More than 1 hour gap
                        time_gaps.append({
                            "between": [str(timestamped_items[i-1].file_path), str(timestamped_items[i].file_path)],
                            "gap_seconds": gap
                        })
                
                if time_gaps:
                    validation["timeline_issues"] = time_gaps
                    validation["consistent"] = False
            
            # Additional consistency checks would go here
            # (metadata correlation, cross-references, etc.)
            
        except Exception as e:
            validation["consistent"] = False
            validation["error"] = str(e)
            
        return validation
    
    def _generate_evidence_summary(self, evidence_items: List[EvidenceItem]) -> Dict[str, Any]:
        """Generate summary of evidence package."""
        summary = {
            "total_items": len(evidence_items),
            "total_size_mb": sum(item.file_size for item in evidence_items) / (1024 * 1024),
            "by_type": {},
            "earliest_timestamp": None,
            "latest_timestamp": None
        }
        
        try:
            # Group by type
            for evidence_type in EvidenceType:
                type_items = [item for item in evidence_items if item.evidence_type == evidence_type]
                if type_items:
                    summary["by_type"][evidence_type.value] = {
                        "count": len(type_items),
                        "total_size_mb": sum(item.file_size for item in type_items) / (1024 * 1024)
                    }
            
            # Find timestamp range
            timestamps = [item.timestamp for item in evidence_items if item.timestamp]
            if timestamps:
                timestamps.sort()
                summary["earliest_timestamp"] = timestamps[0]
                summary["latest_timestamp"] = timestamps[-1]
                
        except Exception as e:
            summary["error"] = str(e)
            
        return summary
    
    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA-256 hash of file."""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
        except Exception as e:
            self.logger.error(f"Failed to calculate hash for {file_path}: {e}")
            return ""
        return sha256_hash.hexdigest()
    
    def _generate_file_description(self, file_path: Path, evidence_type: EvidenceType) -> str:
        """Generate description for evidence file."""
        descriptions = {
            EvidenceType.MEMORY_DUMPS: f"Memory dump file: {file_path.name}",
            EvidenceType.NETWORK_CAPTURE: f"Network packet capture: {file_path.name}",
            EvidenceType.API_TRACE: f"Win32 API trace log: {file_path.name}",
            EvidenceType.SCREEN_RECORDING: f"Screen recording: {file_path.name}",
            EvidenceType.FILE_SYSTEM_CHANGES: f"File system changes log: {file_path.name}",
            EvidenceType.REGISTRY_CHANGES: f"Registry changes: {file_path.name}",
            EvidenceType.PROCESS_SNAPSHOTS: f"Process snapshot: {file_path.name}",
            EvidenceType.GPG_SIGNATURE: f"GPG signature: {file_path.name}"
        }
        return descriptions.get(evidence_type, f"Evidence file: {file_path.name}")
    
    def _extract_file_metadata(self, file_path: Path) -> Dict[str, Any]:
        """Extract metadata from evidence file."""
        metadata = {}
        try:
            stat = file_path.stat()
            metadata.update({
                "size_bytes": stat.st_size,
                "creation_time": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                "modification_time": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "access_time": datetime.fromtimestamp(stat.st_atime).isoformat()
            })
            
            # Add MIME type
            mime_type, _ = mimetypes.guess_type(str(file_path))
            if mime_type:
                metadata["mime_type"] = mime_type
                
        except Exception as e:
            metadata["extraction_error"] = str(e)
            
        return metadata
    
    def _get_timestamp(self) -> str:
        """Get ISO timestamp."""
        return datetime.utcnow().isoformat() + 'Z'
    
    def create_evidence_package(self, evidence_files: List[Path], package_name: str) -> EvidencePackage:
        """Create a new evidence package with proper structure."""
        package_id = f"intellicrack-evidence-{int(time.time())}"
        evidence_items = []
        
        try:
            for file_path in evidence_files:
                if file_path.exists():
                    evidence_type = self._determine_evidence_type(file_path)
                    if evidence_type:
                        item = EvidenceItem(
                            evidence_type=evidence_type,
                            file_path=file_path,
                            file_hash=self._calculate_file_hash(file_path),
                            file_size=file_path.stat().st_size,
                            timestamp=self._get_timestamp(),
                            description=self._generate_file_description(file_path, evidence_type),
                            metadata=self._extract_file_metadata(file_path)
                        )
                        evidence_items.append(item)
            
            # Create integrity manifest
            integrity_manifest = {item.file_path.name: item.file_hash for item in evidence_items}
            
            # Create evidence package
            package = EvidencePackage(
                package_id=package_id,
                creation_timestamp=self._get_timestamp(),
                evidence_items=evidence_items,
                integrity_manifest=integrity_manifest
            )
            
            # Save package manifest
            manifest_path = self.evidence_path / f"{package_name}_manifest.json"
            with open(manifest_path, 'w', encoding='utf-8') as f:
                json.dump(asdict(package), f, indent=2, default=str)
            
            return package
            
        except Exception as e:
            self.logger.error(f"Failed to create evidence package: {e}")
            raise


def main():
    """Example usage of EvidenceRequirementsValidator."""
    validator = EvidenceRequirementsValidator(
        evidence_path=Path("C:/Intellicrack/tests/validation_system/evidence"),
        gpg_key_id="test-key@example.com"
    )
    
    # Validate evidence package
    result, report = validator.validate_evidence_package(
        Path("C:/Intellicrack/tests/validation_system/evidence/test_package")
    )
    
    print(f"Evidence Validation Result: {result.value}")
    print(f"Report: {json.dumps(report, indent=2, default=str)}")


if __name__ == "__main__":
    main()