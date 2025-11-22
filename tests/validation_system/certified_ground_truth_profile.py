#!/usr/bin/env python3
"""
Certified Ground Truth Profile Manager for Intellicrack Validation System
Manages and provides certified access to established ground truth data
"""

import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

class ProtectionType(Enum):
    """Enumeration of protection types."""
    LICENSE_MANAGER = "license_manager"
    PACKER = "packer"
    OBFUSCATOR = "obfuscator"
    ANTI_DEBUG = "anti_debug"
    ANTI_VM = "anti_vm"
    DONGLE = "dongle"
    CLOUD_LICENSE = "cloud_license"
    CUSTOM = "custom"


class ConfidenceLevel(Enum):
    """Confidence levels for ground truth data."""
    CERTAIN = 1.0
    HIGH = 0.9
    MEDIUM = 0.7
    LOW = 0.5
    UNCERTAIN = 0.3


@dataclass
class ProtectionProfile:
    """Data class representing a protection profile."""
    name: str
    type: ProtectionType
    version: str
    confidence: float
    detection_methods: list[str]
    bypass_methods: list[str]
    metadata: dict[str, Any]
    timestamp: str
    hash: str


@dataclass
class CertificationRecord:
    """Record of ground truth certification."""
    profile_id: str
    certifier: str
    certification_date: str
    expiry_date: str
    signature: str
    validation_count: int
    last_validation: str


class CertifiedGroundTruthProfile:
    """
    Manages certified ground truth profiles for validation.
    Provides secure access to established ground truth data.
    """

    def __init__(self, base_dir: str = r"D:\Intellicrack\tests\validation_system"):
        self.base_dir = Path(base_dir)
        self.ground_truth_dir = self.base_dir / "certified_ground_truth"
        self.profiles_dir = self.ground_truth_dir / "profiles"
        self.certifications_dir = self.ground_truth_dir / "certifications"
        self.db_path = self.ground_truth_dir / "ground_truth.db"

        self._ensure_directories()
        self._setup_logging()
        self._initialize_database()
        self._load_secret_key()

        self.profiles_cache = {}
        self.certifications_cache = {}
        self.validation_stats = {
            "total_validations": 0,
            "successful_validations": 0,
            "failed_validations": 0,
            "last_validation": None
        }

    def _ensure_directories(self):
        """Ensure all required directories exist."""
        directories = [
            self.ground_truth_dir,
            self.profiles_dir,
            self.certifications_dir
        ]
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)

    def _setup_logging(self):
        """Configure logging for ground truth profile operations."""
        log_file = self.ground_truth_dir / "profile_manager.log"
        handler = logging.FileHandler(log_file)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

    def _load_secret_key(self):
        """Load or generate secret key for HMAC signatures."""
        key_file = self.ground_truth_dir / ".secret_key"
        if key_file.exists():
            with open(key_file, 'rb') as f:
                self.secret_key = f.read()
        else:
            self.secret_key = secrets.token_bytes(64)
            with open(key_file, 'wb') as f:
                f.write(self.secret_key)
            os.chmod(key_file, 0o600)

    def _initialize_database(self):
        """Initialize SQLite database for ground truth profiles."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Create profiles table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS profiles (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                type TEXT NOT NULL,
                version TEXT NOT NULL,
                confidence REAL NOT NULL,
                detection_methods TEXT NOT NULL,
                bypass_methods TEXT NOT NULL,
                metadata TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                hash TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        ''')

        # Create certifications table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS certifications (
                id TEXT PRIMARY KEY,
                profile_id TEXT NOT NULL,
                certifier TEXT NOT NULL,
                certification_date TEXT NOT NULL,
                expiry_date TEXT NOT NULL,
                signature TEXT NOT NULL,
                validation_count INTEGER DEFAULT 0,
                last_validation TEXT,
                FOREIGN KEY (profile_id) REFERENCES profiles(id)
            )
        ''')

        # Create validation log table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS validation_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                profile_id TEXT NOT NULL,
                validation_time TEXT NOT NULL,
                result TEXT NOT NULL,
                details TEXT,
                FOREIGN KEY (profile_id) REFERENCES profiles(id)
            )
        ''')

        # Create consensus table for multi-source verification
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS consensus (
                id TEXT PRIMARY KEY,
                profile_id TEXT NOT NULL,
                source_count INTEGER NOT NULL,
                consensus_level REAL NOT NULL,
                sources TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (profile_id) REFERENCES profiles(id)
            )
        ''')

        conn.commit()
        conn.close()

    def create_profile(self, binary_path: Path, ground_truth_data: dict[str, Any]) -> ProtectionProfile:
        """
        Create a certified protection profile from ground truth data.

        Args:
            binary_path: Path to the binary being profiled
            ground_truth_data: Established ground truth data

        Returns:
            ProtectionProfile object
        """
        logger.info(f"Creating profile for {binary_path.name}")

        # Extract protection information
        protections = ground_truth_data.get("protections", [])
        if not protections:
            logger.warning(f"No protections found in ground truth for {binary_path.name}")
            protection_name = "Unknown"
            protection_type = ProtectionType.CUSTOM
        else:
            main_protection = protections[0]
            protection_name = main_protection.get("name", "Unknown")
            protection_type = self._determine_protection_type(protection_name)

        # Calculate confidence based on consensus
        confidence = self._calculate_confidence(ground_truth_data)

        # Extract detection methods
        detection_methods = self._extract_detection_methods(ground_truth_data)

        # Generate bypass methods based on protection type
        bypass_methods = self._generate_bypass_methods(protection_type, ground_truth_data)

        # Create metadata
        metadata = {
            "binary_name": binary_path.name,
            "binary_hash": self._calculate_file_hash(binary_path),
            "analysis_sources": ground_truth_data.get("sources", []),
            "consensus_data": ground_truth_data.get("consensus", {}),
            "additional_protections": protections[1:] if len(protections) > 1 else []
        }

        # Generate profile hash
        profile_data = {
            "name": protection_name,
            "type": protection_type.value,
            "version": ground_truth_data.get("version", "1.0"),
            "confidence": confidence,
            "detection_methods": detection_methods,
            "bypass_methods": bypass_methods,
            "metadata": metadata
        }
        profile_hash = self._calculate_profile_hash(profile_data)

        # Create profile object
        profile = ProtectionProfile(
            name=protection_name,
            type=protection_type,
            version=ground_truth_data.get("version", "1.0"),
            confidence=confidence,
            detection_methods=detection_methods,
            bypass_methods=bypass_methods,
            metadata=metadata,
            timestamp=datetime.now().isoformat(),
            hash=profile_hash
        )

        # Store profile
        self._store_profile(profile)

        return profile

    def _determine_protection_type(self, protection_name: str) -> ProtectionType:
        """Determine the protection type based on name."""
        protection_map = {
            "flexnet": ProtectionType.LICENSE_MANAGER,
            "flexlm": ProtectionType.LICENSE_MANAGER,
            "sentinel": ProtectionType.DONGLE,
            "hasp": ProtectionType.DONGLE,
            "codemeter": ProtectionType.DONGLE,
            "wibu": ProtectionType.DONGLE,
            "themida": ProtectionType.PACKER,
            "winlicense": ProtectionType.PACKER,
            "vmprotect": ProtectionType.PACKER,
            "denuvo": ProtectionType.ANTI_DEBUG,
            "enigma": ProtectionType.PACKER,
            "asprotect": ProtectionType.PACKER,
            "upx": ProtectionType.PACKER,
            "cloud": ProtectionType.CLOUD_LICENSE
        }

        name_lower = protection_name.lower()
        for key, ptype in protection_map.items():
            if key in name_lower:
                return ptype

        return ProtectionType.CUSTOM

    def _calculate_confidence(self, ground_truth_data: dict[str, Any]) -> float:
        """Calculate confidence level based on consensus data."""
        consensus = ground_truth_data.get("consensus", {})

        # Base confidence on number of agreeing sources
        source_count = consensus.get("source_count", 1)
        agreement_level = consensus.get("agreement_level", 0.5)

        if source_count >= 3 and agreement_level >= 0.9:
            return ConfidenceLevel.CERTAIN.value
        elif source_count >= 2 and agreement_level >= 0.8:
            return ConfidenceLevel.HIGH.value
        elif source_count >= 2 and agreement_level >= 0.6:
            return ConfidenceLevel.MEDIUM.value
        elif source_count >= 1 and agreement_level >= 0.5:
            return ConfidenceLevel.LOW.value
        else:
            return ConfidenceLevel.UNCERTAIN.value

    def _extract_detection_methods(self, ground_truth_data: dict[str, Any]) -> list[str]:
        """Extract detection methods from ground truth data."""
        methods = []

        # Add scanner-based detections
        for scanner in ground_truth_data.get("scanners", []):
            if scanner.get("detected"):
                methods.append(f"scanner:{scanner.get('name', 'unknown')}")

        # Add binary analysis detections
        for analyzer in ground_truth_data.get("analyzers", []):
            if analyzer.get("indicators"):
                methods.append(f"analyzer:{analyzer.get('name', 'unknown')}")

        # Add signature-based detections
        for signature in ground_truth_data.get("signatures", []):
            if signature.get("matched"):
                methods.append(f"signature:{signature.get('name', 'unknown')}")

        # Add behavioral detections
        if ground_truth_data.get("behavioral_indicators"):
            methods.append("behavioral:runtime_analysis")

        # Add import table analysis
        if ground_truth_data.get("imports_analysis"):
            methods.append("imports:api_analysis")

        # Add string analysis
        if ground_truth_data.get("strings_analysis"):
            methods.append("strings:pattern_matching")

        return methods if methods else ["manual:expert_analysis"]

    def _generate_bypass_methods(self, protection_type: ProtectionType,
                                 ground_truth_data: dict[str, Any]) -> list[str]:
        """Generate bypass methods based on protection type."""
        bypass_methods = []

        if protection_type == ProtectionType.LICENSE_MANAGER:
            bypass_methods.extend([
                "api_hooking:license_check_bypass",
                "memory_patching:validation_skip",
                "network_interception:license_server_emulation",
                "registry_modification:cached_license"
            ])

        elif protection_type == ProtectionType.PACKER:
            bypass_methods.extend([
                "unpacking:manual_unpacking",
                "dumping:memory_dump_reconstruction",
                "import_reconstruction:iat_rebuild",
                "oep_finding:original_entry_point"
            ])

        elif protection_type == ProtectionType.DONGLE:
            bypass_methods.extend([
                "emulation:virtual_dongle",
                "driver_hooking:usb_interception",
                "memory_patching:dongle_check_bypass",
                "api_redirection:dongle_api_emulation"
            ])

        elif protection_type == ProtectionType.ANTI_DEBUG:
            bypass_methods.extend([
                "debugger_hiding:peb_manipulation",
                "api_hooking:antidebug_bypass",
                "timing_manipulation:rdtsc_hooking",
                "exception_handling:debug_exception_bypass"
            ])

        elif protection_type == ProtectionType.ANTI_VM:
            bypass_methods.extend([
                "vm_detection_bypass:cpuid_manipulation",
                "hardware_spoofing:device_id_modification",
                "registry_cleaning:vm_artifact_removal",
                "driver_hiding:hypervisor_concealment"
            ])

        elif protection_type == ProtectionType.CLOUD_LICENSE:
            bypass_methods.extend([
                "proxy_interception:https_mitm",
                "response_modification:license_response_patch",
                "token_generation:jwt_forging",
                "offline_mode:force_offline_validation"
            ])

        else:  # CUSTOM or unknown
            bypass_methods.extend([
                "analysis:reverse_engineering",
                "patching:binary_modification",
                "hooking:runtime_manipulation",
                "emulation:behavior_simulation"
            ])

        # Add specific bypass hints from ground truth
        if "bypass_hints" in ground_truth_data:
            for hint in ground_truth_data["bypass_hints"]:
                bypass_methods.append(f"hint:{hint}")

        return bypass_methods

    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA-256 hash of a file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(65536), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def _calculate_profile_hash(self, profile_data: dict[str, Any]) -> str:
        """Calculate unique hash for a profile."""
        profile_json = json.dumps(profile_data, sort_keys=True)
        return hashlib.sha256(profile_json.encode()).hexdigest()

    def _store_profile(self, profile: ProtectionProfile):
        """Store profile in database and file system."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        profile_id = f"profile_{profile.hash[:16]}"

        try:
            cursor.execute('''
                INSERT INTO profiles (
                    id, name, type, version, confidence,
                    detection_methods, bypass_methods, metadata,
                    timestamp, hash, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                profile_id,
                profile.name,
                profile.type.value,
                profile.version,
                profile.confidence,
                json.dumps(profile.detection_methods),
                json.dumps(profile.bypass_methods),
                json.dumps(profile.metadata),
                profile.timestamp,
                profile.hash,
                datetime.now().isoformat(),
                datetime.now().isoformat()
            ))

            conn.commit()

            # Also save to file
            profile_file = self.profiles_dir / f"{profile_id}.json"
            profile_dict = {
                "id": profile_id,
                "name": profile.name,
                "type": profile.type.value,
                "version": profile.version,
                "confidence": profile.confidence,
                "detection_methods": profile.detection_methods,
                "bypass_methods": profile.bypass_methods,
                "metadata": profile.metadata,
                "timestamp": profile.timestamp,
                "hash": profile.hash
            }

            with open(profile_file, 'w') as f:
                json.dump(profile_dict, f, indent=2)

            logger.info(f"Stored profile {profile_id} for {profile.name}")

        except sqlite3.IntegrityError as e:
            logger.warning(f"Profile already exists: {e}")
        finally:
            conn.close()

    def certify_profile(self, profile_id: str, certifier: str = "ValidationSystem",
                       validity_days: int = 90) -> CertificationRecord:
        """
        Certify a ground truth profile.

        Args:
            profile_id: ID of the profile to certify
            certifier: Name of the certifying entity
            validity_days: Number of days the certification is valid

        Returns:
            CertificationRecord object
        """
        logger.info(f"Certifying profile {profile_id}")

        # Verify profile exists
        profile = self.get_profile(profile_id)
        if not profile:
            raise ValueError(f"Profile {profile_id} not found")

        # Generate certification
        cert_id = f"cert_{secrets.token_hex(8)}"
        certification_date = datetime.now()
        expiry_date = certification_date + timedelta(days=validity_days)

        # Create signature
        signature_data = f"{profile_id}:{certifier}:{certification_date.isoformat()}"
        signature = hmac.new(
            self.secret_key,
            signature_data.encode(),
            hashlib.sha256
        ).hexdigest()

        certification = CertificationRecord(
            profile_id=profile_id,
            certifier=certifier,
            certification_date=certification_date.isoformat(),
            expiry_date=expiry_date.isoformat(),
            signature=signature,
            validation_count=0,
            last_validation=None
        )

        # Store certification
        self._store_certification(cert_id, certification)

        return certification

    def _store_certification(self, cert_id: str, certification: CertificationRecord):
        """Store certification record."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO certifications (
                id, profile_id, certifier, certification_date,
                expiry_date, signature, validation_count, last_validation
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            cert_id,
            certification.profile_id,
            certification.certifier,
            certification.certification_date,
            certification.expiry_date,
            certification.signature,
            certification.validation_count,
            certification.last_validation
        ))

        conn.commit()
        conn.close()

        # Save to file
        cert_file = self.certifications_dir / f"{cert_id}.json"
        cert_dict = {
            "id": cert_id,
            "profile_id": certification.profile_id,
            "certifier": certification.certifier,
            "certification_date": certification.certification_date,
            "expiry_date": certification.expiry_date,
            "signature": certification.signature,
            "validation_count": certification.validation_count,
            "last_validation": certification.last_validation
        }

        with open(cert_file, 'w') as f:
            json.dump(cert_dict, f, indent=2)

        logger.info(f"Stored certification {cert_id}")

    def validate_profile(self, profile_id: str, test_data: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
        """
        Validate test data against a certified profile.

        Args:
            profile_id: ID of the profile to validate against
            test_data: Data from test execution to validate

        Returns:
            Tuple of (validation_result, validation_details)
        """
        logger.info(f"Validating against profile {profile_id}")

        profile = self.get_profile(profile_id)
        if not profile:
            return False, {"error": f"Profile {profile_id} not found"}

        validation_results = {
            "profile_id": profile_id,
            "timestamp": datetime.now().isoformat(),
            "checks": {}
        }

        # Check protection detection
        detected_protections = test_data.get("detected_protections", [])
        expected_protection = profile["name"]

        protection_match = any(
            expected_protection.lower() in p.lower()
            for p in detected_protections
        )
        validation_results["checks"]["protection_detection"] = protection_match

        # Check detection methods
        used_methods = test_data.get("detection_methods", [])
        expected_methods = profile["detection_methods"]

        method_coverage = len(set(used_methods) & set(expected_methods)) / len(expected_methods)
        validation_results["checks"]["method_coverage"] = method_coverage

        # Check bypass success
        bypass_attempted = test_data.get("bypass_attempted", False)
        bypass_successful = test_data.get("bypass_successful", False)

        if bypass_attempted:
            validation_results["checks"]["bypass_success"] = bypass_successful

        # Check confidence level
        test_confidence = test_data.get("confidence", 0)
        expected_confidence = profile["confidence"]

        confidence_match = abs(test_confidence - expected_confidence) < 0.2
        validation_results["checks"]["confidence_match"] = confidence_match

        # Calculate overall validation
        checks = validation_results["checks"]

        validation_passed = (
            checks.get("protection_detection", False) and
            checks.get("method_coverage", 0) >= 0.5
        )

        if bypass_attempted:
            validation_passed = validation_passed and checks.get("bypass_success", False)

        # Log validation
        self._log_validation(profile_id, validation_passed, validation_results)

        # Update statistics
        self.validation_stats["total_validations"] += 1
        if validation_passed:
            self.validation_stats["successful_validations"] += 1
        else:
            self.validation_stats["failed_validations"] += 1
        self.validation_stats["last_validation"] = datetime.now().isoformat()

        return validation_passed, validation_results

    def _log_validation(self, profile_id: str, result: bool, details: dict[str, Any]):
        """Log validation attempt."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO validation_log (
                profile_id, validation_time, result, details
            ) VALUES (?, ?, ?, ?)
        ''', (
            profile_id,
            datetime.now().isoformat(),
            "PASS" if result else "FAIL",
            json.dumps(details)
        ))

        # Update certification validation count
        cursor.execute('''
            UPDATE certifications
            SET validation_count = validation_count + 1,
                last_validation = ?
            WHERE profile_id = ?
        ''', (datetime.now().isoformat(), profile_id))

        conn.commit()
        conn.close()

    def get_profile(self, profile_id: str) -> dict[str, Any] | None:
        """Retrieve a profile by ID."""
        # Check cache first
        if profile_id in self.profiles_cache:
            return self.profiles_cache[profile_id]

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            SELECT * FROM profiles WHERE id = ?
        ''', (profile_id,))

        row = cursor.fetchone()
        conn.close()

        if row:
            profile = {
                "id": row[0],
                "name": row[1],
                "type": row[2],
                "version": row[3],
                "confidence": row[4],
                "detection_methods": json.loads(row[5]),
                "bypass_methods": json.loads(row[6]),
                "metadata": json.loads(row[7]),
                "timestamp": row[8],
                "hash": row[9],
                "created_at": row[10],
                "updated_at": row[11]
            }

            # Cache the profile
            self.profiles_cache[profile_id] = profile
            return profile

        return None

    def list_profiles(self, protection_type: ProtectionType | None = None) -> list[dict[str, Any]]:
        """List all profiles, optionally filtered by type."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        if protection_type:
            cursor.execute('''
                SELECT id, name, type, version, confidence, created_at
                FROM profiles WHERE type = ?
                ORDER BY created_at DESC
            ''', (protection_type.value,))
        else:
            cursor.execute('''
                SELECT id, name, type, version, confidence, created_at
                FROM profiles
                ORDER BY created_at DESC
            ''')

        profiles = []
        for row in cursor.fetchall():
            profiles.append({
                "id": row[0],
                "name": row[1],
                "type": row[2],
                "version": row[3],
                "confidence": row[4],
                "created_at": row[5]
            })

        conn.close()
        return profiles

    def get_certification(self, profile_id: str) -> dict[str, Any] | None:
        """Get certification for a profile."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            SELECT * FROM certifications
            WHERE profile_id = ?
            ORDER BY certification_date DESC
            LIMIT 1
        ''', (profile_id,))

        row = cursor.fetchone()
        conn.close()

        if row:
            return {
                "id": row[0],
                "profile_id": row[1],
                "certifier": row[2],
                "certification_date": row[3],
                "expiry_date": row[4],
                "signature": row[5],
                "validation_count": row[6],
                "last_validation": row[7]
            }

        return None

    def verify_certification(self, profile_id: str) -> tuple[bool, str]:
        """
        Verify if a profile's certification is valid.

        Returns:
            Tuple of (is_valid, reason)
        """
        certification = self.get_certification(profile_id)

        if not certification:
            return False, "No certification found"

        # Check expiry
        expiry_date = datetime.fromisoformat(certification["expiry_date"])
        if datetime.now() > expiry_date:
            return False, "Certification expired"

        # Verify signature
        signature_data = f"{profile_id}:{certification['certifier']}:{certification['certification_date']}"
        expected_signature = hmac.new(
            self.secret_key,
            signature_data.encode(),
            hashlib.sha256
        ).hexdigest()

        if certification["signature"] != expected_signature:
            return False, "Invalid signature"

        return True, "Certification valid"

    def export_profile(self, profile_id: str, output_path: Path) -> bool:
        """Export a profile with all associated data."""
        profile = self.get_profile(profile_id)
        if not profile:
            logger.error(f"Profile {profile_id} not found")
            return False

        certification = self.get_certification(profile_id)

        export_data = {
            "profile": profile,
            "certification": certification,
            "export_timestamp": datetime.now().isoformat(),
            "validation_stats": self.validation_stats
        }

        with open(output_path, 'w') as f:
            json.dump(export_data, f, indent=2)

        logger.info(f"Exported profile {profile_id} to {output_path}")
        return True

    def import_profile(self, import_path: Path) -> str:
        """Import a profile from exported data."""
        with open(import_path) as f:
            import_data = json.load(f)

        profile_data = import_data["profile"]

        # Create ProtectionProfile object
        profile = ProtectionProfile(
            name=profile_data["name"],
            type=ProtectionType(profile_data["type"]),
            version=profile_data["version"],
            confidence=profile_data["confidence"],
            detection_methods=profile_data["detection_methods"],
            bypass_methods=profile_data["bypass_methods"],
            metadata=profile_data["metadata"],
            timestamp=profile_data["timestamp"],
            hash=profile_data["hash"]
        )

        # Store the profile
        self._store_profile(profile)

        # Import certification if present
        if import_data.get("certification"):
            cert_data = import_data["certification"]
            certification = CertificationRecord(
                profile_id=profile_data["id"],
                certifier=cert_data["certifier"],
                certification_date=cert_data["certification_date"],
                expiry_date=cert_data["expiry_date"],
                signature=cert_data["signature"],
                validation_count=cert_data["validation_count"],
                last_validation=cert_data["last_validation"]
            )
            self._store_certification(cert_data["id"], certification)

        logger.info(f"Imported profile {profile_data['id']}")
        return profile_data["id"]

    def generate_validation_report(self) -> dict[str, Any]:
        """Generate a comprehensive validation report."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Get profile statistics
        cursor.execute("SELECT COUNT(*) FROM profiles")
        total_profiles = cursor.fetchone()[0]

        cursor.execute("SELECT type, COUNT(*) FROM profiles GROUP BY type")
        profiles_by_type = dict(cursor.fetchall())

        # Get certification statistics
        cursor.execute("SELECT COUNT(*) FROM certifications")
        total_certifications = cursor.fetchone()[0]

        cursor.execute('''
            SELECT COUNT(*) FROM certifications
            WHERE date(expiry_date) > date('now')
        ''')
        active_certifications = cursor.fetchone()[0]

        # Get validation statistics
        cursor.execute("SELECT COUNT(*) FROM validation_log")
        total_validations = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM validation_log WHERE result = 'PASS'")
        successful_validations = cursor.fetchone()[0]

        cursor.execute('''
            SELECT profile_id, COUNT(*) as count
            FROM validation_log
            GROUP BY profile_id
            ORDER BY count DESC
            LIMIT 5
        ''')
        most_validated = cursor.fetchall()

        conn.close()

        report = {
            "timestamp": datetime.now().isoformat(),
            "profile_statistics": {
                "total_profiles": total_profiles,
                "profiles_by_type": profiles_by_type
            },
            "certification_statistics": {
                "total_certifications": total_certifications,
                "active_certifications": active_certifications,
                "expired_certifications": total_certifications - active_certifications
            },
            "validation_statistics": {
                "total_validations": total_validations,
                "successful_validations": successful_validations,
                "failed_validations": total_validations - successful_validations,
                "success_rate": successful_validations / total_validations if total_validations > 0 else 0,
                "most_validated_profiles": most_validated
            },
            "system_stats": self.validation_stats
        }

        return report


def main():
    """Initialize and run the Certified Ground Truth Profile Manager."""
    manager = CertifiedGroundTruthProfile()

    # Load ground truth from external sources (not from Intellicrack)
    ground_truth_path = Path(r"D:\Intellicrack\tests\validation_system\certified_ground_truth")

    # Process all available ground truth profiles
    for gt_file in ground_truth_path.glob("*.json"):
        try:
            with open(gt_file) as f:
                ground_truth_data = json.load(f)

            # Verify ground truth is from external sources
            if "external_sources" not in ground_truth_data:
                logger.warning(f"Skipping {gt_file.name} - no external source verification")
                continue

            # Get corresponding binary path
            binary_name = ground_truth_data.get("binary_metadata", {}).get("name")
            if not binary_name:
                logger.warning(f"Skipping {gt_file.name} - no binary name specified")
                continue

            binary_path = Path(r"D:\Intellicrack\tests\validation_system\commercial_binaries") / binary_name

            if not binary_path.exists():
                logger.warning(f"Binary not found: {binary_path}")
                continue

            # Create profile from verified external ground truth
            profile = manager.create_profile(binary_path, ground_truth_data)
            logger.info(f"Created profile: {profile.name} (Type: {profile.type.value})")
            logger.info(f"Confidence: {profile.confidence}")
            logger.info(f"Detection methods: {len(profile.detection_methods)}")
            logger.info(f"Bypass methods: {len(profile.bypass_methods)}")

        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in {gt_file.name}: {e}")
        except Exception as e:
            logger.error(f"Error processing {gt_file.name}: {e}")

    # Certify all loaded profiles
    profiles = manager.list_profiles()
    for profile in profiles:
        profile_id = profile["id"]
        logger.info(f"Certifying profile: {profile_id}")

        try:
            certification = manager.certify_profile(profile_id)
            logger.info(f"Certification created for {profile_id}, expires: {certification.expiry_date}")

            # Verify certification
            is_valid, reason = manager.verify_certification(profile_id)
            logger.info(f"Certification valid for {profile_id}: {is_valid} ({reason})")
        except Exception as e:
            logger.error(f"Failed to certify profile {profile_id}: {e}")

    # Generate final report
    if profiles:
        logger.info("Generating validation report...")
        report = manager.generate_validation_report()
        logger.info(f"Total profiles: {report['profile_statistics']['total_profiles']}")
        logger.info(f"Active certifications: {report['certification_statistics']['active_certifications']}")

        # Save report to file
        report_path = manager.ground_truth_dir / f"ground_truth_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        logger.info(f"Report saved to: {report_path}")

    logger.info("Certified Ground Truth Profile Manager initialization complete.")


if __name__ == "__main__":
    main()
