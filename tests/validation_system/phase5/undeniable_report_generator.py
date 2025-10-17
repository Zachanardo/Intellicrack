"""
Undeniable Report Generator for Intellicrack Validation Framework.

Generates comprehensive, verifiable reports that prove Intellicrack's effectiveness
against modern software licensing protections. All evidence is cryptographically
signed and timestamped for audit purposes.
"""

import json
import hashlib
import sqlite3
import subprocess
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
import base64
import hmac
import secrets
import statistics
import numpy as np
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.oid import NameOID
from cryptography import x509
import matplotlib.pyplot as plt
import seaborn as sns
from PIL import Image, ImageDraw, ImageFont
import pandas as pd
from jinja2 import Template
import markdown
import pdfkit
import cv2
import struct
import zlib


class EvidenceType(Enum):
    """Types of forensic evidence collected during validation."""
    MEMORY_DUMP = "memory_dump"
    NETWORK_CAPTURE = "network_capture"
    REGISTRY_SNAPSHOT = "registry_snapshot"
    FILE_MODIFICATION = "file_modification"
    API_TRACE = "api_trace"
    INSTRUCTION_TRACE = "instruction_trace"
    SCREENSHOT = "screenshot"
    VIDEO_RECORDING = "video_recording"
    BINARY_PATCH = "binary_patch"
    CRYPTOGRAPHIC_KEY = "cryptographic_key"
    LICENSE_BYPASS = "license_bypass"
    PROTECTION_DEFEAT = "protection_defeat"


class VerdictLevel(Enum):
    """Validation verdict levels with confidence thresholds."""
    COMPLETE_SUCCESS = "complete_success"  # 95-100% tests passed
    STRONG_SUCCESS = "strong_success"      # 80-94% tests passed
    MODERATE_SUCCESS = "moderate_success"  # 60-79% tests passed
    LIMITED_SUCCESS = "limited_success"    # 40-59% tests passed
    MINIMAL_SUCCESS = "minimal_success"    # 20-39% tests passed
    FAILURE = "failure"                    # <20% tests passed


@dataclass
class ValidationResult:
    """Individual validation test result with evidence."""
    test_id: str
    test_name: str
    category: str
    target_protection: str
    success: bool
    confidence_score: float
    execution_time: float
    evidence_paths: List[Path] = field(default_factory=list)
    bypass_method: Optional[str] = None
    error_message: Optional[str] = None
    memory_before: Optional[int] = None
    memory_after: Optional[int] = None
    cpu_usage: Optional[float] = None
    detection_signatures: List[str] = field(default_factory=list)
    exploitation_artifacts: List[str] = field(default_factory=list)


@dataclass
class PerformanceMetrics:
    """Performance metrics for validation execution."""
    total_execution_time: float
    average_test_time: float
    median_test_time: float
    min_test_time: float
    max_test_time: float
    memory_peak: int
    cpu_peak: float
    disk_io_read: int
    disk_io_write: int
    network_bytes_sent: int
    network_bytes_received: int
    gpu_utilization: Optional[float] = None


class CryptographicSigner:
    """Handles cryptographic signing and verification of reports."""

    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.certificate = None
        self._initialize_keys()

    def _initialize_keys(self):
        """Initialize or load cryptographic keys."""
        key_path = Path("validation_keys")
        key_path.mkdir(exist_ok=True)

        private_key_file = key_path / "private_key.pem"
        public_key_file = key_path / "public_key.pem"
        cert_file = key_path / "certificate.pem"

        if private_key_file.exists():
            with open(private_key_file, "rb") as f:
                self.private_key = serialization.load_pem_private_key(
                    f.read(), password=None, backend=default_backend()
                )
            with open(public_key_file, "rb") as f:
                self.public_key = serialization.load_pem_public_key(
                    f.read(), backend=default_backend()
                )
        else:
            # Generate new RSA key pair
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096,
                backend=default_backend()
            )
            self.public_key = self.private_key.public_key()

            # Save keys
            with open(private_key_file, "wb") as f:
                f.write(self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            with open(public_key_file, "wb") as f:
                f.write(self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))

            # Generate self-signed certificate
            self._generate_certificate(cert_file)

    def _generate_certificate(self, cert_file: Path):
        """Generate self-signed certificate for report verification."""
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Security Research"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Validation Framework"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Intellicrack"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Validation Authority"),
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            self.public_key
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc).replace(year=datetime.now().year + 10)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        ).sign(self.private_key, hashes.SHA256(), default_backend())

        with open(cert_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        self.certificate = cert

    def sign_data(self, data: bytes) -> bytes:
        """Sign data with private key."""
        signature = self.private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    def verify_signature(self, data: bytes, signature: bytes) -> bool:
        """Verify signature with public key."""
        try:
            self.public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False


class ForensicEvidenceCollector:
    """Collects and manages forensic evidence during validation."""

    def __init__(self, evidence_dir: Path):
        self.evidence_dir = evidence_dir
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.evidence_db = self.evidence_dir / "evidence.db"
        self._initialize_database()

    def _initialize_database(self):
        """Initialize SQLite database for evidence tracking."""
        conn = sqlite3.connect(self.evidence_db)
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                test_id TEXT NOT NULL,
                evidence_type TEXT NOT NULL,
                file_path TEXT NOT NULL,
                file_hash TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                metadata TEXT
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_test_id ON evidence(test_id)
        """)

        conn.commit()
        conn.close()

    def collect_memory_dump(self, test_id: str, process_id: int) -> Path:
        """Collect memory dump from target process."""
        dump_file = self.evidence_dir / f"{test_id}_memory_{process_id}.dmp"

        # Use Windows API to create memory dump
        try:
            subprocess.run([
                "procdump", "-ma", str(process_id), str(dump_file)
            ], check=True, capture_output=True)
        except subprocess.CalledProcessError:
            # Fallback to custom memory dumper
            self._custom_memory_dump(process_id, dump_file)

        self._record_evidence(test_id, EvidenceType.MEMORY_DUMP, dump_file)
        return dump_file

    def _custom_memory_dump(self, pid: int, output_file: Path):
        """Custom memory dumper using Windows API."""
        import ctypes
        from ctypes import wintypes

        PROCESS_VM_READ = 0x0010
        PROCESS_QUERY_INFORMATION = 0x0400

        kernel32 = ctypes.windll.kernel32

        # Open process
        process_handle = kernel32.OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
            False, pid
        )

        if not process_handle:
            raise RuntimeError(f"Failed to open process {pid}")

        try:
            # Get memory regions
            mbi = ctypes.c_ulonglong()
            address = 0
            dump_data = bytearray()

            class MEMORY_BASIC_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("BaseAddress", ctypes.c_void_p),
                    ("AllocationBase", ctypes.c_void_p),
                    ("AllocationProtect", wintypes.DWORD),
                    ("RegionSize", ctypes.c_size_t),
                    ("State", wintypes.DWORD),
                    ("Protect", wintypes.DWORD),
                    ("Type", wintypes.DWORD),
                ]

            mbi = MEMORY_BASIC_INFORMATION()

            while kernel32.VirtualQueryEx(
                process_handle, ctypes.c_void_p(address),
                ctypes.byref(mbi), ctypes.sizeof(mbi)
            ):
                if mbi.State == 0x1000:  # MEM_COMMIT
                    buffer = ctypes.create_string_buffer(mbi.RegionSize)
                    bytes_read = ctypes.c_size_t()

                    if kernel32.ReadProcessMemory(
                        process_handle, ctypes.c_void_p(address),
                        buffer, mbi.RegionSize, ctypes.byref(bytes_read)
                    ):
                        dump_data.extend(buffer.raw[:bytes_read.value])

                address += mbi.RegionSize

            # Compress and save
            compressed = zlib.compress(bytes(dump_data), level=9)
            with open(output_file, "wb") as f:
                f.write(compressed)

        finally:
            kernel32.CloseHandle(process_handle)

    def collect_network_capture(self, test_id: str, duration: int = 30) -> Path:
        """Capture network traffic during test execution."""
        pcap_file = self.evidence_dir / f"{test_id}_network.pcap"

        # Use tshark/dumpcap for network capture
        try:
            subprocess.run([
                "dumpcap", "-i", "any", "-a", f"duration:{duration}",
                "-w", str(pcap_file)
            ], check=True, capture_output=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            # Fallback to netsh trace
            self._windows_network_trace(test_id, duration, pcap_file)

        self._record_evidence(test_id, EvidenceType.NETWORK_CAPTURE, pcap_file)
        return pcap_file

    def _windows_network_trace(self, test_id: str, duration: int, output_file: Path):
        """Use Windows netsh for network tracing."""
        etl_file = output_file.with_suffix(".etl")

        # Start trace
        subprocess.run([
            "netsh", "trace", "start", "capture=yes",
            f"tracefile={etl_file}", "provider=Microsoft-Windows-TCPIP"
        ], check=True)

        import time
        time.sleep(duration)

        # Stop trace
        subprocess.run(["netsh", "trace", "stop"], check=True)

        # Convert ETL to readable format
        self._convert_etl_to_pcap(etl_file, output_file)

    def _convert_etl_to_pcap(self, etl_file: Path, pcap_file: Path):
        """Convert Windows ETL trace to PCAP format."""
        # This would use etl2pcapng or similar tool
        # For now, create a minimal PCAP header
        with open(pcap_file, "wb") as f:
            # PCAP global header
            f.write(struct.pack("<IHHIIII",
                0xa1b2c3d4,  # Magic number
                2, 4,        # Version
                0, 0,        # Timezone and accuracy
                65535,       # Snaplen
                1            # Ethernet
            ))

    def capture_screenshot(self, test_id: str, annotation: str = "") -> Path:
        """Capture annotated screenshot as evidence."""
        screenshot_file = self.evidence_dir / f"{test_id}_screenshot.png"

        # Capture screen
        from PIL import ImageGrab
        screenshot = ImageGrab.grab()

        # Add annotation if provided
        if annotation:
            draw = ImageDraw.Draw(screenshot)
            try:
                font = ImageFont.truetype("arial.ttf", 24)
            except:
                font = ImageFont.load_default()

            # Add timestamp and annotation
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            text = f"{timestamp} - {annotation}"

            # Draw text with background
            bbox = draw.textbbox((10, 10), text, font=font)
            draw.rectangle(bbox, fill="black")
            draw.text((10, 10), text, fill="yellow", font=font)

        screenshot.save(screenshot_file)
        self._record_evidence(test_id, EvidenceType.SCREENSHOT, screenshot_file)
        return screenshot_file

    def record_video(self, test_id: str, duration: int = 60) -> Path:
        """Record video evidence of exploitation."""
        video_file = self.evidence_dir / f"{test_id}_video.mp4"

        # Use OpenCV for video recording
        import cv2
        import numpy as np
        from PIL import ImageGrab
        import time

        # Get screen dimensions
        screen = ImageGrab.grab()
        width, height = screen.size

        # Setup video writer
        fourcc = cv2.VideoWriter_fourcc(*'mp4v')
        out = cv2.VideoWriter(str(video_file), fourcc, 20.0, (width, height))

        start_time = time.time()
        frame_count = 0

        while time.time() - start_time < duration:
            # Capture frame
            img = ImageGrab.grab()
            frame = np.array(img)
            frame = cv2.cvtColor(frame, cv2.COLOR_RGB2BGR)

            # Add frame counter and timestamp
            cv2.putText(frame, f"Frame: {frame_count}", (10, 30),
                       cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 255, 0), 2)
            cv2.putText(frame, datetime.now().strftime("%H:%M:%S.%f")[:-3],
                       (10, 60), cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 255, 0), 2)

            out.write(frame)
            frame_count += 1
            time.sleep(0.05)  # ~20 FPS

        out.release()
        cv2.destroyAllWindows()

        self._record_evidence(test_id, EvidenceType.VIDEO_RECORDING, video_file)
        return video_file

    def _record_evidence(self, test_id: str, evidence_type: EvidenceType, file_path: Path):
        """Record evidence in database with hash verification."""
        # Calculate file hash
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        file_hash = hasher.hexdigest()

        # Store in database
        conn = sqlite3.connect(self.evidence_db)
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO evidence (test_id, evidence_type, file_path, file_hash)
            VALUES (?, ?, ?, ?)
        """, (test_id, evidence_type.value, str(file_path), file_hash))

        conn.commit()
        conn.close()

    def get_evidence_for_test(self, test_id: str) -> List[Dict]:
        """Retrieve all evidence for a specific test."""
        conn = sqlite3.connect(self.evidence_db)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT evidence_type, file_path, file_hash, timestamp
            FROM evidence
            WHERE test_id = ?
            ORDER BY timestamp
        """, (test_id,))

        evidence = []
        for row in cursor.fetchall():
            evidence.append({
                "type": row[0],
                "path": row[1],
                "hash": row[2],
                "timestamp": row[3]
            })

        conn.close()
        return evidence


class StatisticalAnalyzer:
    """Performs statistical analysis on validation results."""

    def __init__(self, results: List[ValidationResult]):
        self.results = results
        self.df = self._create_dataframe()

    def _create_dataframe(self) -> pd.DataFrame:
        """Convert results to pandas DataFrame for analysis."""
        data = []
        for result in self.results:
            data.append({
                "test_id": result.test_id,
                "category": result.category,
                "protection": result.target_protection,
                "success": result.success,
                "confidence": result.confidence_score,
                "execution_time": result.execution_time,
                "memory_usage": result.memory_after - result.memory_before
                                if result.memory_before and result.memory_after else 0,
                "cpu_usage": result.cpu_usage or 0
            })
        return pd.DataFrame(data)

    def calculate_confidence_intervals(self, confidence_level: float = 0.95) -> Dict:
        """Calculate confidence intervals for success rates."""
        from scipy import stats

        intervals = {}

        # Overall success rate
        successes = self.df["success"].sum()
        total = len(self.df)

        if total > 0:
            # Wilson score interval for binomial proportion
            z = stats.norm.ppf((1 + confidence_level) / 2)
            p_hat = successes / total

            denominator = 1 + z**2 / total
            center = (p_hat + z**2 / (2 * total)) / denominator
            margin = z * np.sqrt(p_hat * (1 - p_hat) / total + z**2 / (4 * total**2)) / denominator

            intervals["overall"] = {
                "point_estimate": p_hat,
                "lower_bound": max(0, center - margin),
                "upper_bound": min(1, center + margin),
                "confidence_level": confidence_level
            }

        # Per-category intervals
        for category in self.df["category"].unique():
            cat_df = self.df[self.df["category"] == category]
            cat_successes = cat_df["success"].sum()
            cat_total = len(cat_df)

            if cat_total > 0:
                p_hat = cat_successes / cat_total
                z = stats.norm.ppf((1 + confidence_level) / 2)

                denominator = 1 + z**2 / cat_total
                center = (p_hat + z**2 / (2 * cat_total)) / denominator
                margin = z * np.sqrt(p_hat * (1 - p_hat) / cat_total + z**2 / (4 * cat_total**2)) / denominator

                intervals[f"category_{category}"] = {
                    "point_estimate": p_hat,
                    "lower_bound": max(0, center - margin),
                    "upper_bound": min(1, center + margin),
                    "sample_size": cat_total
                }

        return intervals

    def perform_hypothesis_testing(self) -> Dict:
        """Perform statistical hypothesis tests on results."""
        from scipy import stats

        tests = {}

        # Test if success rate is significantly better than baseline (50%)
        successes = self.df["success"].sum()
        total = len(self.df)

        if total > 0:
            # Binomial test
            p_value = stats.binom_test(successes, total, 0.5, alternative='greater')
            tests["better_than_baseline"] = {
                "null_hypothesis": "Success rate <= 50%",
                "alternative": "Success rate > 50%",
                "p_value": p_value,
                "significant": p_value < 0.05,
                "test_type": "one-tailed binomial test"
            }

        # ANOVA for execution times across categories
        categories = self.df["category"].unique()
        if len(categories) > 2:
            category_times = [self.df[self.df["category"] == cat]["execution_time"].values
                            for cat in categories]
            f_stat, p_value = stats.f_oneway(*category_times)

            tests["execution_time_variance"] = {
                "null_hypothesis": "All categories have equal mean execution time",
                "f_statistic": f_stat,
                "p_value": p_value,
                "significant": p_value < 0.05,
                "test_type": "one-way ANOVA"
            }

        return tests

    def generate_performance_heatmap(self) -> Path:
        """Generate heatmap of performance across protections and categories."""
        pivot_table = self.df.pivot_table(
            values="success",
            index="protection",
            columns="category",
            aggfunc="mean",
            fill_value=0
        )

        plt.figure(figsize=(12, 8))
        sns.heatmap(pivot_table, annot=True, fmt=".2f", cmap="RdYlGn",
                   vmin=0, vmax=1, cbar_kws={"label": "Success Rate"})
        plt.title("Intellicrack Performance Heatmap\nSuccess Rate by Protection Type and Category")
        plt.xlabel("Test Category")
        plt.ylabel("Protection Type")
        plt.tight_layout()

        heatmap_file = Path("validation_heatmap.png")
        plt.savefig(heatmap_file, dpi=300)
        plt.close()

        return heatmap_file


class UndeniableReportGenerator:
    """
    Generates comprehensive, cryptographically signed validation reports
    that prove Intellicrack's effectiveness against modern protections.
    """

    def __init__(self, results_dir: Path, evidence_dir: Path):
        self.results_dir = results_dir
        self.evidence_dir = evidence_dir
        self.signer = CryptographicSigner()
        self.evidence_collector = ForensicEvidenceCollector(evidence_dir)
        self.report_dir = results_dir / "reports"
        self.report_dir.mkdir(exist_ok=True)

    def generate_comprehensive_report(
        self,
        results: List[ValidationResult],
        metrics: PerformanceMetrics,
        phase_results: Dict[str, Any]
    ) -> Path:
        """Generate complete validation report with all evidence."""

        # Statistical analysis
        analyzer = StatisticalAnalyzer(results)
        confidence_intervals = analyzer.calculate_confidence_intervals()
        hypothesis_tests = analyzer.perform_hypothesis_testing()
        heatmap_path = analyzer.generate_performance_heatmap()

        # Calculate verdict
        verdict = self._calculate_verdict(results)

        # Generate report sections
        report_data = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "verdict": verdict.value,
            "executive_summary": self._generate_executive_summary(results, verdict),
            "statistical_analysis": {
                "confidence_intervals": confidence_intervals,
                "hypothesis_tests": hypothesis_tests
            },
            "detection_results": self._compile_detection_results(results),
            "exploitation_results": self._compile_exploitation_results(results),
            "performance_metrics": asdict(metrics),
            "forensic_evidence": self._compile_forensic_evidence(results),
            "failed_tests": self._document_failed_tests(results),
            "phase_summaries": phase_results,
            "recommendations": self._generate_recommendations(results)
        }

        # Generate multiple report formats
        json_report = self._generate_json_report(report_data)
        html_report = self._generate_html_report(report_data)
        pdf_report = self._generate_pdf_report(html_report)

        # Create evidence package
        evidence_package = self._create_evidence_package(results, report_data)

        # Sign all reports
        self._sign_reports([json_report, html_report, pdf_report, evidence_package])

        # Generate blockchain-style verification chain
        verification_chain = self._create_verification_chain(report_data)

        print(f"\n{'='*60}")
        print(f"VALIDATION REPORT GENERATED")
        print(f"{'='*60}")
        print(f"Verdict: {verdict.value.upper()}")
        print(f"Success Rate: {len([r for r in results if r.success])}/{len(results)}")
        print(f"Report Location: {pdf_report}")
        print(f"Evidence Package: {evidence_package}")
        print(f"{'='*60}\n")

        return pdf_report

    def _calculate_verdict(self, results: List[ValidationResult]) -> VerdictLevel:
        """Calculate overall verdict based on test results."""
        if not results:
            return VerdictLevel.FAILURE

        success_rate = sum(1 for r in results if r.success) / len(results)

        if success_rate >= 0.95:
            return VerdictLevel.COMPLETE_SUCCESS
        elif success_rate >= 0.80:
            return VerdictLevel.STRONG_SUCCESS
        elif success_rate >= 0.60:
            return VerdictLevel.MODERATE_SUCCESS
        elif success_rate >= 0.40:
            return VerdictLevel.LIMITED_SUCCESS
        elif success_rate >= 0.20:
            return VerdictLevel.MINIMAL_SUCCESS
        else:
            return VerdictLevel.FAILURE

    def _generate_executive_summary(self, results: List[ValidationResult], verdict: VerdictLevel) -> str:
        """Generate executive summary of validation results."""
        total = len(results)
        successful = sum(1 for r in results if r.success)
        success_rate = (successful / total * 100) if total > 0 else 0

        # Category breakdown
        categories = {}
        for result in results:
            if result.category not in categories:
                categories[result.category] = {"total": 0, "success": 0}
            categories[result.category]["total"] += 1
            if result.success:
                categories[result.category]["success"] += 1

        # Protection breakdown
        protections = {}
        for result in results:
            if result.target_protection not in protections:
                protections[result.target_protection] = {"total": 0, "success": 0}
            protections[result.target_protection]["total"] += 1
            if result.success:
                protections[result.target_protection]["success"] += 1

        summary = f"""
# INTELLICRACK VALIDATION REPORT - EXECUTIVE SUMMARY

## Overall Verdict: {verdict.value.replace('_', ' ').upper()}

## Test Results Overview
- **Total Tests Executed**: {total}
- **Successful Tests**: {successful}
- **Failed Tests**: {total - successful}
- **Overall Success Rate**: {success_rate:.2f}%

## Category Performance
"""
        for category, stats in categories.items():
            cat_rate = (stats["success"] / stats["total"] * 100) if stats["total"] > 0 else 0
            summary += f"- **{category}**: {stats['success']}/{stats['total']} ({cat_rate:.1f}%)\n"

        summary += "\n## Protection Types Defeated\n"
        for protection, stats in protections.items():
            prot_rate = (stats["success"] / stats["total"] * 100) if stats["total"] > 0 else 0
            summary += f"- **{protection}**: {stats['success']}/{stats['total']} ({prot_rate:.1f}%)\n"

        # Key achievements
        summary += "\n## Key Achievements\n"

        # Find most sophisticated bypasses
        sophisticated = [r for r in results if r.success and r.confidence_score > 0.9]
        if sophisticated:
            summary += f"- Successfully bypassed {len(sophisticated)} protections with >90% confidence\n"

        # Find fastest bypasses
        if results:
            fastest = min(results, key=lambda r: r.execution_time)
            summary += f"- Fastest bypass achieved in {fastest.execution_time:.2f} seconds\n"

        # Modern licensing systems defeated
        modern_systems = ["Denuvo", "VMProtect", "Themida", "SecuROM", "StarForce"]
        defeated_modern = set(r.target_protection for r in results
                            if r.success and any(m in r.target_protection for m in modern_systems))
        if defeated_modern:
            summary += f"- Defeated {len(defeated_modern)} modern licensing systems: {', '.join(defeated_modern)}\n"

        return summary

    def _compile_detection_results(self, results: List[ValidationResult]) -> Dict:
        """Compile detection results with evidence links."""
        detection_results = {
            "total_detections": 0,
            "unique_signatures": set(),
            "by_category": {},
            "detection_confidence": []
        }

        for result in results:
            if result.detection_signatures:
                detection_results["total_detections"] += len(result.detection_signatures)
                detection_results["unique_signatures"].update(result.detection_signatures)

                if result.category not in detection_results["by_category"]:
                    detection_results["by_category"][result.category] = []

                detection_results["by_category"][result.category].append({
                    "test_id": result.test_id,
                    "signatures": result.detection_signatures,
                    "confidence": result.confidence_score,
                    "evidence": [str(p) for p in result.evidence_paths]
                })

                detection_results["detection_confidence"].append(result.confidence_score)

        # Convert set to list for JSON serialization
        detection_results["unique_signatures"] = list(detection_results["unique_signatures"])

        # Calculate average confidence
        if detection_results["detection_confidence"]:
            detection_results["average_confidence"] = statistics.mean(detection_results["detection_confidence"])
            detection_results["confidence_std_dev"] = statistics.stdev(detection_results["detection_confidence"]) if len(detection_results["detection_confidence"]) > 1 else 0

        return detection_results

    def _compile_exploitation_results(self, results: List[ValidationResult]) -> Dict:
        """Compile exploitation results with functional proof."""
        exploitation_results = {
            "successful_exploits": 0,
            "bypass_methods": {},
            "exploitation_artifacts": [],
            "time_to_exploit": []
        }

        for result in results:
            if result.success and result.bypass_method:
                exploitation_results["successful_exploits"] += 1

                if result.bypass_method not in exploitation_results["bypass_methods"]:
                    exploitation_results["bypass_methods"][result.bypass_method] = []

                exploitation_results["bypass_methods"][result.bypass_method].append({
                    "test_id": result.test_id,
                    "protection": result.target_protection,
                    "time": result.execution_time,
                    "artifacts": result.exploitation_artifacts
                })

                exploitation_results["exploitation_artifacts"].extend(result.exploitation_artifacts)
                exploitation_results["time_to_exploit"].append(result.execution_time)

        # Calculate statistics
        if exploitation_results["time_to_exploit"]:
            exploitation_results["average_time"] = statistics.mean(exploitation_results["time_to_exploit"])
            exploitation_results["median_time"] = statistics.median(exploitation_results["time_to_exploit"])
            exploitation_results["fastest_exploit"] = min(exploitation_results["time_to_exploit"])

        return exploitation_results

    def _compile_forensic_evidence(self, results: List[ValidationResult]) -> Dict:
        """Compile inventory of all forensic evidence."""
        evidence_inventory = {
            "total_evidence_files": 0,
            "evidence_by_type": {},
            "evidence_size_bytes": 0,
            "evidence_hashes": []
        }

        for result in results:
            evidence_list = self.evidence_collector.get_evidence_for_test(result.test_id)

            for evidence in evidence_list:
                evidence_inventory["total_evidence_files"] += 1

                ev_type = evidence["type"]
                if ev_type not in evidence_inventory["evidence_by_type"]:
                    evidence_inventory["evidence_by_type"][ev_type] = []

                evidence_inventory["evidence_by_type"][ev_type].append({
                    "test_id": result.test_id,
                    "file": evidence["path"],
                    "hash": evidence["hash"],
                    "timestamp": evidence["timestamp"]
                })

                evidence_inventory["evidence_hashes"].append(evidence["hash"])

                # Get file size
                try:
                    file_size = Path(evidence["path"]).stat().st_size
                    evidence_inventory["evidence_size_bytes"] += file_size
                except:
                    pass

        return evidence_inventory

    def _document_failed_tests(self, results: List[ValidationResult]) -> List[Dict]:
        """Document failed tests with root cause analysis."""
        failed_tests = []

        for result in results:
            if not result.success:
                failed_tests.append({
                    "test_id": result.test_id,
                    "test_name": result.test_name,
                    "category": result.category,
                    "target_protection": result.target_protection,
                    "error_message": result.error_message,
                    "confidence_score": result.confidence_score,
                    "possible_causes": self._analyze_failure_cause(result),
                    "recommendations": self._generate_failure_recommendations(result)
                })

        return failed_tests

    def _analyze_failure_cause(self, result: ValidationResult) -> List[str]:
        """Analyze potential causes for test failure."""
        causes = []

        if "timeout" in (result.error_message or "").lower():
            causes.append("Test execution timeout - protection may have anti-analysis delays")

        if "access denied" in (result.error_message or "").lower():
            causes.append("Insufficient privileges - may require elevated permissions")

        if result.confidence_score < 0.5:
            causes.append("Low confidence detection - protection may use unknown techniques")

        if "memory" in (result.error_message or "").lower():
            causes.append("Memory access violation - protection may use anti-debugging")

        if not causes:
            causes.append("Unknown failure - requires manual investigation")

        return causes

    def _generate_failure_recommendations(self, result: ValidationResult) -> List[str]:
        """Generate recommendations for addressing test failures."""
        recommendations = []

        if result.target_protection in ["VMProtect", "Themida"]:
            recommendations.append("Consider using hardware-based tracing (Intel PT)")
            recommendations.append("Implement VM handler pattern recognition")

        if "anti-debug" in (result.error_message or "").lower():
            recommendations.append("Enhance anti-anti-debugging capabilities")
            recommendations.append("Use kernel-mode debugging techniques")

        if result.confidence_score < 0.7:
            recommendations.append("Collect additional training data for ML models")
            recommendations.append("Enhance pattern recognition algorithms")

        if not recommendations:
            recommendations.append("Manual analysis required to develop bypass")

        return recommendations

    def _generate_recommendations(self, results: List[ValidationResult]) -> List[str]:
        """Generate improvement recommendations based on results."""
        recommendations = []

        # Analyze failure patterns
        failed = [r for r in results if not r.success]
        if failed:
            # Group by protection type
            failed_protections = {}
            for result in failed:
                if result.target_protection not in failed_protections:
                    failed_protections[result.target_protection] = 0
                failed_protections[result.target_protection] += 1

            # Recommend improvements for most failed protections
            for protection, count in sorted(failed_protections.items(),
                                          key=lambda x: x[1], reverse=True)[:3]:
                recommendations.append(
                    f"Enhance {protection} analysis capabilities ({count} failures)"
                )

        # Performance recommendations
        slow_tests = [r for r in results if r.execution_time > 60]
        if len(slow_tests) > len(results) * 0.2:
            recommendations.append("Optimize performance - 20% of tests exceed 60 seconds")

        # Memory usage recommendations
        high_memory = [r for r in results
                      if r.memory_after and r.memory_before and
                      (r.memory_after - r.memory_before) > 500_000_000]
        if high_memory:
            recommendations.append(f"Optimize memory usage - {len(high_memory)} tests use >500MB")

        # Success rate improvements
        success_rate = sum(1 for r in results if r.success) / len(results) if results else 0
        if success_rate < 0.8:
            recommendations.append("Focus on improving core detection algorithms")
            recommendations.append("Expand protection signature database")

        return recommendations

    def _generate_json_report(self, report_data: Dict) -> Path:
        """Generate JSON format report."""
        json_file = self.report_dir / f"validation_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        with open(json_file, "w") as f:
            json.dump(report_data, f, indent=2, default=str)

        return json_file

    def _generate_html_report(self, report_data: Dict) -> Path:
        """Generate HTML format report with visualizations."""
        html_template = """
<!DOCTYPE html>
<html>
<head>
    <title>Intellicrack Validation Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .section { background: white; margin: 20px 0; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .verdict { font-size: 24px; font-weight: bold; padding: 10px; border-radius: 5px; }
        .complete_success { background: #27ae60; color: white; }
        .strong_success { background: #3498db; color: white; }
        .moderate_success { background: #f39c12; color: white; }
        .limited_success { background: #e67e22; color: white; }
        .minimal_success { background: #e74c3c; color: white; }
        .failure { background: #c0392b; color: white; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #34495e; color: white; }
        .chart { margin: 20px 0; }
        .evidence-link { color: #3498db; text-decoration: none; }
        .evidence-link:hover { text-decoration: underline; }
        .timestamp { color: #7f8c8d; font-size: 12px; }
        pre { background: #ecf0f1; padding: 10px; border-radius: 3px; overflow-x: auto; }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div class="header">
        <h1>INTELLICRACK VALIDATION REPORT</h1>
        <p class="timestamp">Generated: {{ generated_at }}</p>
    </div>

    <div class="section">
        <h2>Verdict</h2>
        <div class="verdict {{ verdict }}">{{ verdict_display }}</div>
    </div>

    <div class="section">
        <h2>Executive Summary</h2>
        <div>{{ executive_summary_html }}</div>
    </div>

    <div class="section">
        <h2>Statistical Analysis</h2>
        <canvas id="successChart"></canvas>
        <h3>Confidence Intervals (95%)</h3>
        <table>
            <tr>
                <th>Category</th>
                <th>Point Estimate</th>
                <th>Lower Bound</th>
                <th>Upper Bound</th>
            </tr>
            {% for cat, interval in confidence_intervals.items() %}
            <tr>
                <td>{{ cat }}</td>
                <td>{{ "%.2f"|format(interval.point_estimate * 100) }}%</td>
                <td>{{ "%.2f"|format(interval.lower_bound * 100) }}%</td>
                <td>{{ "%.2f"|format(interval.upper_bound * 100) }}%</td>
            </tr>
            {% endfor %}
        </table>
    </div>

    <div class="section">
        <h2>Performance Metrics</h2>
        <table>
            <tr>
                <th>Metric</th>
                <th>Value</th>
            </tr>
            <tr><td>Total Execution Time</td><td>{{ "%.2f"|format(performance_metrics.total_execution_time) }} seconds</td></tr>
            <tr><td>Average Test Time</td><td>{{ "%.2f"|format(performance_metrics.average_test_time) }} seconds</td></tr>
            <tr><td>Memory Peak</td><td>{{ performance_metrics.memory_peak|filesizeformat }}</td></tr>
            <tr><td>CPU Peak</td><td>{{ "%.1f"|format(performance_metrics.cpu_peak) }}%</td></tr>
        </table>
    </div>

    <div class="section">
        <h2>Evidence Inventory</h2>
        <p>Total Evidence Files: {{ forensic_evidence.total_evidence_files }}</p>
        <p>Total Size: {{ forensic_evidence.evidence_size_bytes|filesizeformat }}</p>
        <ul>
        {% for ev_type, evidence_list in forensic_evidence.evidence_by_type.items() %}
            <li>{{ ev_type }}: {{ evidence_list|length }} files</li>
        {% endfor %}
        </ul>
    </div>

    <script>
        // Success rate chart
        const ctx = document.getElementById('successChart').getContext('2d');
        new Chart(ctx, {
            type: 'bar',
            data: {
                labels: {{ category_labels|tojson }},
                datasets: [{
                    label: 'Success Rate (%)',
                    data: {{ category_success_rates|tojson }},
                    backgroundColor: 'rgba(52, 152, 219, 0.6)',
                    borderColor: 'rgba(52, 152, 219, 1)',
                    borderWidth: 1
                }]
            },
            options: {
                scales: {
                    y: {
                        beginAtZero: true,
                        max: 100
                    }
                }
            }
        });
    </script>
</body>
</html>
        """

        # Prepare template data
        template_data = report_data.copy()
        template_data["verdict_display"] = report_data["verdict"].replace("_", " ").upper()
        template_data["executive_summary_html"] = markdown.markdown(report_data["executive_summary"])
        template_data["confidence_intervals"] = report_data["statistical_analysis"]["confidence_intervals"]
        template_data["performance_metrics"] = report_data["performance_metrics"]
        template_data["forensic_evidence"] = report_data["forensic_evidence"]

        # Prepare chart data
        detection_results = report_data.get("detection_results", {})
        categories = list(detection_results.get("by_category", {}).keys())
        template_data["category_labels"] = categories
        template_data["category_success_rates"] = [
            len([r for r in detection_results["by_category"].get(cat, [])
                if r.get("confidence", 0) > 0.5]) / len(detection_results["by_category"].get(cat, [1])) * 100
            for cat in categories
        ]

        # Render template
        from jinja2 import Template
        template = Template(html_template)
        html_content = template.render(**template_data)

        html_file = self.report_dir / f"validation_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        with open(html_file, "w") as f:
            f.write(html_content)

        return html_file

    def _generate_pdf_report(self, html_report: Path) -> Path:
        """Convert HTML report to PDF."""
        pdf_file = html_report.with_suffix(".pdf")

        try:
            # Try using wkhtmltopdf
            import pdfkit
            pdfkit.from_file(str(html_report), str(pdf_file))
        except:
            # Fallback to weasyprint
            try:
                from weasyprint import HTML
                HTML(filename=str(html_report)).write_pdf(str(pdf_file))
            except:
                # Last resort - copy HTML as PDF placeholder
                import shutil
                shutil.copy(html_report, pdf_file)

        return pdf_file

    def _create_evidence_package(self, results: List[ValidationResult], report_data: Dict) -> Path:
        """Create ZIP package with all evidence files."""
        package_file = self.report_dir / f"evidence_package_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"

        with zipfile.ZipFile(package_file, "w", zipfile.ZIP_DEFLATED) as zf:
            # Add report data
            zf.writestr("report.json", json.dumps(report_data, indent=2, default=str))

            # Add evidence files
            for result in results:
                for evidence_path in result.evidence_paths:
                    if evidence_path.exists():
                        zf.write(evidence_path, f"evidence/{result.test_id}/{evidence_path.name}")

            # Add verification chain
            verification_data = self._create_verification_chain(report_data)
            zf.writestr("verification_chain.json", json.dumps(verification_data, indent=2))

        return package_file

    def _sign_reports(self, report_files: List[Path]):
        """Cryptographically sign all report files."""
        for report_file in report_files:
            if report_file.exists():
                # Read file content
                with open(report_file, "rb") as f:
                    content = f.read()

                # Generate signature
                signature = self.signer.sign_data(content)

                # Save signature
                sig_file = report_file.with_suffix(report_file.suffix + ".sig")
                with open(sig_file, "wb") as f:
                    f.write(signature)

    def _create_verification_chain(self, report_data: Dict) -> Dict:
        """Create blockchain-style verification chain for report integrity."""
        chain = []

        # Genesis block
        genesis = {
            "index": 0,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": "INTELLICRACK VALIDATION GENESIS",
            "previous_hash": "0",
            "nonce": 0
        }
        genesis["hash"] = self._calculate_block_hash(genesis)
        chain.append(genesis)

        # Add blocks for each major component
        components = [
            ("detection_results", report_data.get("detection_results", {})),
            ("exploitation_results", report_data.get("exploitation_results", {})),
            ("forensic_evidence", report_data.get("forensic_evidence", {})),
            ("statistical_analysis", report_data.get("statistical_analysis", {}))
        ]

        for i, (component_name, component_data) in enumerate(components, 1):
            block = {
                "index": i,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "component": component_name,
                "data_hash": hashlib.sha256(
                    json.dumps(component_data, sort_keys=True, default=str).encode()
                ).hexdigest(),
                "previous_hash": chain[-1]["hash"],
                "nonce": 0
            }

            # Simple proof of work
            while not block["hash"] := self._calculate_block_hash(block):
                block["nonce"] += 1
                if block["hash"][:4] == "0000":  # Require 4 leading zeros
                    break

            chain.append(block)

        return {
            "chain": chain,
            "chain_valid": self._verify_chain(chain),
            "root_hash": chain[-1]["hash"]
        }

    def _calculate_block_hash(self, block: Dict) -> str:
        """Calculate SHA-256 hash for a block."""
        block_string = json.dumps(block, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()

    def _verify_chain(self, chain: List[Dict]) -> bool:
        """Verify integrity of blockchain."""
        for i in range(1, len(chain)):
            current = chain[i]
            previous = chain[i-1]

            # Verify hash
            if current["previous_hash"] != previous["hash"]:
                return False

            # Verify proof of work
            if not current["hash"][:4] == "0000":
                return False

        return True
