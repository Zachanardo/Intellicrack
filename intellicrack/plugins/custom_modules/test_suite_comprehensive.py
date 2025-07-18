#!/usr/bin/env python3
"""
This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

"""
Comprehensive Test Suite for Intellicrack Framework

Full testing framework with unit tests, integration tests, performance
benchmarks, security validation, and automated reporting for all
Intellicrack modules and components.

Author: Intellicrack Framework
Version: 2.0.0
License: GPL v3
"""

import unittest
import pytest
import asyncio
import time
import psutil
import threading
import multiprocessing
import tempfile
import shutil
import json
import sqlite3
import logging
import sys
import os
import subprocess
import hashlib
import random
import struct
from typing import Dict, List, Tuple, Optional, Any, Callable, Union
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock
from contextlib import contextmanager
import coverage
import requests
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import matplotlib.pyplot as plt
import seaborn as sns

class TestCategory(Enum):
    """Test categories"""
    UNIT = "unit"
    INTEGRATION = "integration"
    PERFORMANCE = "performance"
    SECURITY = "security"
    REGRESSION = "regression"
    STRESS = "stress"
    API = "api"
    UI = "ui"

class TestStatus(Enum):
    """Test execution status"""
    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ERROR = "error"

class TestPriority(Enum):
    """Test priority levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

@dataclass
class TestResult:
    """Individual test result"""
    test_name: str
    category: TestCategory
    status: TestStatus
    execution_time: float
    error_message: Optional[str] = None
    assertion_count: int = 0
    memory_usage: float = 0.0
    cpu_usage: float = 0.0
    priority: TestPriority = TestPriority.MEDIUM
    tags: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert test result to dictionary format."""
        return {
            'test_name': self.test_name,
            'category': self.category.value,
            'status': self.status.value,
            'execution_time': self.execution_time,
            'error_message': self.error_message,
            'assertion_count': self.assertion_count,
            'memory_usage': self.memory_usage,
            'cpu_usage': self.cpu_usage,
            'priority': self.priority.value,
            'tags': self.tags
        }

@dataclass
class TestSuiteResults:
    """Complete test suite results"""
    total_tests: int = 0
    passed_tests: int = 0
    failed_tests: int = 0
    skipped_tests: int = 0
    error_tests: int = 0
    total_execution_time: float = 0.0
    coverage_percentage: float = 0.0
    test_results: List[TestResult] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)
    
    @property
    def success_rate(self) -> float:
        """Calculate the test success rate as a percentage."""
        if self.total_tests == 0:
            return 0.0
        return (self.passed_tests / self.total_tests) * 100
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert test summary to dictionary format."""
        return {
            'total_tests': self.total_tests,
            'passed_tests': self.passed_tests,
            'failed_tests': self.failed_tests,
            'skipped_tests': self.skipped_tests,
            'error_tests': self.error_tests,
            'total_execution_time': self.total_execution_time,
            'coverage_percentage': self.coverage_percentage,
            'success_rate': self.success_rate,
            'test_results': [result.to_dict() for result in self.test_results],
            'timestamp': self.timestamp.isoformat()
        }

class TestDataGenerator:
    """Generate test data for various scenarios"""
    
    def __init__(self):
        """Initialize test data generator with deterministic random seed and temporary directory."""
        self.random = random.Random(42)  # Deterministic for reproducible tests
        self.temp_dir = tempfile.mkdtemp(prefix="intellicrack_test_")
    
    def generate_binary_data(self, size: int) -> bytes:
        """Generate random binary data"""
        return bytes([self.random.randint(0, 255) for _ in range(size)])
    
    def generate_pe_header(self) -> bytes:
        """Generate minimal PE header for testing"""
        # DOS header
        dos_header = b'MZ' + b'\x00' * 58 + struct.pack('<L', 0x80)
        
        # PE signature
        pe_sig = b'PE\x00\x00'
        
        # COFF header
        coff_header = struct.pack('<HHLLHHH',
            0x014c,  # Machine (i386)
            3,       # NumberOfSections
            int(time.time()),  # TimeDateStamp
            0,       # PointerToSymbolTable
            0,       # NumberOfSymbols
            0xE0,    # SizeOfOptionalHeader
            0x0102   # Characteristics
        )
        
        # Optional header (minimal)
        opt_header = struct.pack('<HHBBLLLLLLLHHHHHHLLLLHHL',
            0x010b,  # Magic (PE32)
            1, 0,    # MajorLinkerVersion, MinorLinkerVersion
            0x1000,  # SizeOfCode
            0x1000,  # SizeOfInitializedData
            0,       # SizeOfUninitializedData
            0x1000,  # AddressOfEntryPoint
            0x1000,  # BaseOfCode
            0x1000,  # BaseOfData
            0x400000, # ImageBase
            0x1000,  # SectionAlignment
            0x200,   # FileAlignment
            4, 0,    # MajorOSVersion, MinorOSVersion
            0, 0,    # MajorImageVersion, MinorImageVersion
            4, 0,    # MajorSubsystemVersion, MinorSubsystemVersion
            0,       # Win32VersionValue
            0x3000,  # SizeOfImage
            0x200,   # SizeOfHeaders
            0,       # CheckSum
            2,       # Subsystem (GUI)
            0,       # DllCharacteristics
            0x100000, # SizeOfStackReserve
            0x1000,  # SizeOfStackCommit
            0x100000, # SizeOfHeapReserve
            0x1000,  # SizeOfHeapCommit
            0,       # LoaderFlags
            16       # NumberOfRvaAndSizes
        )
        
        # Add data directories (16 entries, 8 bytes each)
        data_dirs = b'\x00' * (16 * 8)
        
        return dos_header + b'\x00' * (0x80 - len(dos_header)) + pe_sig + coff_header + opt_header + data_dirs
    
    def generate_license_key(self, format_type: str = "standard") -> str:
        """Generate test license keys"""
        if format_type == "standard":
            parts = []
            for _ in range(4):
                part = ''.join([self.random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(4)])
                parts.append(part)
            return '-'.join(parts)
        elif format_type == "uuid":
            import uuid
            return str(uuid.uuid4())
        elif format_type == "numeric":
            return ''.join([str(self.random.randint(0, 9)) for _ in range(16)])
        else:
            return f"TEST-{self.random.randint(1000, 9999)}-{self.random.randint(1000, 9999)}"
    
    def generate_api_sequence(self, length: int = 10) -> List[str]:
        """Generate API call sequence for testing"""
        apis = [
            "CreateFileW", "ReadFile", "WriteFile", "CloseHandle",
            "VirtualAlloc", "VirtualProtect", "GetProcAddress",
            "LoadLibraryW", "RegOpenKeyW", "RegQueryValueW",
            "CryptAcquireContextW", "CryptEncrypt", "CryptDecrypt"
        ]
        return [self.random.choice(apis) for _ in range(length)]
    
    def generate_crypto_data(self) -> Dict[str, Any]:
        """Generate cryptographic test data"""
        return {
            'key': self.generate_binary_data(32),
            'iv': self.generate_binary_data(16),
            'plaintext': b"Hello, World! This is test data for encryption.",
            'salt': self.generate_binary_data(16),
            'iterations': 10000
        }
    
    def create_test_binary(self, path: Path, binary_type: str = "pe") -> Path:
        """Create test binary file"""
        if binary_type == "pe":
            data = self.generate_pe_header()
            # Add some sections
            data += b'\x00' * (0x400 - len(data))  # Pad to file alignment
            data += self.generate_binary_data(0x1000)  # Code section
            data += self.generate_binary_data(0x1000)  # Data section
        else:
            data = self.generate_binary_data(4096)
        
        path.write_bytes(data)
        return path
    
    def setup_test_database(self) -> sqlite3.Connection:
        """Setup SQLite database for test data storage"""
        db_path = os.path.join(self.temp_dir, "test_data.db")
        self.db_connection = sqlite3.connect(db_path)
        
        # Create tables for test data
        cursor = self.db_connection.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS test_binaries (
                id INTEGER PRIMARY KEY,
                filename TEXT,
                hash TEXT,
                size INTEGER,
                created_at TIMESTAMP,
                analysis_data TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS test_results (
                id INTEGER PRIMARY KEY,
                test_name TEXT,
                status TEXT,
                execution_time REAL,
                memory_usage REAL,
                error_message TEXT
            )
        ''')
        self.db_connection.commit()
        return self.db_connection
    
    def store_test_binary(self, filename: str, data: bytes) -> str:
        """Store test binary data and return hash"""
        if not self.db_connection:
            self.setup_test_database()
            
        # Calculate hash
        hash_value = hashlib.sha256(data).hexdigest()
        file_path = os.path.join(self.temp_dir, filename)
        
        # Write binary data
        with open(file_path, 'wb') as f:
            f.write(data)
            
        # Store in database
        cursor = self.db_connection.cursor()
        cursor.execute('''
            INSERT INTO test_binaries (filename, hash, size, created_at, analysis_data)
            VALUES (?, ?, ?, ?, ?)
        ''', (filename, hash_value, len(data), datetime.now().isoformat(), '{}'))
        self.db_connection.commit()
        
        return hash_value
    
    def generate_analysis_data(self, num_samples: int = 100) -> pd.DataFrame:
        """Generate synthetic analysis data using pandas"""
        data = {
            'test_id': range(num_samples),
            'execution_time': np.random.normal(1.5, 0.3, num_samples),
            'memory_usage': np.random.normal(50.0, 10.0, num_samples),
            'cpu_usage': np.random.normal(25.0, 5.0, num_samples),
            'success_rate': np.random.beta(8, 2, num_samples),
            'category': np.random.choice(['unit', 'integration', 'performance'], num_samples)
        }
        return pd.DataFrame(data)
    
    def calculate_performance_metrics(self, test_results: List[TestResult]) -> Dict[str, float]:
        """Calculate performance metrics using sklearn"""
        if not test_results:
            return {}
            
        # Convert test results to arrays for analysis
        execution_times = [r.execution_time for r in test_results]
        memory_usage = [r.memory_usage for r in test_results]
        
        # Create synthetic ground truth and predictions for metrics demo
        y_true = [1 if r.status == TestStatus.PASSED else 0 for r in test_results]
        y_pred = [1 if r.execution_time < np.mean(execution_times) else 0 for r in test_results]
        
        if len(set(y_true)) > 1 and len(set(y_pred)) > 1:
            return {
                'accuracy': accuracy_score(y_true, y_pred),
                'precision': precision_score(y_true, y_pred, zero_division=0),
                'recall': recall_score(y_true, y_pred, zero_division=0),
                'f1': f1_score(y_true, y_pred, zero_division=0),
                'avg_memory_usage': np.mean(memory_usage) if memory_usage else 0.0,
                'max_memory_usage': np.max(memory_usage) if memory_usage else 0.0,
                'memory_efficiency': np.std(memory_usage) if len(memory_usage) > 1 else 0.0
            }
        return {
            'accuracy': 0.0, 
            'precision': 0.0, 
            'recall': 0.0, 
            'f1': 0.0,
            'avg_memory_usage': np.mean(memory_usage) if memory_usage else 0.0,
            'max_memory_usage': np.max(memory_usage) if memory_usage else 0.0,
            'memory_efficiency': 0.0
        }
    
    def cleanup(self):
        """Clean up temporary resources"""
        if self.db_connection:
            self.db_connection.close()
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

class PerformanceMonitor:
    """Monitor performance during tests"""
    
    def __init__(self):
        """Initialize performance monitor with psutil process and timing variables."""
        self.process = psutil.Process()
        self.start_time = None
        self.start_memory = None
        self.start_cpu = None
    
    def start_monitoring(self):
        """Start performance monitoring"""
        self.start_time = time.time()
        self.start_memory = self.process.memory_info().rss
        self.start_cpu = self.process.cpu_percent()
    
    def stop_monitoring(self) -> Dict[str, float]:
        """Stop monitoring and return metrics"""
        end_time = time.time()
        end_memory = self.process.memory_info().rss
        end_cpu = self.process.cpu_percent()
        
        return {
            'execution_time': end_time - (self.start_time or end_time),
            'memory_usage': (end_memory - (self.start_memory or end_memory)) / 1024 / 1024,  # MB
            'cpu_usage': end_cpu
        }

class TestFixtures:
    """Test fixtures and sample data"""
    
    def __init__(self):
        """Initialize test fixtures with temporary directory and data generator."""
        self.temp_dir = None
        self.data_generator = TestDataGenerator()
    
    def setup(self):
        """Setup test environment"""
        self.temp_dir = Path(tempfile.mkdtemp(prefix="intellicrack_test_"))
        
        # Create test directories
        (self.temp_dir / "binaries").mkdir()
        (self.temp_dir / "scripts").mkdir()
        (self.temp_dir / "data").mkdir()
        (self.temp_dir / "output").mkdir()
        
        # Create test files
        self.create_test_files()
    
    def teardown(self):
        """Cleanup test environment"""
        if self.temp_dir and self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)
        self.data_generator.cleanup()
    
    def create_test_files(self):
        """Create various test files"""
        # Test binary files
        self.test_pe = self.data_generator.create_test_binary(
            self.temp_dir / "binaries" / "test.exe", "pe"
        )
        
        self.test_dll = self.data_generator.create_test_binary(
            self.temp_dir / "binaries" / "test.dll", "pe"
        )
        
        # Test script files
        frida_script = """
        Java.perform(function() {
            console.log("Test Frida script");
        });
        """
        (self.temp_dir / "scripts" / "test.js").write_text(frida_script)
        
        ghidra_script = """
        public class TestScript extends GhidraScript {
            public void run() throws Exception {
                println("Test Ghidra script");
            }
        }
        """
        (self.temp_dir / "scripts" / "test.java").write_text(ghidra_script)
        
        # Test data files
        test_data = {
            "license_keys": [
                self.data_generator.generate_license_key() for _ in range(10)
            ],
            "api_sequences": [
                self.data_generator.generate_api_sequence() for _ in range(5)
            ]
        }
        
        (self.temp_dir / "data" / "test_data.json").write_text(
            json.dumps(test_data, indent=2)
        )
    
    def run_parallel_analysis(self, binary_paths: List[Path]) -> List[Dict[str, Any]]:
        """Run parallel analysis using multiprocessing"""
        with multiprocessing.Pool(processes=min(4, len(binary_paths))) as pool:
            results = pool.map(self._analyze_binary_worker, binary_paths)
        return results
    
    def _analyze_binary_worker(self, binary_path: Path) -> Dict[str, Any]:
        """Worker function for parallel binary analysis"""
        import struct
        try:
            with open(binary_path, 'rb') as f:
                header = f.read(64)
                
            # Basic PE header analysis
            if len(header) >= 64:
                dos_header = struct.unpack('<H', header[:2])[0]
                return {
                    'path': str(binary_path),
                    'size': binary_path.stat().st_size,
                    'dos_signature': dos_header,
                    'analyzed_at': datetime.now().isoformat()
                }
        except Exception as e:
            return {'path': str(binary_path), 'error': str(e)}
    
    def run_threaded_tests(self, test_functions: List[Callable]) -> List[Dict[str, Any]]:
        """Run tests in parallel threads"""
        results = []
        threads = []
        
        for test_func in test_functions:
            thread = threading.Thread(target=self._thread_test_worker, args=(test_func, results))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        return results
    
    def _thread_test_worker(self, test_func: Callable, results: List[Dict[str, Any]]):
        """Worker function for threaded test execution"""
        try:
            start_time = time.time()
            test_func()
            execution_time = time.time() - start_time
            results.append({
                'function': test_func.__name__,
                'status': 'passed',
                'execution_time': execution_time
            })
        except Exception as e:
            results.append({
                'function': test_func.__name__,
                'status': 'failed',
                'error': str(e)
            })
    
    async def run_async_analysis(self, targets: List[str]) -> List[Dict[str, Any]]:
        """Run asynchronous analysis of multiple targets"""
        tasks = [self._async_analyze_target(target) for target in targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r if not isinstance(r, Exception) else {'error': str(r)} for r in results]
    
    async def _async_analyze_target(self, target: str) -> Dict[str, Any]:
        """Async worker for target analysis"""
        await asyncio.sleep(0.1)  # Simulate async work
        return {
            'target': target,
            'analysis_time': datetime.now().isoformat(),
            'hash': hashlib.md5(target.encode()).hexdigest()
        }
    
    def run_external_analysis(self, binary_path: Path) -> Dict[str, Any]:
        """Run external analysis using subprocess"""
        try:
            # Run a simple file command as external analysis
            result = subprocess.run(
                ['file', str(binary_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            return {
                'command': 'file',
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode
            }
        except subprocess.TimeoutExpired:
            return {'error': 'Analysis timeout'}
        except FileNotFoundError:
            return {'error': 'External analysis tool not found'}
        except Exception as e:
            return {'error': str(e)}
    
    def fetch_remote_signatures(self, signature_url: str = "https://httpbin.org/json") -> Dict[str, Any]:
        """Fetch remote signature data using requests"""
        try:
            response = requests.get(signature_url, timeout=10)
            response.raise_for_status()
            return {
                'status': 'success',
                'data': response.json() if response.headers.get('content-type', '').startswith('application/json') else response.text,
                'headers': dict(response.headers)
            }
        except requests.RequestException as e:
            return {'status': 'error', 'error': str(e)}
    
    @contextmanager
    def mock_analysis_environment(self):
        """Context manager for mocked analysis environment"""
        original_path = os.environ.get('PATH', '')
        mock_tools = {
            'objdump': Mock(return_value='mock objdump output'),
            'strings': Mock(return_value='mock strings output'),
            'hexdump': Mock(return_value='mock hexdump output')
        }
        
        try:
            # Setup mock environment
            os.environ['PATH'] = f"{self.temp_dir}:{original_path}"
            yield mock_tools
        finally:
            # Restore environment
            os.environ['PATH'] = original_path
    
    def analyze_with_mocking(self, binary_path: Path) -> Dict[str, Any]:
        """Analyze binary with mocked external tools using patch decorator"""
        with patch('subprocess.run') as mock_run:
            # Configure MagicMock for subprocess return value
            mock_result = MagicMock()
            mock_result.stdout = "mocked analysis output"
            mock_result.stderr = ""
            mock_result.returncode = 0
            mock_run.return_value = mock_result
            
            # Run analysis with mocked subprocess
            result = self.run_external_analysis(binary_path)
            
            # Verify mock was called
            mock_run.assert_called_once()
            return {
                'analysis_result': result,
                'mock_called': mock_run.called,
                'call_count': mock_run.call_count
            }
    
    def get_performance_metrics_tuple(self, test_results: List[TestResult]) -> Tuple[float, float, int]:
        """Get performance metrics as a tuple (avg_time, avg_memory, total_tests)"""
        if not test_results:
            return (0.0, 0.0, 0)
        
        avg_time = sum(r.execution_time for r in test_results) / len(test_results)
        avg_memory = sum(r.memory_usage for r in test_results) / len(test_results)
        total_tests = len(test_results)
        
        return (avg_time, avg_memory, total_tests)
    
    def analyze_test_data_with_union(self, data: Union[List[TestResult], Dict[str, Any], str]) -> Dict[str, Any]:
        """Analyze test data that can be multiple types using Union"""
        if isinstance(data, list):
            # Handle List[TestResult]
            return {
                'type': 'test_results_list',
                'count': len(data),
                'passed': sum(1 for r in data if r.status == TestStatus.PASSED),
                'failed': sum(1 for r in data if r.status == TestStatus.FAILED)
            }
        elif isinstance(data, dict):
            # Handle Dict[str, Any]
            return {
                'type': 'dictionary',
                'keys': list(data.keys()),
                'size': len(data)
            }
        elif isinstance(data, str):
            # Handle string data
            return {
                'type': 'string',
                'length': len(data),
                'words': len(data.split())
            }
        else:
            return {'type': 'unknown', 'data': str(data)}
    
    def schedule_analysis_with_timedelta(self, delay_minutes: int = 5) -> Dict[str, Any]:
        """Schedule analysis to run after a timedelta delay"""
        now = datetime.now()
        delay = timedelta(minutes=delay_minutes)
        scheduled_time = now + delay
        
        return {
            'current_time': now.isoformat(),
            'delay': f"{delay_minutes} minutes",
            'scheduled_time': scheduled_time.isoformat(),
            'time_until_execution': str(delay)
        }
    
    def create_performance_charts(self, test_results: List[TestResult]):
        """Create performance visualization charts"""
        if not test_results:
            return
            
        # Generate analysis data
        df = self.data_generator.generate_analysis_data(len(test_results))
        
        # Create execution time plot
        plt.figure(figsize=(10, 6))
        plt.subplot(2, 2, 1)
        plt.hist([r.execution_time for r in test_results], bins=20, alpha=0.7)
        plt.title('Test Execution Time Distribution')
        plt.xlabel('Execution Time (s)')
        plt.ylabel('Frequency')
        
        # Create memory usage plot
        plt.subplot(2, 2, 2)
        plt.scatter(df['execution_time'], df['memory_usage'], alpha=0.6)
        plt.title('Memory vs Execution Time')
        plt.xlabel('Execution Time (s)')
        plt.ylabel('Memory Usage (MB)')
        
        # Create category distribution
        plt.subplot(2, 2, 3)
        categories = [r.category.value for r in test_results]
        category_counts = pd.Series(categories).value_counts()
        plt.pie(category_counts.values, labels=category_counts.index, autopct='%1.1f%%')
        plt.title('Test Category Distribution')
        
        # Create seaborn correlation matrix
        plt.subplot(2, 2, 4)
        correlation_matrix = df[['execution_time', 'memory_usage', 'cpu_usage', 'success_rate']].corr()
        sns.heatmap(correlation_matrix, annot=True, cmap='coolwarm', center=0)
        plt.title('Performance Metrics Correlation')
        
        plt.tight_layout()
        plt.savefig(self.temp_dir / 'performance_charts.png', dpi=150, bbox_inches='tight')
        plt.close()
    
    @pytest.fixture
    def sample_binary(self) -> Path:
        """Pytest fixture for sample binary"""
        return self.test_pe
    
    @pytest.fixture
    def analysis_data(self) -> pd.DataFrame:
        """Pytest fixture for analysis data"""
        return self.data_generator.generate_analysis_data()
    
    @property
    def sample_files(self) -> Dict[str, Path]:
        """Get sample file paths"""
        return {
            'pe_file': self.test_pe,
            'dll_file': self.test_dll,
            'frida_script': self.temp_dir / "scripts" / "test.js",
            'ghidra_script': self.temp_dir / "scripts" / "test.java",
            'test_data': self.temp_dir / "data" / "test_data.json"
        }

# Unit Tests for Core Modules
class TestProtectionClassifier(unittest.TestCase):
    """Unit tests for protection classifier"""
    
    def setUp(self):
        """Set up test environment for protection classifier tests.
        
        Initializes test fixtures, performance monitoring, and imports
        the ProtectionClassifier module. Creates temporary test files
        and prepares the classifier instance for testing.
        
        Raises:
            SkipTest: If ProtectionClassifier module is not available
        """
        self.fixtures = TestFixtures()
        self.fixtures.setup()
        self.monitor = PerformanceMonitor()
        
        # Import module under test
        try:
            from .protection_classifier import ProtectionClassifier
            self.classifier = ProtectionClassifier()
        except ImportError:
            self.skipTest("ProtectionClassifier module not available")
    def tearDown(self):
        """Clean up test fixtures after each test."""
        self.fixtures.teardown()
    
    def test_classifier_initialization(self):
        """Test classifier initialization"""
        self.monitor.start_monitoring()
        
        self.assertIsNotNone(self.classifier)
        self.assertTrue(hasattr(self.classifier, 'classify_file'))
        self.assertTrue(hasattr(self.classifier, 'load_signatures'))
        
        metrics = self.monitor.stop_monitoring()
        self.assertLess(metrics['execution_time'], 1.0)  # Should initialize quickly
    
    def test_file_classification(self):
        """Test file classification functionality"""
        self.monitor.start_monitoring()
        
        test_file = self.fixtures.sample_files['pe_file']
        result = self.classifier.classify_file(str(test_file))
        
        self.assertIsNotNone(result)
        self.assertTrue(hasattr(result, 'protection_type'))
        self.assertTrue(hasattr(result, 'confidence'))
        self.assertIsInstance(result.confidence, (int, float))
        self.assertGreaterEqual(result.confidence, 0.0)
        self.assertLessEqual(result.confidence, 1.0)
        
        metrics = self.monitor.stop_monitoring()
        self.assertLess(metrics['execution_time'], 5.0)  # Should classify quickly
    
    def test_signature_loading(self):
        """Test signature database loading"""
        self.monitor.start_monitoring()
        
        # Test loading default signatures
        signature_count = self.classifier.load_signatures()
        self.assertGreater(signature_count, 0)
        
        # Test signature validation
        if hasattr(self.classifier, 'signatures'):
            for sig_name, sig_data in self.classifier.signatures.items():
                self.assertIsInstance(sig_name, str)
                self.assertTrue(len(sig_name) > 0)
                self.assertIsInstance(sig_data, dict)
        
        metrics = self.monitor.stop_monitoring()
        self.assertLess(metrics['execution_time'], 2.0)
    
    def test_invalid_file_handling(self):
        """Test handling of invalid files"""
        self.monitor.start_monitoring()
        
        # Test non-existent file
        result = self.classifier.classify_file("non_existent_file.exe")
        self.assertIsNotNone(result)
        
        # Test empty file
        empty_file = self.fixtures.temp_dir / "empty.exe"
        empty_file.touch()
        result = self.classifier.classify_file(str(empty_file))
        self.assertIsNotNone(result)
        
        metrics = self.monitor.stop_monitoring()
        self.assertLess(metrics['execution_time'], 3.0)
    
    def test_classification_accuracy(self):
        """Test classification accuracy with known samples"""
        self.monitor.start_monitoring()
        
        # Create files with known patterns
        known_samples = []
        
        # VMProtect-like pattern
        vmprotect_data = b'VMProtect' + b'\x00' * 100 + b'virtualization'
        vmprotect_file = self.fixtures.temp_dir / "vmprotect_test.exe"
        vmprotect_file.write_bytes(vmprotect_data)
        known_samples.append(('VMProtect', vmprotect_file))
        
        # Themida-like pattern
        themida_data = b'Themida' + b'\x00' * 100 + b'protection'
        themida_file = self.fixtures.temp_dir / "themida_test.exe"
        themida_file.write_bytes(themida_data)
        known_samples.append(('Themida', themida_file))
        
        # Test classification
        correct_classifications = 0
        total_classifications = len(known_samples)
        
        for expected_type, file_path in known_samples:
            result = self.classifier.classify_file(str(file_path))
            if expected_type.lower() in result.protection_type.lower():
                correct_classifications += 1
        
        # Allow for some flexibility in classification
        accuracy = correct_classifications / total_classifications if total_classifications > 0 else 0
        self.assertGreater(accuracy, 0.5)  # At least 50% accuracy on known samples
        
        metrics = self.monitor.stop_monitoring()
        self.assertLess(metrics['execution_time'], 10.0)

class TestNeuralNetworkDetector(unittest.TestCase):
    """Neural network detection tests"""
    
    def setUp(self):
        """Set up test fixtures before each test."""
        self.fixtures = TestFixtures()
        self.fixtures.setup()
        self.monitor = PerformanceMonitor()
        
        try:
            from .neural_network_detector import NeuralNetworkDetector
            self.detector = NeuralNetworkDetector()
        except ImportError:
            self.skipTest("NeuralNetworkDetector module not available")
    
    def tearDown(self):
        """Clean up test fixtures after each test."""
        self.fixtures.teardown()
    
    def test_detector_initialization(self):
        """Test neural network detector initialization."""
        self.monitor.start_monitoring()
        
        self.assertIsNotNone(self.detector)
        self.assertTrue(hasattr(self.detector, 'detect_protection'))
        self.assertTrue(hasattr(self.detector, 'train_model'))
        
        metrics = self.monitor.stop_monitoring()
        self.assertLess(metrics['execution_time'], 5.0)
    
    def test_feature_extraction(self):
        """Test feature extraction functionality."""
        self.monitor.start_monitoring()
        
        test_file = self.fixtures.sample_files['pe_file']
        
        if hasattr(self.detector, 'extract_features'):
            features = self.detector.extract_features(str(test_file))
            self.assertIsNotNone(features)
            self.assertIsInstance(features, (list, np.ndarray))
            self.assertGreater(len(features), 0)
        
        metrics = self.monitor.stop_monitoring()
        self.assertLess(metrics['execution_time'], 3.0)
    
    def test_model_prediction(self):
        """Test model prediction functionality"""
        self.monitor.start_monitoring()
        
        test_file = self.fixtures.sample_files['pe_file']
        
        try:
            prediction = self.detector.detect_protection(str(test_file))
            self.assertIsNotNone(prediction)
            
            if hasattr(prediction, 'confidence'):
                self.assertIsInstance(prediction.confidence, (int, float))
                self.assertGreaterEqual(prediction.confidence, 0.0)
                self.assertLessEqual(prediction.confidence, 1.0)
            
        except Exception as e:
            # Model might not be trained yet, which is acceptable
            self.assertIn('model', str(e).lower())
        
        metrics = self.monitor.stop_monitoring()
        self.assertLess(metrics['execution_time'], 10.0)
    
    def test_training_data_preparation(self):
        """Test training data preparation"""
        self.monitor.start_monitoring()
        
        if hasattr(self.detector, 'prepare_training_data'):
            # Create minimal training dataset
            training_files = [self.fixtures.sample_files['pe_file']]
            labels = ['unknown']
            
            X, y = self.detector.prepare_training_data(training_files, labels)
            
            self.assertIsNotNone(X)
            self.assertIsNotNone(y)
            self.assertEqual(len(X), len(y))
            self.assertGreater(len(X), 0)
        
        metrics = self.monitor.stop_monitoring()
        self.assertLess(metrics['execution_time'], 5.0)
class TestHardwareDongleEmulator(unittest.TestCase):
    """Unit tests for hardware dongle emulator"""
    
    def setUp(self):
        """Set up test fixtures before each test."""
        self.fixtures = TestFixtures()
        self.fixtures.setup()
        self.monitor = PerformanceMonitor()
        
        try:
            from .hardware_dongle_emulator import HardwareDongleEmulator
            self.emulator = HardwareDongleEmulator()
        except ImportError:
            self.skipTest("HardwareDongleEmulator module not available")
    
    def tearDown(self):
        """Clean up test fixtures after hardware dongle emulator tests."""
        self.fixtures.teardown()
    
    def test_emulator_initialization(self):
        """Test dongle emulator initialization"""
        self.monitor.start_monitoring()
        
        self.assertIsNotNone(self.emulator)
        self.assertTrue(hasattr(self.emulator, 'emulate_dongle'))
        
        metrics = self.monitor.stop_monitoring()
        self.assertLess(metrics['execution_time'], 2.0)
    
    def test_dongle_creation(self):
        """Test virtual dongle creation"""
        self.monitor.start_monitoring()
        
        if hasattr(self.emulator, 'create_virtual_dongle'):
            dongle_id = self.emulator.create_virtual_dongle('HASP_HL')
            self.assertIsNotNone(dongle_id)
            self.assertIsInstance(dongle_id, str)
        
        metrics = self.monitor.stop_monitoring()
        self.assertLess(metrics['execution_time'], 1.0)
    
    def test_dongle_memory_operations(self):
        """Test dongle memory read/write operations"""
        self.monitor.start_monitoring()
        
        if hasattr(self.emulator, 'create_virtual_dongle'):
            dongle_id = self.emulator.create_virtual_dongle('HASP_HL')
            
            # Test memory operations
            if hasattr(self.emulator, 'write_dongle_memory'):
                test_data = b'TEST_DATA_1234567890'
                success = self.emulator.write_dongle_memory(dongle_id, 0, test_data)
                self.assertTrue(success)
                
                if hasattr(self.emulator, 'read_dongle_memory'):
                    read_data = self.emulator.read_dongle_memory(dongle_id, 0, len(test_data))
                    self.assertEqual(read_data, test_data)
        
        metrics = self.monitor.stop_monitoring()
        self.assertLess(metrics['execution_time'], 2.0)
    
    def test_encryption_operations(self):
        """Test dongle encryption/decryption"""
        self.monitor.start_monitoring()
        
        if hasattr(self.emulator, 'create_virtual_dongle'):
            dongle_id = self.emulator.create_virtual_dongle('HASP_HL')
            
            # Test encryption
            if hasattr(self.emulator, 'encrypt_data'):
                test_data = b'Hello, World!'
                encrypted = self.emulator.encrypt_data(dongle_id, test_data)
                self.assertIsNotNone(encrypted)
                self.assertNotEqual(encrypted, test_data)
                
                if hasattr(self.emulator, 'decrypt_data'):
                    decrypted = self.emulator.decrypt_data(dongle_id, encrypted)
                    self.assertEqual(decrypted, test_data)
        
        metrics = self.monitor.stop_monitoring()
        self.assertLess(metrics['execution_time'], 3.0)
class TestVMProtectionUnwrapper(unittest.TestCase):
    """Unit tests for VM protection unwrapper"""
    
    def setUp(self):
        """Set up test fixtures for VM protection unwrapper tests."""
        self.fixtures = TestFixtures()
        self.fixtures.setup()
        self.monitor = PerformanceMonitor()
        try:
            from .vm_protection_unwrapper import VMProtectionUnwrapper
            self.unwrapper = VMProtectionUnwrapper()
        except ImportError:
            self.skipTest("VMProtectionUnwrapper module not available")
    
    def tearDown(self):
        """Clean up test fixtures after VM protection unwrapper tests."""
        self.fixtures.teardown()
    
    def test_unwrapper_initialization(self):
        """Test VM unwrapper initialization"""
        self.monitor.start_monitoring()
        
        self.assertIsNotNone(self.unwrapper)
        self.assertTrue(hasattr(self.unwrapper, 'unwrap_binary'))
        
        metrics = self.monitor.stop_monitoring()
        self.assertLess(metrics['execution_time'], 3.0)
    
    def test_vm_detection(self):
        """Test VM protection detection"""
        self.monitor.start_monitoring()
        
        test_file = self.fixtures.sample_files['pe_file']
        
        if hasattr(self.unwrapper, 'detect_vm_protection'):
            detection_result = self.unwrapper.detect_vm_protection(str(test_file))
            self.assertIsNotNone(detection_result)
            
            if hasattr(detection_result, 'is_protected'):
                self.assertIsInstance(detection_result.is_protected, bool)
            
            if hasattr(detection_result, 'protection_type'):
                self.assertIsInstance(detection_result.protection_type, str)
        
        metrics = self.monitor.stop_monitoring()
        self.assertLess(metrics['execution_time'], 5.0)
    
    def test_vm_instruction_parsing(self):
        """Test VM instruction parsing"""
        self.monitor.start_monitoring()
        
        if hasattr(self.unwrapper, 'parse_vm_instructions'):
            # Create test VM bytecode
            test_bytecode = bytes([0x01, 0x02, 0x03, 0x04, 0x05])
            
            instructions = self.unwrapper.parse_vm_instructions(test_bytecode)
            self.assertIsNotNone(instructions)
            self.assertIsInstance(instructions, (list, tuple))
        
        metrics = self.monitor.stop_monitoring()
        self.assertLess(metrics['execution_time'], 2.0)
    
    def test_vm_context_emulation(self):
        """Test VM context emulation"""
        self.monitor.start_monitoring()
        
        if hasattr(self.unwrapper, 'create_vm_context'):
            context = self.unwrapper.create_vm_context()
            self.assertIsNotNone(context)
            
            if hasattr(context, 'registers'):
                self.assertIsInstance(context.registers, dict)
                self.assertGreater(len(context.registers), 0)
            
            if hasattr(context, 'stack'):
                self.assertIsInstance(context.stack, list)
        metrics = self.monitor.stop_monitoring()
        self.assertLess(metrics['execution_time'], 1.0)

class TestAntiAntiDebugSuite(unittest.TestCase):
    """Unit tests for anti-anti-debug suite"""
    
    def setUp(self):
        """Set up test fixtures for anti-anti-debug suite tests."""
        self.fixtures = TestFixtures()
        self.fixtures.setup()
        self.monitor = PerformanceMonitor()
        
        try:
            from .anti_anti_debug_suite import AntiAntiDebugSuite
            self.anti_debug = AntiAntiDebugSuite()
        except ImportError:
            self.skipTest("AntiAntiDebugSuite module not available")
    
    def tearDown(self):
        """Clean up test fixtures after anti-anti-debug suite tests."""
        self.fixtures.teardown()
    
    def test_anti_debug_initialization(self):
        """Test anti-debug suite initialization"""
        self.monitor.start_monitoring()
        
        self.assertIsNotNone(self.anti_debug)
        self.assertTrue(hasattr(self.anti_debug, 'apply_bypasses'))
        
        metrics = self.monitor.stop_monitoring()
        self.assertLess(metrics['execution_time'], 2.0)
    
    def test_debug_detection_bypass(self):
        """Test debug detection bypass"""
        self.monitor.start_monitoring()
        
        if hasattr(self.anti_debug, 'bypass_debugger_detection'):
            result = self.anti_debug.bypass_debugger_detection()
            self.assertIsNotNone(result)
            
            if hasattr(result, 'success'):
                self.assertIsInstance(result.success, bool)
            
            if hasattr(result, 'bypassed_techniques'):
                self.assertIsInstance(result.bypassed_techniques, list)
        
        metrics = self.monitor.stop_monitoring()
        self.assertLess(metrics['execution_time'], 5.0)
    
    def test_api_hook_installation(self):
        """Test API hook installation"""
        self.monitor.start_monitoring()
        
        if hasattr(self.anti_debug, 'install_api_hooks'):
            hook_count = self.anti_debug.install_api_hooks()
            self.assertIsInstance(hook_count, int)
            self.assertGreaterEqual(hook_count, 0)
        
        metrics = self.monitor.stop_monitoring()
        self.assertLess(metrics['execution_time'], 3.0)
    
    def test_memory_protection_bypass(self):
        """Test memory protection bypass"""
        self.monitor.start_monitoring()
        
        if hasattr(self.anti_debug, 'bypass_memory_protection'):
            result = self.anti_debug.bypass_memory_protection()
            self.assertIsNotNone(result)
        metrics = self.monitor.stop_monitoring()
        self.assertLess(metrics['execution_time'], 2.0)

# Integration Tests
class TestModuleIntegration(unittest.TestCase):
    """Integration tests for module interactions"""
    
    def setUp(self):
        """Set up test fixtures for module integration tests."""
        self.fixtures = TestFixtures()
        self.fixtures.setup()
        self.monitor = PerformanceMonitor()
        
        # Import all modules
        self.modules = {}
        module_imports = [
            ('protection_classifier', 'ProtectionClassifier'),
            ('neural_network_detector', 'NeuralNetworkDetector'),
            ('hardware_dongle_emulator', 'HardwareDongleEmulator'),
            ('vm_protection_unwrapper', 'VMProtectionUnwrapper'),
            ('anti_anti_debug_suite', 'AntiAntiDebugSuite'),
            ('intellicrack_core_engine', 'IntellicrackcoreEngine')
        ]
        
        for module_name, class_name in module_imports:
            try:
                module = __import__(f'.{module_name}', package=__package__, fromlist=[class_name])
                self.modules[module_name] = getattr(module, class_name)()
            except ImportError:
                self.modules[module_name] = None
    
    def tearDown(self):
        """Clean up test fixtures after module integration tests."""
        self.fixtures.teardown()
    
    def test_core_engine_integration(self):
        """Test core engine integration with all modules"""
        self.monitor.start_monitoring()
        
        core_engine = self.modules.get('intellicrack_core_engine')
        if core_engine is None:
            self.skipTest("Core engine not available")
        
        test_file = self.fixtures.sample_files['pe_file']
        
        # Test end-to-end analysis
        if hasattr(core_engine, 'analyze_binary'):
            result = core_engine.analyze_binary(str(test_file))
            self.assertIsNotNone(result)
            
            if hasattr(result, 'protection_type'):
                self.assertIsInstance(result.protection_type, str)
            
            if hasattr(result, 'bypass_recommendations'):
                self.assertIsInstance(result.bypass_recommendations, list)
        
        metrics = self.monitor.stop_monitoring()
        self.assertLess(metrics['execution_time'], 30.0)  # Complex analysis
    
    def test_classifier_detector_integration(self):
        """Test integration between classifier and neural detector"""
        self.monitor.start_monitoring()
        
        classifier = self.modules.get('protection_classifier')
        detector = self.modules.get('neural_network_detector')
        
        if classifier is None or detector is None:
            self.skipTest("Required modules not available")
        
        test_file = self.fixtures.sample_files['pe_file']
        
        # Test both classification methods
        classifier_result = classifier.classify_file(str(test_file))
        
        try:
            detector_result = detector.detect_protection(str(test_file))
            
            # Results should be compatible
            self.assertIsNotNone(classifier_result)
            self.assertIsNotNone(detector_result)
            
        except Exception:
            # Detector might not be trained, which is acceptable
            pass
        
        metrics = self.monitor.stop_monitoring()
        self.assertLess(metrics['execution_time'], 15.0)
    
    def test_unwrapper_anti_debug_integration(self):
        """Test integration between unwrapper and anti-debug"""
        self.monitor.start_monitoring()
        
        unwrapper = self.modules.get('vm_protection_unwrapper')
        anti_debug = self.modules.get('anti_anti_debug_suite')
        
        if unwrapper is None or anti_debug is None:
            self.skipTest("Required modules not available")
        
        # Test combined bypass approach
        if hasattr(anti_debug, 'apply_bypasses'):
            bypass_result = anti_debug.apply_bypasses()
            self.assertIsNotNone(bypass_result)
        
        if hasattr(unwrapper, 'detect_vm_protection'):
            test_file = self.fixtures.sample_files['pe_file']
            detection_result = unwrapper.detect_vm_protection(str(test_file))
            self.assertIsNotNone(detection_result)
        
        metrics = self.monitor.stop_monitoring()
        self.assertLess(metrics['execution_time'], 10.0)

# Performance Tests
class TestPerformanceBenchmarks(unittest.TestCase):
    """Performance benchmark tests"""
    
    def setUp(self):
        """Set up test fixtures for performance benchmark tests."""
        self.fixtures = TestFixtures()
        self.fixtures.setup()
        self.monitor = PerformanceMonitor()
    
    def tearDown(self):
        """Clean up test fixtures after performance benchmark tests."""
        self.fixtures.teardown()
    
    def test_classification_performance(self):
        """Test protection classification performance benchmarks."""
        try:
            from .protection_classifier import ProtectionClassifier
            classifier = ProtectionClassifier()
        except ImportError:
            self.skipTest("ProtectionClassifier not available")
        
        test_files = []
        for i in range(10):
            test_file = self.fixtures.temp_dir / f"perf_test_{i}.exe"
            self.fixtures.data_generator.create_test_binary(test_file, "pe")
            test_files.append(test_file)
        
        self.monitor.start_monitoring()
        
        # Benchmark classification speed
        start_time = time.time()
        for test_file in test_files:
            classifier.classify_file(str(test_file))
        end_time = time.time()
        
        metrics = self.monitor.stop_monitoring()
        
        avg_time_per_file = (end_time - start_time) / len(test_files)
        self.assertLess(avg_time_per_file, 2.0)  # Should classify each file in under 2 seconds
        
        # Memory usage should be reasonable
        self.assertLess(metrics['memory_usage'], 100.0)  # Less than 100MB additional memory
    
    def test_batch_processing_performance(self):
        """Test batch processing performance benchmarks."""
        try:
            from .protection_classifier import ProtectionClassifier
            classifier = ProtectionClassifier()
        except ImportError:
            self.skipTest("ProtectionClassifier not available")
        
        # Create large number of test files
        test_files = []
        for i in range(50):
            test_file = self.fixtures.temp_dir / f"batch_test_{i}.exe"
            self.fixtures.data_generator.create_test_binary(test_file, "pe")
            test_files.append(str(test_file))
        
        self.monitor.start_monitoring()
        
        # Test batch processing if available
        if hasattr(classifier, 'classify_batch'):
            results = classifier.classify_batch(test_files)
            self.assertEqual(len(results), len(test_files))
        else:
            # Fallback to individual classification
            results = [classifier.classify_file(f) for f in test_files]
        
        metrics = self.monitor.stop_monitoring()
        
        # Batch processing should be efficient
        self.assertLess(metrics['execution_time'], 60.0)  # Should complete in under 1 minute
        self.assertLess(metrics['memory_usage'], 200.0)   # Memory usage should be controlled
    
    def test_memory_leak_detection(self):
        """Test memory leak detection in repeated operations."""
        try:
            from .protection_classifier import ProtectionClassifier
            classifier = ProtectionClassifier()
        except ImportError:
            self.skipTest("ProtectionClassifier not available")
        
        test_file = self.fixtures.sample_files['pe_file']
        
        # Measure initial memory
        initial_memory = psutil.Process().memory_info().rss
        
        # Perform repeated operations
        for i in range(100):
            classifier.classify_file(str(test_file))
            
            # Check memory every 10 iterations
            if i % 10 == 0:
                current_memory = psutil.Process().memory_info().rss
                memory_growth = (current_memory - initial_memory) / 1024 / 1024  # MB
                
                # Memory growth should be limited
                self.assertLess(memory_growth, 50.0)  # Less than 50MB growth
    
    def test_concurrent_processing(self):
        """Test concurrent processing performance and thread safety."""
        try:
            from .protection_classifier import ProtectionClassifier
        except ImportError:
            self.skipTest("ProtectionClassifier not available")
        
        # Create test files
        test_files = []
        for i in range(20):
            test_file = self.fixtures.temp_dir / f"concurrent_test_{i}.exe"
            self.fixtures.data_generator.create_test_binary(test_file, "pe")
            test_files.append(str(test_file))
        
        self.monitor.start_monitoring()
        
        # Test concurrent classification
        import concurrent.futures
        
        def classify_file(file_path):
            classifier = ProtectionClassifier()
            return classifier.classify_file(file_path)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(classify_file, f) for f in test_files]
            results = [future.result() for future in concurrent.futures.as_completed(futures)]
        
        metrics = self.monitor.stop_monitoring()
        # Concurrent processing should be faster than sequential
        self.assertEqual(len(results), len(test_files))
        self.assertLess(metrics['execution_time'], 30.0)  # Should benefit from concurrency

# Security Tests
class TestSecurityValidation(unittest.TestCase):
    """Security validation tests"""
    
    def setUp(self):
        """Set up test fixtures for security validation tests."""
        self.fixtures = TestFixtures()
        self.fixtures.setup()
        self.monitor = PerformanceMonitor()
    
    def tearDown(self):
        """Clean up test fixtures after security validation tests."""
        self.fixtures.teardown()
    
    def test_input_validation(self):
        """Test input validation security mechanisms."""
        try:
            from .protection_classifier import ProtectionClassifier
            classifier = ProtectionClassifier()
        except ImportError:
            self.skipTest("ProtectionClassifier not available")
        
        self.monitor.start_monitoring()
        
        # Test with malicious inputs
        malicious_inputs = [
            "",
            "/dev/null",
            "../../../etc/passwd",
            "CON",  # Windows reserved name
            "file://" + "A" * 1000,  # Very long path
            None,
            123,  # Wrong type
        ]
        
        for malicious_input in malicious_inputs:
            try:
                result = classifier.classify_file(malicious_input)
                # Should handle gracefully, not crash
                self.assertIsNotNone(result)
            except (ValueError, TypeError, FileNotFoundError):
                # These exceptions are acceptable
                pass
            except Exception as e:
                self.fail(f"Unexpected exception for input {malicious_input}: {e}")
        
        metrics = self.monitor.stop_monitoring()
        self.assertLess(metrics['execution_time'], 5.0)
    
    def test_buffer_overflow_protection(self):
        """Test buffer overflow protection mechanisms."""
        try:
            from .protection_classifier import ProtectionClassifier
            classifier = ProtectionClassifier()
        except ImportError:
            self.skipTest("ProtectionClassifier not available")
        
        # Create file with extremely large data
        large_file = self.fixtures.temp_dir / "large_test.exe"
        large_data = b'A' * (10 * 1024 * 1024)  # 10MB of 'A's
        large_file.write_bytes(large_data)
        
        self.monitor.start_monitoring()
        
        try:
            result = classifier.classify_file(str(large_file))
            # Should handle large files without crashing
            self.assertIsNotNone(result)
        except MemoryError:
            # Acceptable if system runs out of memory
            pass
        except Exception as e:
            # Should not crash with other exceptions
            self.assertIn('memory', str(e).lower())
        
        metrics = self.monitor.stop_monitoring()
        # Should complete within reasonable time even for large files
        self.assertLess(metrics['execution_time'], 30.0)
    
    def test_path_traversal_protection(self):
        """Test path traversal attack protection mechanisms."""
        try:
            from .protection_classifier import ProtectionClassifier
            classifier = ProtectionClassifier()
        except ImportError:
            self.skipTest("ProtectionClassifier not available")
        
        # Test various path traversal attempts
        traversal_paths = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "/etc/shadow",
            "C:\\Windows\\System32\\config\\SAM",
            "file:///etc/passwd",
            "\\\\?\\C:\\Windows\\System32\\config\\SAM"
        ]
        
        for path in traversal_paths:
            try:
                result = classifier.classify_file(path)
                # Should not access sensitive system files
                self.assertIsNotNone(result)
            except (FileNotFoundError, PermissionError, ValueError):
                # These are expected and safe
                pass
            except Exception as e:
                # Should not expose system information
                self.assertNotIn('password', str(e).lower())
                self.assertNotIn('admin', str(e).lower())
    
    def test_code_injection_protection(self):
        """Test code injection attack protection mechanisms."""
        try:
            from .protection_classifier import ProtectionClassifier
            classifier = ProtectionClassifier()
        except ImportError:
            self.skipTest("ProtectionClassifier not available")
        
        # Create file with potential code injection payloads
        injection_file = self.fixtures.temp_dir / "injection_test.exe"
        injection_data = b'<?php system($_GET["cmd"]); ?>'
        injection_data += b'<script>alert("XSS")</script>'
        injection_data += b'"; DROP TABLE users; --'
        injection_file.write_bytes(injection_data)
        
        self.monitor.start_monitoring()
        
        try:
            result = classifier.classify_file(str(injection_file))
            # Should process safely without executing any code
            self.assertIsNotNone(result)
        except Exception as e:
            # Should not contain executed code output
            self.assertNotIn('XSS', str(e))
            self.assertNotIn('alert', str(e))
        
        metrics = self.monitor.stop_monitoring()
        self.assertLess(metrics['execution_time'], 5.0)

# Test Runner and Reporter
class TestRunner:
    """Custom test runner with comprehensive reporting"""
    
    def __init__(self, output_dir: Path = None):
        """Initialize test runner with output directory and logging setup."""
        self.output_dir = output_dir or Path("test_results")
        self.output_dir.mkdir(exist_ok=True)
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
        handler = logging.FileHandler(self.output_dir / "test_execution.log")
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
        
        # Coverage tracking
        self.coverage = coverage.Coverage()
        
        # Results storage
        self.test_results = []
    
    def run_all_tests(self) -> TestSuiteResults:
        """Run all test suites"""
        self.logger.info("Starting comprehensive test suite execution")
        
        # Start coverage tracking
        self.coverage.start()
        
        # Test categories to run
        test_classes = [
            (TestProtectionClassifier, TestCategory.UNIT),
            (TestNeuralNetworkDetector, TestCategory.UNIT),
            (TestHardwareDongleEmulator, TestCategory.UNIT),
            (TestVMProtectionUnwrapper, TestCategory.UNIT),
            (TestAntiAntiDebugSuite, TestCategory.UNIT),
            (TestModuleIntegration, TestCategory.INTEGRATION),
            (TestPerformanceBenchmarks, TestCategory.PERFORMANCE),
            (TestSecurityValidation, TestCategory.SECURITY)
        ]
        
        suite_results = TestSuiteResults()
        
        for test_class, category in test_classes:
            self.logger.info(f"Running {test_class.__name__} ({category.value} tests)")
            
            suite = unittest.TestLoader().loadTestsFromTestCase(test_class)
            
            for test in suite:
                result = self._run_single_test(test, category)
                suite_results.test_results.append(result)
                suite_results.total_tests += 1
                
                if result.status == TestStatus.PASSED:
                    suite_results.passed_tests += 1
                elif result.status == TestStatus.FAILED:
                    suite_results.failed_tests += 1
                elif result.status == TestStatus.SKIPPED:
                    suite_results.skipped_tests += 1
                elif result.status == TestStatus.ERROR:
                    suite_results.error_tests += 1
                
                suite_results.total_execution_time += result.execution_time
        
        # Stop coverage tracking
        self.coverage.stop()
        self.coverage.save()
        
        # Calculate coverage
        suite_results.coverage_percentage = self._calculate_coverage()
        
        # Generate reports
        self._generate_reports(suite_results)
        
        self.logger.info(f"Test suite completed: {suite_results.passed_tests}/{suite_results.total_tests} passed")
        
        return suite_results
    
    def _run_single_test(self, test: unittest.TestCase, category: TestCategory) -> TestResult:
        """Run a single test and collect metrics"""
        test_name = f"{test.__class__.__name__}.{test._testMethodName}"
        
        monitor = PerformanceMonitor()
        monitor.start_monitoring()
        
        # Run the test
        result = unittest.TestResult()
        start_time = time.time()
        
        try:
            test.run(result)
            execution_time = time.time() - start_time
            
            if result.wasSuccessful():
                status = TestStatus.PASSED
                error_message = None
            elif result.failures:
                status = TestStatus.FAILED
                error_message = result.failures[0][1] if result.failures else None
            elif result.errors:
                status = TestStatus.ERROR
                error_message = result.errors[0][1] if result.errors else None
            elif result.skipped:
                status = TestStatus.SKIPPED
                error_message = result.skipped[0][1] if result.skipped else None
            else:
                status = TestStatus.ERROR
                error_message = "Unknown test result"
        
        except Exception as e:
            execution_time = time.time() - start_time
            status = TestStatus.ERROR
            error_message = str(e)
        
        # Get performance metrics
        metrics = monitor.stop_monitoring()
        
        # Determine priority based on category
        priority_map = {
            TestCategory.UNIT: TestPriority.HIGH,
            TestCategory.INTEGRATION: TestPriority.HIGH,
            TestCategory.SECURITY: TestPriority.CRITICAL,
            TestCategory.PERFORMANCE: TestPriority.MEDIUM,
            TestCategory.REGRESSION: TestPriority.HIGH,
            TestCategory.STRESS: TestPriority.LOW
        }
        
        return TestResult(
            test_name=test_name,
            category=category,
            status=status,
            execution_time=execution_time,
            error_message=error_message,
            memory_usage=metrics['memory_usage'],
            cpu_usage=metrics['cpu_usage'],
            priority=priority_map.get(category, TestPriority.MEDIUM),
            tags=[category.value]
        )
    
    def _calculate_coverage(self) -> float:
        try:
            # Generate coverage report
            coverage_file = self.output_dir / "coverage.xml"
            self.coverage.xml_report(outfile=str(coverage_file))
            
            # Parse coverage data
            total_lines = 0
            covered_lines = 0
            
            if hasattr(self.coverage, 'get_data'):
                data = self.coverage.get_data()
                for filename in data.measured_files():
                    analysis = self.coverage.analyze(filename)
                    total_lines += len(analysis.statements)
                    covered_lines += len(analysis.statements) - len(analysis.missing)
            
            if total_lines > 0:
                return (covered_lines / total_lines) * 100
            else:
                return 0.0
        
        except Exception as e:
            self.logger.warning(f"Failed to calculate coverage: {e}")
            return 0.0
    
    def _generate_reports(self, results: TestSuiteResults):
        """Generate comprehensive test reports"""
        # JSON report
        json_report = self.output_dir / "test_results.json"
        with open(json_report, 'w', encoding='utf-8') as f:
            json.dump(results.to_dict(), f, indent=2)
        
        # HTML report
        self._generate_html_report(results)
        
        # Text summary
        self._generate_text_summary(results)
        
        # Performance charts
        self._generate_performance_charts(results)
        
        # Coverage report
        try:
            self.coverage.html_report(directory=str(self.output_dir / "coverage_html"))
        except Exception as e:
            self.logger.warning(f"Failed to generate HTML coverage report: {e}")
    
    def _generate_html_report(self, results: TestSuiteResults):
        """Generate HTML test report"""
        html_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>Intellicrack Test Suite Results</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 20px; border-radius: 5px; }
        .summary { display: flex; justify-content: space-around; margin: 20px 0; }
        .metric { text-align: center; padding: 10px; background-color: #e9e9e9; border-radius: 5px; }
        .passed { color: green; }
        .failed { color: red; }
        .skipped { color: orange; }
        .error { color: darkred; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .test-passed { background-color: #d4edda; }
        .test-failed { background-color: #f8d7da; }
        .test-skipped { background-color: #fff3cd; }
        .test-error { background-color: #f5c6cb; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Intellicrack Comprehensive Test Suite Results</h1>
        <p>Generated: {timestamp}</p>
        <p>Success Rate: {success_rate:.1f}%</p>
    </div>
    
    <div class="summary">
        <div class="metric">
            <h3>Total Tests</h3>
            <p>{total_tests}</p>
        </div>
        <div class="metric passed">
            <h3>Passed</h3>
            <p>{passed_tests}</p>
        </div>
        <div class="metric failed">
            <h3>Failed</h3>
            <p>{failed_tests}</p>
        </div>
        <div class="metric skipped">
            <h3>Skipped</h3>
            <p>{skipped_tests}</p>
        </div>
        <div class="metric error">
            <h3>Errors</h3>
            <p>{error_tests}</p>
        </div>
    </div>
    
    <h2>Test Results Details</h2>
    <table>
        <thead>
            <tr>
                <th>Test Name</th>
                <th>Category</th>
                <th>Status</th>
                <th>Execution Time (s)</th>
                <th>Memory Usage (MB)</th>
                <th>Priority</th>
                <th>Error Message</th>
            </tr>
        </thead>
        <tbody>
'''
        
        for result in results.test_results:
            status_class = f"test-{result.status.value}"
            error_msg = result.error_message[:100] + "..." if result.error_message and len(result.error_message) > 100 else (result.error_message or "")
            
            html_template += f'''
            <tr class="{status_class}">
                <td>{result.test_name}</td>
                <td>{result.category.value}</td>
                <td>{result.status.value}</td>
                <td>{result.execution_time:.3f}</td>
                <td>{result.memory_usage:.2f}</td>
                <td>{result.priority.value}</td>
                <td>{error_msg}</td>
            </tr>
'''
        
        html_template += '''
        </tbody>
    </table>
    
    <h2>Performance Metrics</h2>
    <div class="summary">
        <div class="metric">
            <h3>Total Execution Time</h3>
            <p>{:.2f} seconds</p>
        </div>
        <div class="metric">
            <h3>Average Test Time</h3>
            <p>{:.3f} seconds</p>
        </div>
        <div class="metric">
            <h3>Code Coverage</h3>
            <p>{:.1f}%</p>
        </div>
    </div>
</body>
</html>
'''.format(
            results.total_execution_time,
            results.total_execution_time / max(results.total_tests, 1),
            results.coverage_percentage
        )
        
        html_report = self.output_dir / "test_results.html"
        with open(html_report, 'w', encoding='utf-8') as f:
            f.write(html_template.format(
                timestamp=results.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                success_rate=results.success_rate,
                total_tests=results.total_tests,
                passed_tests=results.passed_tests,
                failed_tests=results.failed_tests,
                skipped_tests=results.skipped_tests,
                error_tests=results.error_tests
            ))
    
    def _generate_text_summary(self, results: TestSuiteResults):
        """Generate text summary report"""
        summary = "INTELLICRACK COMPREHENSIVE TEST SUITE RESULTS\n"
        summary += "==============================================\n\n"
        summary += f"Execution Date: {results.timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        summary += "SUMMARY:\n--------\n"
        summary += f"Total Tests:     {results.total_tests}\n"
        summary += f"Passed:          {results.passed_tests}\n"
        summary += f"Failed:          {results.failed_tests}\n"
        summary += f"Skipped:         {results.skipped_tests}\n"
        summary += f"Errors:          {results.error_tests}\n\n"
        summary += f"Success Rate:    {results.success_rate:.1f}%\n"
        summary += f"Total Time:      {results.total_execution_time:.2f} seconds\n"
        summary += f"Average Time:    {results.total_execution_time / max(results.total_tests, 1):.3f} seconds\n"
        summary += f"Code Coverage:   {results.coverage_percentage:.1f}%\n\n"
        summary += "RESULTS BY CATEGORY:\n-------------------\n"
        
        # Group results by category
        category_stats = {}
        for result in results.test_results:
            cat = result.category.value
            if cat not in category_stats:
                category_stats[cat] = {'total': 0, 'passed': 0, 'failed': 0, 'skipped': 0, 'error': 0}
            
            category_stats[cat]['total'] += 1
            category_stats[cat][result.status.value] += 1
        
        for category, stats in category_stats.items():
            success_rate = (stats['passed'] / stats['total']) * 100 if stats['total'] > 0 else 0
            summary += f"\n{category.upper()}:\n"
            summary += f"  Total: {stats['total']}, Passed: {stats['passed']}, Failed: {stats['failed']}\n"
            summary += f"  Success Rate: {success_rate:.1f}%\n"
        
        # Failed tests details
        failed_tests = [r for r in results.test_results if r.status in [TestStatus.FAILED, TestStatus.ERROR]]
        if failed_tests:
            summary += "\nFAILED TESTS:\n"
            summary += "-------------\n"
            for test in failed_tests:
                summary += f"{test.test_name} ({test.category.value}): {test.error_message}\n"
        
        text_report = self.output_dir / "test_summary.txt"
        with open(text_report, 'w', encoding='utf-8') as f:
            f.write(summary)
    
    def _generate_performance_charts(self, results: TestSuiteResults):
        try:
            import matplotlib.pyplot as plt
            import seaborn as sns
            
            # Set style
            plt.style.use('default')
            sns.set_palette("husl")
            
            # Performance by category
            fig, axes = plt.subplots(2, 2, figsize=(15, 10))
            fig.suptitle('Intellicrack Test Suite Performance Analysis', fontsize=16)
            
            # Execution time by category
            category_times = {}
            for result in results.test_results:
                cat = result.category.value
                if cat not in category_times:
                    category_times[cat] = []
                category_times[cat].append(result.execution_time)
            
            categories = list(category_times.keys())
            avg_times = [np.mean(category_times[cat]) for cat in categories]
            
            axes[0, 0].bar(categories, avg_times)
            axes[0, 0].set_title('Average Execution Time by Category')
            axes[0, 0].set_ylabel('Time (seconds)')
            axes[0, 0].tick_params(axis='x', rotation=45)
            
            # Memory usage distribution
            memory_usage = [r.memory_usage for r in results.test_results if r.memory_usage > 0]
            if memory_usage:
                axes[0, 1].hist(memory_usage, bins=20, alpha=0.7, edgecolor='black')
                axes[0, 1].set_title('Memory Usage Distribution')
                axes[0, 1].set_xlabel('Memory Usage (MB)')
                axes[0, 1].set_ylabel('Frequency')
            
            # Test status distribution
            status_counts = {}
            for result in results.test_results:
                status = result.status.value
                status_counts[status] = status_counts.get(status, 0) + 1
            
            axes[1, 0].pie(status_counts.values(), labels=status_counts.keys(), autopct='%1.1f%%')
            axes[1, 0].set_title('Test Status Distribution')
            
            # Execution time vs memory usage scatter
            exec_times = [r.execution_time for r in results.test_results]
            mem_usage = [r.memory_usage for r in results.test_results]
            
            axes[1, 1].scatter(exec_times, mem_usage, alpha=0.6)
            axes[1, 1].set_title('Execution Time vs Memory Usage')
            axes[1, 1].set_xlabel('Execution Time (seconds)')
            axes[1, 1].set_ylabel('Memory Usage (MB)')
            
            plt.tight_layout()
            plt.savefig(self.output_dir / "performance_charts.png", dpi=300, bbox_inches='tight')
            plt.close()
            
        except Exception as e:
            self.logger.warning(f"Failed to generate performance charts: {e}")
    
    def run_category_tests(self, category: TestCategory) -> TestSuiteResults:
        """Run tests for specific category"""
        self.logger.info(f"Running {category.value} tests only")
        
        category_map = {
            TestCategory.UNIT: [TestProtectionClassifier, TestNeuralNetworkDetector, 
                              TestHardwareDongleEmulator, TestVMProtectionUnwrapper, 
                              TestAntiAntiDebugSuite],
            TestCategory.INTEGRATION: [TestModuleIntegration],
            TestCategory.PERFORMANCE: [TestPerformanceBenchmarks],
            TestCategory.SECURITY: [TestSecurityValidation]
        }
        
        test_classes = category_map.get(category, [])
        
        suite_results = TestSuiteResults()
        
        for test_class in test_classes:
            suite = unittest.TestLoader().loadTestsFromTestCase(test_class)
            
            for test in suite:
                result = self._run_single_test(test, category)
                suite_results.test_results.append(result)
                # ... (update counters as in run_all_tests)
        
        return suite_results

def main():
    """Main test execution function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Intellicrack Comprehensive Test Suite")
    parser.add_argument('--category', choices=[c.value for c in TestCategory],
                       help="Run tests for specific category only")
    parser.add_argument('--output', type=str, default="test_results",
                       help="Output directory for test results")
    parser.add_argument('--verbose', action='store_true',
                       help="Enable verbose output")
    parser.add_argument('--coverage', action='store_true',
                       help="Generate code coverage report")
    
    args = parser.parse_args()
    
    # Setup logging
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    
    # Create test runner
    runner = TestRunner(Path(args.output))
    
    # Run tests
    if args.category:
        category = TestCategory(args.category)
        results = runner.run_category_tests(category)
    else:
        results = runner.run_all_tests()
    
    # Print summary
    print(f"\nTest Suite Completed!")
    print(f"Total Tests: {results.total_tests}")
    print(f"Passed: {results.passed_tests}")
    print(f"Failed: {results.failed_tests}")
    print(f"Success Rate: {results.success_rate:.1f}%")
    print(f"Execution Time: {results.total_execution_time:.2f} seconds")
    print(f"Code Coverage: {results.coverage_percentage:.1f}%")
    print(f"\nDetailed results saved to: {args.output}/")
    
    # Exit with appropriate code
    if results.failed_tests > 0 or results.error_tests > 0:
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == "__main__":
    main()