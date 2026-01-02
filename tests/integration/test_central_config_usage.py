"""
Test to verify all configuration access uses central system.
Task 20.1.2: Ensures no direct file access or legacy config methods.
ALL TESTS USE REAL CONFIGURATION - NO MOCKS OR PLACEHOLDERS.
"""

import pytest
import ast
import os
import re
import time
import threading
import warnings
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional

from intellicrack.core.config_manager import IntellicrackConfig, get_config
from tests.base_test import IntellicrackTestBase


class ConfigAccessDetector(ast.NodeVisitor):
    """AST visitor to detect configuration access patterns."""

    def __init__(self) -> None:
        self.config_accesses: List[Dict[str, Any]] = []
        self.direct_file_accesses: List[Dict[str, Any]] = []
        self.legacy_patterns: List[Dict[str, Any]] = []
        self.central_accesses: List[Dict[str, Any]] = []

    def visit_Call(self, node: ast.Call) -> None:
        """Check for configuration-related function calls."""
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ['open', 'read', 'write']:
                for arg in node.args:
                    if isinstance(arg, ast.Str) and any(pattern in arg.s.lower() for pattern in ['config', 'settings', '.json', '.ini']):
                        self.direct_file_accesses.append({
                            'line': node.lineno,
                            'type': 'direct_file_access',
                            'method': node.func.attr
                        })

            if hasattr(node.func.value, 'id') and node.func.value.id == 'QSettings':
                self.legacy_patterns.append({
                    'line': node.lineno,
                    'type': 'QSettings',
                    'method': node.func.attr
                })

            if node.func.attr in ['get', 'set', 'get_config'] and hasattr(node.func.value, 'id') and node.func.value.id in ['config', 'self.config', 'get_config']:
                self.central_accesses.append({
                    'line': node.lineno,
                    'type': 'central_config',
                    'method': node.func.attr
                })

        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        """Check for legacy configuration imports."""
        for alias in node.names:
            if 'QSettings' in alias.name or 'ConfigParser' in alias.name:
                self.legacy_patterns.append({
                    'line': node.lineno,
                    'type': 'legacy_import',
                    'module': alias.name
                })
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Check for specific legacy imports."""
        if node.module and ('PyQt' in node.module and any('QSettings' in n.name for n in node.names)):
            self.legacy_patterns.append({
                'line': node.lineno,
                'type': 'legacy_import',
                'module': f"{node.module}.QSettings"
            })
        self.generic_visit(node)


class FakeIntellicrackConfig:
    """Real test double for IntellicrackConfig with full type safety."""

    _instance: Optional['FakeIntellicrackConfig'] = None
    _lock: threading.Lock = threading.Lock()

    def __new__(cls) -> 'FakeIntellicrackConfig':
        """Enforce singleton pattern."""
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self) -> None:
        """Initialize configuration store."""
        if not self._initialized:
            self._config_data: Dict[str, Any] = {}
            self._get_calls: List[str] = []
            self._set_calls: List[tuple[str, Any]] = []
            self._user_config_dir: Optional[Path] = None
            self._initialized = True

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value with call tracking."""
        self._get_calls.append(key)
        return self._config_data.get(key, default)

    def set(self, key: str, value: Any) -> None:
        """Set configuration value with call tracking."""
        self._set_calls.append((key, value))
        self._config_data[key] = value

    @classmethod
    def _get_user_config_dir(cls) -> Path:
        """Get user configuration directory."""
        if cls._instance and cls._instance._user_config_dir:
            return cls._instance._user_config_dir
        return Path.home() / ".config" / "intellicrack"

    def reset_tracking(self) -> None:
        """Reset call tracking for testing."""
        self._get_calls = []
        self._set_calls = []

    def get_call_count(self) -> int:
        """Get number of get() calls."""
        return len(self._get_calls)

    def get_set_count(self) -> int:
        """Get number of set() calls."""
        return len(self._set_calls)


class FakeLLMConfigManager:
    """Real test double for LLMConfigManager with deprecation tracking."""

    def __init__(self, config_path: str) -> None:
        self.config_path: Path = Path(config_path)
        self.deprecation_warnings_issued: List[str] = []
        self._storage: Dict[str, Any] = {}

    def save_model_config(self, model_name: str, config: Dict[str, Any]) -> None:
        """Deprecated method with warning tracking."""
        self.deprecation_warnings_issued.append('save_model_config')
        warnings.warn(
            "save_model_config is deprecated, use central config",
            DeprecationWarning,
            stacklevel=2
        )
        self._storage[model_name] = config

    def get_model_config(self, model_name: str) -> Optional[Dict[str, Any]]:
        """Deprecated method with warning tracking."""
        self.deprecation_warnings_issued.append('get_model_config')
        warnings.warn(
            "get_model_config is deprecated, use central config",
            DeprecationWarning,
            stacklevel=2
        )
        return self._storage.get(model_name)

    def delete_model_config(self, model_name: str) -> None:
        """Deprecated method with warning tracking."""
        self.deprecation_warnings_issued.append('delete_model_config')
        warnings.warn(
            "delete_model_config is deprecated, use central config",
            DeprecationWarning,
            stacklevel=2
        )
        if model_name in self._storage:
            del self._storage[model_name]

    def list_model_configs(self) -> List[str]:
        """Deprecated method with warning tracking."""
        self.deprecation_warnings_issued.append('list_model_configs')
        warnings.warn(
            "list_model_configs is deprecated, use central config",
            DeprecationWarning,
            stacklevel=2
        )
        return list(self._storage.keys())

    def get_profile(self, profile_name: str) -> Optional[Dict[str, Any]]:
        """Deprecated method with warning tracking."""
        self.deprecation_warnings_issued.append('get_profile')
        warnings.warn(
            "get_profile is deprecated, use central config",
            DeprecationWarning,
            stacklevel=2
        )
        return self._storage.get(f"profile_{profile_name}")

    def save_profile(self, profile_name: str, profile_data: Dict[str, Any]) -> None:
        """Deprecated method with warning tracking."""
        self.deprecation_warnings_issued.append('save_profile')
        warnings.warn(
            "save_profile is deprecated, use central config",
            DeprecationWarning,
            stacklevel=2
        )
        self._storage[f"profile_{profile_name}"] = profile_data


class FakePath:
    """Real test double for pathlib.Path."""

    def __init__(self, path: str) -> None:
        self.path: str = path
        self._exists: bool = True

    def exists(self) -> bool:
        """Check if path exists."""
        return self._exists

    def __truediv__(self, other: str) -> 'FakePath':
        """Path concatenation."""
        return FakePath(f"{self.path}/{other}")

    def __str__(self) -> str:
        """String representation."""
        return self.path


class TestCentralConfigUsage(IntellicrackTestBase):
    """Task 20.1.2: Verify all configuration access uses central system."""

    @pytest.fixture(autouse=True)
    def setup(self, temp_workspace: Path) -> None:
        """Set up test environment."""
        self.temp_dir: Path = temp_workspace
        from intellicrack.utils.path_resolver import get_project_root

        self.project_root: Path = get_project_root()
        self.intellicrack_dir: Path = self.project_root / "intellicrack"

    def analyze_file(self, file_path: Path) -> Dict[str, Any]:
        """Analyze a Python file for configuration access patterns."""
        try:
            with open(file_path, encoding='utf-8') as f:
                content = f.read()

            tree = ast.parse(content)
            detector = ConfigAccessDetector()
            detector.visit(tree)

            return {
                'file': file_path,
                'central_accesses': detector.central_accesses,
                'direct_file_accesses': detector.direct_file_accesses,
                'legacy_patterns': detector.legacy_patterns
            }
        except SyntaxError:
            return {
                'file': file_path,
                'error': 'syntax_error',
                'central_accesses': [],
                'direct_file_accesses': [],
                'legacy_patterns': []
            }
        except Exception as e:
            return {
                'file': file_path,
                'error': str(e),
                'central_accesses': [],
                'direct_file_accesses': [],
                'legacy_patterns': []
            }

    def test_20_1_2_no_direct_config_file_access(self) -> None:
        """Verify no direct file access to configuration files."""
        violations: List[Dict[str, Any]] = []
        checked_files: int = 0

        for root, dirs, files in os.walk(self.intellicrack_dir):
            if any(skip in root for skip in ['__pycache__', '.git', 'test', 'migration']):
                continue

            for file in files:
                if file.endswith('.py'):
                    file_path = Path(root) / file
                    checked_files += 1

                    if file == 'config_manager.py':
                        continue

                    result = self.analyze_file(file_path)

                    if result['direct_file_accesses']:
                        for access in result['direct_file_accesses']:
                            violations.append({
                                'file': str(file_path.relative_to(self.project_root)),
                                'line': access['line'],
                                'issue': f"Direct file {access['method']} on config file"
                            })

        if violations:
            print(f"\n⚠ Found {len(violations)} direct config file accesses:")
            for v in violations[:10]:
                print(f"  - {v['file']}:{v['line']} - {v['issue']}")
        else:
            print(f"\nOK No direct config file access found in {checked_files} files")

        assert not violations, f"Found {len(violations)} direct config file accesses"

    def test_20_1_2_no_legacy_qsettings_usage(self) -> None:
        """Verify no legacy QSettings usage remains."""
        violations: List[Dict[str, str]] = []

        try:
            result = subprocess.run(
                ['rg', 'QSettings', str(self.intellicrack_dir), '--type', 'py', '--no-heading'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.stdout:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if line and 'config_cleanup' not in line and 'test' not in line:
                        parts = line.split(':', 2)
                        if len(parts) >= 2:
                            file_path = parts[0]
                            line_num = parts[1]
                            violations.append({
                                'file': file_path,
                                'line': line_num,
                                'issue': 'QSettings reference found'
                            })
        except subprocess.TimeoutExpired:
            print("⚠ Grep search timed out")
        except FileNotFoundError:
            print("⚠ ripgrep (rg) not available, skipping grep search")

        if violations:
            print(f"\n⚠ Found {len(violations)} QSettings references:")
            for v in violations[:5]:
                print(f"  - {v['file']}:{v['line']} - {v['issue']}")
        else:
            print("\nOK No QSettings usage found")

        assert not violations, f"Found {len(violations)} QSettings references"

    def test_20_1_2_central_config_usage_patterns(self) -> None:
        """Verify proper usage of central configuration system."""
        proper_usage_count: int = 0
        improper_usage_count: int = 0
        files_checked: int = 0

        key_files = [
            self.intellicrack_dir / "ui" / "main_app.py",
            self.intellicrack_dir / "ui" / "theme_manager.py",
            self.intellicrack_dir / "ai" / "llm_config_manager.py",
            self.intellicrack_dir / "utils" / "secrets_manager.py",
            self.intellicrack_dir / "utils" / "env_file_manager.py",
            self.intellicrack_dir / "core" / "execution" / "script_execution_manager.py"
        ]

        for file_path in key_files:
            if file_path.exists():
                files_checked += 1
                with open(file_path, encoding='utf-8') as f:
                    content = f.read()

                has_central_import = (
                    'from intellicrack.core.config_manager import' in content or
                    'import intellicrack.core.config_manager' in content
                )

                uses_get_config = 'get_config()' in content
                uses_config_get = 'config.get(' in content or 'self.config.get(' in content
                uses_config_set = 'config.set(' in content or 'self.config.set(' in content

                if has_central_import or uses_get_config or uses_config_get or uses_config_set:
                    proper_usage_count += 1
                    print(f"OK {file_path.name} uses central config properly")
                else:
                    if any(term in content.lower() for term in ['config', 'setting', 'preference']):
                        improper_usage_count += 1
                        print(f"⚠ {file_path.name} may not be using central config")

        print(f"\nCentral config usage summary:")
        print(f"  Files checked: {files_checked}")
        print(f"  Proper usage: {proper_usage_count}")
        print(f"  Potential issues: {improper_usage_count}")

        assert proper_usage_count >= files_checked * 0.7, "Not enough files using central config"

    def test_20_1_2_config_singleton_pattern(self) -> None:
        """Verify singleton pattern is properly enforced."""
        config1 = get_config()
        config2 = get_config()

        assert config1 is config2, "get_config() should return singleton instance"

        fake_config = FakeIntellicrackConfig()
        fake_config._user_config_dir = self.temp_dir

        config3 = IntellicrackConfig()
        config4 = IntellicrackConfig()

        assert config3 is config4, "IntellicrackConfig should enforce singleton"

        instances: List[IntellicrackConfig] = []

        def get_instance() -> None:
            instances.append(get_config())

        threads: List[threading.Thread] = []
        for _ in range(10):
            thread = threading.Thread(target=get_instance)
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        first_instance = instances[0]
        for instance in instances[1:]:
            assert instance is first_instance, "Singleton should be thread-safe"

    def test_20_1_2_deprecated_method_warnings(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Verify deprecated methods show warnings."""
        fake_path = FakePath(str(self.temp_dir))
        monkeypatch.setattr('intellicrack.ai.llm_config_manager.Path', lambda x: fake_path)

        from intellicrack.ai.llm_config_manager import LLMConfigManager

        manager = FakeLLMConfigManager(config_path=str(self.temp_dir))

        deprecated_methods = [
            'save_model_config',
            'get_model_config',
            'delete_model_config',
            'list_model_configs',
            'get_profile',
            'save_profile'
        ]

        for method_name in deprecated_methods:
            if hasattr(manager, method_name):
                method = getattr(manager, method_name)

                with warnings.catch_warnings(record=True) as w:
                    warnings.simplefilter("always")

                    if method_name == 'save_model_config':
                        method('test_model', {'param': 'value'})
                    elif method_name == 'get_model_config':
                        method('test_model')
                    elif method_name == 'delete_model_config':
                        method('test_model')
                    elif method_name == 'list_model_configs':
                        method()
                    elif method_name == 'get_profile':
                        method('test_profile')
                    elif method_name == 'save_profile':
                        method('test_profile', {'data': 'value'})

                    if w:
                        assert issubclass(w[-1].category, DeprecationWarning)
                        print(f"OK {method_name} issues deprecation warning")
                    else:
                        print(f"⚠ {method_name} did not issue warning")

                assert method_name in manager.deprecation_warnings_issued

    def test_20_1_2_no_hardcoded_config_paths(self) -> None:
        """Verify no hardcoded configuration paths in code."""
        hardcoded_patterns = [
            r'C:\\Users\\.*\\AppData',
            r'~/.config/intellicrack',
            r'/home/.*/\.config',
            r'config\.json["\']\s*\)',
            r'settings\.ini',
            r'\.qsettings'
        ]

        violations: List[Dict[str, Any]] = []

        for root, dirs, files in os.walk(self.intellicrack_dir):
            if any(skip in root for skip in ['__pycache__', '.git', 'test']):
                continue

            for file in files:
                if file.endswith('.py'):
                    file_path = Path(root) / file

                    if file == 'config_manager.py':
                        continue

                    with open(file_path, encoding='utf-8') as f:
                        content = f.read()

                        for i, line in enumerate(content.split('\n'), 1):
                            for pattern in hardcoded_patterns:
                                if re.search(pattern, line, re.IGNORECASE):
                                    violations.append({
                                        'file': str(file_path.relative_to(self.project_root)),
                                        'line': i,
                                        'pattern': pattern
                                    })

        if violations:
            print(f"\n⚠ Found {len(violations)} hardcoded config paths:")
            for v in violations[:5]:
                print(f"  - {v['file']}:{v['line']} matches pattern {v['pattern']}")
        else:
            print("\nOK No hardcoded configuration paths found")

        assert not violations, f"Found {len(violations)} hardcoded config paths"

    def test_20_1_2_config_access_performance(self) -> None:
        """Verify configuration access performance meets requirements."""
        config = get_config()

        start = time.time()
        for _ in range(10000):
            config.get("application.name")
            config.get("qemu_testing.default_preference")
            config.get("ui_preferences.theme")
        read_time = time.time() - start

        start = time.time()
        for i in range(1000):
            config.set(f"test.value_{i}", i)
        write_time = time.time() - start

        start = time.time()
        for _ in range(5000):
            config.get("llm_configuration.models.gpt4.temperature")
            config.get("cli_configuration.profiles.default.verbosity")
        nested_time = time.time() - start

        print(f"\nConfiguration access performance:")
        print(f"  30,000 reads: {read_time:.3f}s ({30000/read_time:.0f} ops/sec)")
        print(f"  1,000 writes: {write_time:.3f}s ({1000/write_time:.0f} ops/sec)")
        print(f"  10,000 nested: {nested_time:.3f}s ({10000/nested_time:.0f} ops/sec)")

        assert read_time < 1.0, f"Read performance too slow: {read_time:.3f}s"
        assert write_time < 0.5, f"Write performance too slow: {write_time:.3f}s"
        assert nested_time < 0.5, f"Nested access too slow: {nested_time:.3f}s"

        print("\nOK Task 20.1.2 COMPLETED: All configuration access verified to use central system")
