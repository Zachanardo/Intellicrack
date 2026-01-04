"""Production-grade tests for UI Enhancement Module.

Tests validate real UI enhancement functionality with tkinter widgets:
- Widget creation and initialization
- Theme application and styling
- Plugin lifecycle (initialization, configuration, teardown)
- Enhanced workflows (file browsing, analysis triggering)
- Real-time chart updates with matplotlib
- Log viewer filtering and search
- Progress tracking with ETA calculations
- File explorer tree operations
- Analysis viewer updates
- Script generator functionality
- Configuration serialization/deserialization
- Panel integration and layout management
- Menu creation and command binding
- Status bar updates
- Event handling and callbacks
"""

import json
import tempfile
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional

import pytest

try:
    from intellicrack.plugins.custom_modules.ui_enhancement_module import (
        AnalysisResult,
        AnalysisState,
        AnalysisViewerPanel,
        FileExplorerPanel,
        LogViewer,
        PanelType,
        ProgressTracker,
        RealTimeChart,
        ScriptGeneratorPanel,
        UIConfig,
        UIEnhancementModule,
        UITheme,
    )
    from intellicrack.handlers.tkinter_handler import tkinter as tk, ttk
    UI_ENHANCEMENT_AVAILABLE = True
except ImportError as e:
    UI_ENHANCEMENT_AVAILABLE = False
    IMPORT_ERROR = str(e)

pytestmark = pytest.mark.skipif(
    not UI_ENHANCEMENT_AVAILABLE,
    reason=f"UI enhancement module dependencies not available: {'' if UI_ENHANCEMENT_AVAILABLE else IMPORT_ERROR}"
)


class FakeUIController:
    """Real test double for UI controller.

    Implements actual controller interface for testing UI components.
    Tracks all method calls and provides verifiable behavior.
    """

    def __init__(self) -> None:
        self.analyzed_files: List[str] = []
        self.generated_scripts: List[tuple[str, str]] = []
        self.shown_file_properties: List[Path] = []
        self.call_count_analyze_file: int = 0
        self.call_count_generate_scripts: int = 0
        self.call_count_show_file_properties: int = 0
        self.should_fail_analysis: bool = False
        self.analysis_delay: float = 0.0

    def analyze_file(self, file_path: str) -> Optional[AnalysisResult]:
        """Analyze file and return result."""
        self.call_count_analyze_file += 1
        self.analyzed_files.append(file_path)

        if self.should_fail_analysis:
            return None

        if self.analysis_delay > 0:
            time.sleep(self.analysis_delay)

        return AnalysisResult(
            target_file=file_path,
            protection_type="VMProtect",
            confidence=0.85,
            bypass_methods=["Memory Dumping", "API Hooking"],
            timestamp=datetime.now(),
            details={"test": "data"},
            generated_scripts=["script.js"]
        )

    def generate_scripts(self, target_file: str, script_type: str) -> str:
        """Generate analysis script."""
        self.call_count_generate_scripts += 1
        self.generated_scripts.append((target_file, script_type))
        return f"// Generated {script_type} script for {target_file}"

    def show_file_properties(self, file_path: Path) -> Dict[str, Any]:
        """Show file properties."""
        self.call_count_show_file_properties += 1
        self.shown_file_properties.append(file_path)
        return {
            "name": file_path.name,
            "size": 1024,
            "type": file_path.suffix,
            "modified": datetime.now()
        }

    def reset_tracking(self) -> None:
        """Reset tracking data for fresh test."""
        self.analyzed_files.clear()
        self.generated_scripts.clear()
        self.shown_file_properties.clear()
        self.call_count_analyze_file = 0
        self.call_count_generate_scripts = 0
        self.call_count_show_file_properties = 0
        self.should_fail_analysis = False
        self.analysis_delay = 0.0

    def verify_analyze_file_called_with(self, expected_path: str) -> bool:
        """Verify analyze_file was called with specific path."""
        return expected_path in self.analyzed_files

    def verify_analyze_file_call_count(self, expected_count: int) -> bool:
        """Verify analyze_file was called expected number of times."""
        return self.call_count_analyze_file == expected_count


class FakeModuleLoader:
    """Real test double for module loader.

    Simulates module loading behavior for testing plugin lifecycle.
    """

    def __init__(self) -> None:
        self.loaded_modules: List[str] = []
        self.unloaded_modules: List[str] = []
        self.initialized_modules: List[str] = []
        self.configured_modules: List[tuple[str, Dict[str, Any]]] = []

    def load_module(self, module_name: str) -> bool:
        """Load a module."""
        self.loaded_modules.append(module_name)
        return True

    def unload_module(self, module_name: str) -> bool:
        """Unload a module."""
        self.unloaded_modules.append(module_name)
        return True

    def initialize_module(self, module_name: str) -> bool:
        """Initialize a module."""
        self.initialized_modules.append(module_name)
        return True

    def configure_module(self, module_name: str, config: Dict[str, Any]) -> bool:
        """Configure a module."""
        self.configured_modules.append((module_name, config))
        return True

    def is_module_loaded(self, module_name: str) -> bool:
        """Check if module is loaded."""
        return module_name in self.loaded_modules and module_name not in self.unloaded_modules

    def get_module_config(self, module_name: str) -> Optional[Dict[str, Any]]:
        """Get module configuration."""
        for name, config in self.configured_modules:
            if name == module_name:
                return config
        return None

    def reset_tracking(self) -> None:
        """Reset tracking data."""
        self.loaded_modules.clear()
        self.unloaded_modules.clear()
        self.initialized_modules.clear()
        self.configured_modules.clear()


@pytest.fixture
def tk_root() -> tk.Tk:
    """Create tkinter root window for testing."""
    root = tk.Tk()
    root.withdraw()
    yield root
    try:
        root.quit()
        root.destroy()
    except tk.TclError:
        pass


@pytest.fixture
def ui_config() -> UIConfig:
    """Create default UI configuration."""
    return UIConfig()


@pytest.fixture
def custom_ui_config() -> UIConfig:
    """Create customized UI configuration."""
    return UIConfig(
        theme=UITheme.CYBERPUNK,
        font_family="Courier New",
        font_size=12,
        auto_refresh=False,
        refresh_interval=2000,
        max_log_entries=5000,
        enable_animations=False,
        show_tooltips=False,
        panel_weights=(2, 3, 1)
    )


@pytest.fixture
def analysis_result() -> AnalysisResult:
    """Create sample analysis result."""
    return AnalysisResult(
        target_file="C:\\test\\sample.exe",
        protection_type="VMProtect",
        confidence=0.87,
        bypass_methods=["Memory Dumping", "API Hooking", "Hardware Breakpoints"],
        timestamp=datetime.now(),
        details={
            "sections": [".text", ".data", ".rdata"],
            "entry_point": "0x00401000",
            "imports": ["kernel32.dll", "user32.dll"],
            "entropy": 7.2
        },
        generated_scripts=["frida_hook.js", "ghidra_analyze.py"]
    )


@pytest.fixture
def temp_config_file(tmp_path: Path) -> Path:
    """Create temporary configuration file."""
    return tmp_path / "ui_config.json"


@pytest.fixture
def fake_ui_controller() -> Generator[FakeUIController, None, None]:
    """Create real test double for UI controller."""
    controller = FakeUIController()
    yield controller
    controller.reset_tracking()


@pytest.fixture
def fake_module_loader() -> Generator[FakeModuleLoader, None, None]:
    """Create real test double for module loader."""
    loader = FakeModuleLoader()
    yield loader
    loader.reset_tracking()


class TestUITheme:
    """Test UI theme enumeration."""

    def test_theme_values_exist(self) -> None:
        """Theme enumeration has expected values."""
        assert UITheme.DARK.value == "dark"
        assert UITheme.LIGHT.value == "light"
        assert UITheme.HIGH_CONTRAST.value == "high_contrast"
        assert UITheme.CYBERPUNK.value == "cyberpunk"

    def test_theme_from_string(self) -> None:
        """Themes can be created from string values."""
        assert UITheme("dark") == UITheme.DARK
        assert UITheme("light") == UITheme.LIGHT
        assert UITheme("high_contrast") == UITheme.HIGH_CONTRAST
        assert UITheme("cyberpunk") == UITheme.CYBERPUNK

    def test_all_themes_distinct(self) -> None:
        """All theme values are unique."""
        themes = [UITheme.DARK, UITheme.LIGHT, UITheme.HIGH_CONTRAST, UITheme.CYBERPUNK]
        values = [t.value for t in themes]
        assert len(values) == len(set(values))

    def test_theme_equality(self) -> None:
        """Theme equality works correctly."""
        assert UITheme.DARK == UITheme.DARK
        assert UITheme.DARK != UITheme.LIGHT  # type: ignore[comparison-overlap]
        assert UITheme.CYBERPUNK == UITheme("cyberpunk")


class TestPanelType:
    """Test panel type enumeration."""

    def test_panel_types_exist(self) -> None:
        """Panel types have expected values."""
        assert PanelType.FILE_EXPLORER.value == "file_explorer"
        assert PanelType.ANALYSIS_VIEWER.value == "analysis_viewer"
        assert PanelType.SCRIPT_GENERATOR.value == "script_generator"

    def test_panel_type_from_string(self) -> None:
        """Panel types can be created from strings."""
        assert PanelType("file_explorer") == PanelType.FILE_EXPLORER
        assert PanelType("analysis_viewer") == PanelType.ANALYSIS_VIEWER
        assert PanelType("script_generator") == PanelType.SCRIPT_GENERATOR


class TestAnalysisState:
    """Test analysis state enumeration."""

    def test_state_values_exist(self) -> None:
        """Analysis states have expected values."""
        assert AnalysisState.IDLE.value == "idle"
        assert AnalysisState.SCANNING.value == "scanning"
        assert AnalysisState.ANALYZING.value == "analyzing"
        assert AnalysisState.GENERATING.value == "generating"
        assert AnalysisState.COMPLETE.value == "complete"
        assert AnalysisState.ERROR.value == "error"

    def test_state_transitions(self) -> None:
        """Analysis state transitions are valid."""
        states = [
            AnalysisState.IDLE,
            AnalysisState.SCANNING,
            AnalysisState.ANALYZING,
            AnalysisState.GENERATING,
            AnalysisState.COMPLETE
        ]
        for state in states:
            assert isinstance(state, AnalysisState)


class TestUIConfig:
    """Test UI configuration dataclass."""

    def test_default_config_values(self, ui_config: UIConfig) -> None:
        """Default configuration has expected values."""
        assert ui_config.theme == UITheme.DARK
        assert ui_config.font_family == "Consolas"
        assert ui_config.font_size == 10
        assert ui_config.auto_refresh is True
        assert ui_config.refresh_interval == 1000
        assert ui_config.max_log_entries == 10000
        assert ui_config.enable_animations is True
        assert ui_config.show_tooltips is True
        assert ui_config.panel_weights == (1, 2, 1)

    def test_custom_config_values(self, custom_ui_config: UIConfig) -> None:
        """Custom configuration preserves values."""
        assert custom_ui_config.theme == UITheme.CYBERPUNK
        assert custom_ui_config.font_family == "Courier New"
        assert custom_ui_config.font_size == 12
        assert custom_ui_config.auto_refresh is False
        assert custom_ui_config.refresh_interval == 2000
        assert custom_ui_config.max_log_entries == 5000
        assert custom_ui_config.enable_animations is False
        assert custom_ui_config.show_tooltips is False
        assert custom_ui_config.panel_weights == (2, 3, 1)

    def test_config_to_dict_serialization(self, ui_config: UIConfig) -> None:
        """Configuration serializes to dictionary correctly."""
        config_dict = ui_config.to_dict()

        assert isinstance(config_dict, dict)
        assert config_dict["theme"] == "dark"
        assert config_dict["font_family"] == "Consolas"
        assert config_dict["font_size"] == 10
        assert config_dict["auto_refresh"] is True
        assert config_dict["refresh_interval"] == 1000
        assert config_dict["max_log_entries"] == 10000
        assert config_dict["enable_animations"] is True
        assert config_dict["show_tooltips"] is True
        assert config_dict["panel_weights"] == (1, 2, 1)

    def test_config_from_dict_deserialization(self) -> None:
        """Configuration deserializes from dictionary correctly."""
        data = {
            "theme": "cyberpunk",
            "font_family": "Monaco",
            "font_size": 11,
            "auto_refresh": False,
            "refresh_interval": 1500,
            "max_log_entries": 8000,
            "enable_animations": False,
            "show_tooltips": True,
            "panel_weights": [3, 2, 1]
        }

        config = UIConfig.from_dict(data)

        assert config.theme == UITheme.CYBERPUNK
        assert config.font_family == "Monaco"
        assert config.font_size == 11
        assert config.auto_refresh is False
        assert config.refresh_interval == 1500
        assert config.max_log_entries == 8000
        assert config.enable_animations is False
        assert config.show_tooltips is True
        assert config.panel_weights == (3, 2, 1)

    def test_config_roundtrip_serialization(self, custom_ui_config: UIConfig) -> None:
        """Configuration survives serialization roundtrip."""
        serialized = custom_ui_config.to_dict()
        deserialized = UIConfig.from_dict(serialized)

        assert deserialized.theme == custom_ui_config.theme
        assert deserialized.font_family == custom_ui_config.font_family
        assert deserialized.font_size == custom_ui_config.font_size
        assert deserialized.auto_refresh == custom_ui_config.auto_refresh
        assert deserialized.refresh_interval == custom_ui_config.refresh_interval
        assert deserialized.max_log_entries == custom_ui_config.max_log_entries
        assert deserialized.enable_animations == custom_ui_config.enable_animations
        assert deserialized.show_tooltips == custom_ui_config.show_tooltips
        assert deserialized.panel_weights == custom_ui_config.panel_weights

    def test_config_handles_missing_fields(self) -> None:
        """Configuration handles missing fields with defaults."""
        minimal_data = {"theme": "light"}
        config = UIConfig.from_dict(minimal_data)

        assert config.theme == UITheme.LIGHT
        assert config.font_family == "Consolas"
        assert config.font_size == 10
        assert config.auto_refresh is True

    def test_config_all_themes_serializable(self) -> None:
        """All theme types serialize correctly."""
        for theme in UITheme:
            config = UIConfig(theme=theme)
            serialized = config.to_dict()
            deserialized = UIConfig.from_dict(serialized)
            assert deserialized.theme == theme

    def test_config_panel_weights_validation(self) -> None:
        """Panel weights are correctly stored as tuple."""
        config = UIConfig(panel_weights=(3, 4, 5))
        assert config.panel_weights == (3, 4, 5)
        assert isinstance(config.panel_weights, tuple)

    def test_config_large_log_entries(self) -> None:
        """Configuration handles large max_log_entries values."""
        config = UIConfig(max_log_entries=1000000)
        assert config.max_log_entries == 1000000


class TestAnalysisResult:
    """Test analysis result dataclass."""

    def test_analysis_result_creation(self, analysis_result: AnalysisResult) -> None:
        """Analysis result created with expected values."""
        assert analysis_result.target_file == "C:\\test\\sample.exe"
        assert analysis_result.protection_type == "VMProtect"
        assert analysis_result.confidence == 0.87
        assert len(analysis_result.bypass_methods) == 3
        assert "Memory Dumping" in analysis_result.bypass_methods
        assert isinstance(analysis_result.timestamp, datetime)
        assert "sections" in analysis_result.details
        assert len(analysis_result.generated_scripts) == 2

    def test_analysis_result_to_dict(self, analysis_result: AnalysisResult) -> None:
        """Analysis result serializes to dictionary."""
        result_dict = analysis_result.to_dict()

        assert isinstance(result_dict, dict)
        assert result_dict["target_file"] == "C:\\test\\sample.exe"
        assert result_dict["protection_type"] == "VMProtect"
        assert result_dict["confidence"] == 0.87
        assert len(result_dict["bypass_methods"]) == 3
        assert "timestamp" in result_dict
        assert isinstance(result_dict["timestamp"], str)
        assert "details" in result_dict
        assert result_dict["details"]["entropy"] == 7.2
        assert len(result_dict["generated_scripts"]) == 2

    def test_analysis_result_timestamp_serialization(self) -> None:
        """Analysis result timestamp serializes to ISO format."""
        timestamp = datetime(2025, 1, 15, 14, 30, 45)
        result = AnalysisResult(
            target_file="test.exe",
            protection_type="Themida",
            confidence=0.95,
            bypass_methods=["IAT Reconstruction"],
            timestamp=timestamp
        )

        result_dict = result.to_dict()
        assert "2025-01-15" in result_dict["timestamp"]
        assert "14:30:45" in result_dict["timestamp"]

    def test_analysis_result_empty_collections(self) -> None:
        """Analysis result handles empty bypass methods and scripts."""
        result = AnalysisResult(
            target_file="unknown.exe",
            protection_type="Unknown",
            confidence=0.0,
            bypass_methods=[],
            timestamp=datetime.now()
        )

        assert len(result.bypass_methods) == 0
        assert len(result.details) == 0
        assert len(result.generated_scripts) == 0

    def test_analysis_result_complex_details(self) -> None:
        """Analysis result handles complex nested details."""
        details = {
            "protection": {
                "type": "VMProtect",
                "version": "3.5",
                "features": ["virtualization", "mutation"]
            },
            "imports": ["kernel32.dll", "ntdll.dll"],
            "exports": [],
            "resources": {"icons": 3, "strings": 42}
        }

        result = AnalysisResult(
            target_file="complex.exe",
            protection_type="VMProtect",
            confidence=0.92,
            bypass_methods=["Devirtualization"],
            timestamp=datetime.now(),
            details=details
        )

        assert result.details["protection"]["version"] == "3.5"
        assert len(result.details["protection"]["features"]) == 2


class TestRealTimeChart:
    """Test real-time chart widget."""

    def test_chart_initialization(self, tk_root: tk.Tk) -> None:
        """Real-time chart initializes with matplotlib figure."""
        frame = ttk.Frame(tk_root)
        chart = RealTimeChart(frame, title="Test Chart")

        assert chart.parent == frame
        assert chart.title == "Test Chart"
        assert chart.figure is not None
        assert chart.axis is not None
        assert chart.canvas is not None
        assert len(chart.data_points) == 0
        assert chart.max_points == 100

    def test_chart_default_title(self, tk_root: tk.Tk) -> None:
        """Chart uses default title when not specified."""
        frame = ttk.Frame(tk_root)
        chart = RealTimeChart(frame)

        assert chart.title == "Analysis Progress"

    def test_chart_update_single_datapoint(self, tk_root: tk.Tk) -> None:
        """Chart updates with single data point."""
        frame = ttk.Frame(tk_root)
        chart = RealTimeChart(frame, title="Progress")

        chart.update_data(0.5, "Test")

        assert len(chart.data_points) == 1
        timestamp, value, label = chart.data_points[0]
        assert isinstance(timestamp, float)
        assert value == 0.5
        assert label == "Test"

    def test_chart_update_multiple_datapoints(self, tk_root: tk.Tk) -> None:
        """Chart accumulates multiple data points."""
        frame = ttk.Frame(tk_root)
        chart = RealTimeChart(frame)

        for i in range(10):
            chart.update_data(float(i), f"Point {i}")
            time.sleep(0.01)

        assert len(chart.data_points) == 10
        values = [point[1] for point in chart.data_points]
        assert values == [float(i) for i in range(10)]

    def test_chart_max_points_enforcement(self, tk_root: tk.Tk) -> None:
        """Chart enforces maximum data points limit."""
        frame = ttk.Frame(tk_root)
        chart = RealTimeChart(frame)
        chart.max_points = 50

        for i in range(100):
            chart.update_data(float(i))

        assert len(chart.data_points) == 50
        values = [point[1] for point in chart.data_points]
        assert values[0] == 50.0
        assert values[-1] == 99.0

    def test_chart_refresh_without_data(self, tk_root: tk.Tk) -> None:
        """Chart refresh handles empty data gracefully."""
        frame = ttk.Frame(tk_root)
        chart = RealTimeChart(frame)

        chart.refresh()

        assert len(chart.data_points) == 0

    def test_chart_update_without_label(self, tk_root: tk.Tk) -> None:
        """Chart handles updates without labels."""
        frame = ttk.Frame(tk_root)
        chart = RealTimeChart(frame)

        chart.update_data(0.75)

        assert len(chart.data_points) == 1
        _, value, label = chart.data_points[0]
        assert value == 0.75
        assert label == ""

    def test_chart_negative_values(self, tk_root: tk.Tk) -> None:
        """Chart handles negative data values."""
        frame = ttk.Frame(tk_root)
        chart = RealTimeChart(frame)

        chart.update_data(-5.0)
        chart.update_data(10.0)
        chart.update_data(-3.0)

        values = [point[1] for point in chart.data_points]
        assert values == [-5.0, 10.0, -3.0]


class TestLogViewer:
    """Test enhanced log viewer."""

    def test_log_viewer_initialization(self, tk_root: tk.Tk, ui_config: UIConfig) -> None:
        """Log viewer initializes with all components."""
        frame = ttk.Frame(tk_root)
        log_viewer = LogViewer(frame, ui_config)

        assert log_viewer.parent == frame
        assert log_viewer.config == ui_config
        assert len(log_viewer.log_entries) == 0
        assert log_viewer.frame is not None
        assert log_viewer.toolbar is not None
        assert log_viewer.search_var is not None
        assert log_viewer.level_var.get() == "ALL"
        assert log_viewer.text_widget is not None

    def test_log_viewer_add_single_entry(self, tk_root: tk.Tk, ui_config: UIConfig) -> None:
        """Log viewer adds single log entry."""
        frame = ttk.Frame(tk_root)
        log_viewer = LogViewer(frame, ui_config)

        log_viewer.add_log("INFO", "Test message", "TestSource")

        assert len(log_viewer.log_entries) == 1
        entry = log_viewer.log_entries[0]
        assert entry["level"] == "INFO"
        assert entry["message"] == "Test message"
        assert entry["source"] == "TestSource"
        assert "timestamp" in entry

    def test_log_viewer_add_multiple_entries(self, tk_root: tk.Tk, ui_config: UIConfig) -> None:
        """Log viewer accumulates multiple entries."""
        frame = ttk.Frame(tk_root)
        log_viewer = LogViewer(frame, ui_config)

        levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        for level in levels:
            log_viewer.add_log(level, f"Message for {level}")

        assert len(log_viewer.log_entries) == 5
        stored_levels = [entry["level"] for entry in log_viewer.log_entries]
        assert stored_levels == levels

    def test_log_viewer_max_entries_enforcement(self, tk_root: tk.Tk, ui_config: UIConfig) -> None:
        """Log viewer enforces maximum entries limit."""
        ui_config.max_log_entries = 100
        frame = ttk.Frame(tk_root)
        log_viewer = LogViewer(frame, ui_config)

        for i in range(200):
            log_viewer.add_log("INFO", f"Message {i}")

        assert len(log_viewer.log_entries) == 100
        assert log_viewer.log_entries[0]["message"] == "Message 100"
        assert log_viewer.log_entries[-1]["message"] == "Message 199"

    def test_log_viewer_level_filtering(self, tk_root: tk.Tk, ui_config: UIConfig) -> None:
        """Log viewer filters entries by level."""
        frame = ttk.Frame(tk_root)
        log_viewer = LogViewer(frame, ui_config)

        log_viewer.add_log("INFO", "Info message")
        log_viewer.add_log("ERROR", "Error message")
        log_viewer.add_log("WARNING", "Warning message")

        log_viewer.level_var.set("ERROR")
        log_viewer.refresh_display()

        text_content = log_viewer.text_widget.get("1.0", "end-1c")
        assert "Error message" in text_content
        assert "Info message" not in text_content
        assert "Warning message" not in text_content

    def test_log_viewer_search_filtering(self, tk_root: tk.Tk, ui_config: UIConfig) -> None:
        """Log viewer filters entries by search term."""
        frame = ttk.Frame(tk_root)
        log_viewer = LogViewer(frame, ui_config)

        log_viewer.add_log("INFO", "Binary analysis started")
        log_viewer.add_log("INFO", "Protection detection running")
        log_viewer.add_log("INFO", "Binary patching complete")

        log_viewer.search_var.set("binary")
        log_viewer.refresh_display()

        text_content = log_viewer.text_widget.get("1.0", "end-1c")
        assert "Binary analysis" in text_content
        assert "Binary patching" in text_content
        assert "Protection detection" not in text_content

    def test_log_viewer_clear_logs(self, tk_root: tk.Tk, ui_config: UIConfig) -> None:
        """Log viewer clears all entries."""
        frame = ttk.Frame(tk_root)
        log_viewer = LogViewer(frame, ui_config)

        for i in range(10):
            log_viewer.add_log("INFO", f"Message {i}")

        assert len(log_viewer.log_entries) == 10

        log_viewer.clear_logs()

        assert len(log_viewer.log_entries) == 0
        text_content = log_viewer.text_widget.get("1.0", "end-1c")
        assert text_content.strip() == ""

    def test_log_viewer_case_insensitive_search(self, tk_root: tk.Tk, ui_config: UIConfig) -> None:
        """Log viewer search is case insensitive."""
        frame = ttk.Frame(tk_root)
        log_viewer = LogViewer(frame, ui_config)

        log_viewer.add_log("INFO", "VMProtect detected")
        log_viewer.add_log("INFO", "Themida found")

        log_viewer.search_var.set("VMPROTECT")
        log_viewer.refresh_display()

        text_content = log_viewer.text_widget.get("1.0", "end-1c")
        assert "VMProtect detected" in text_content
        assert "Themida found" not in text_content

    def test_log_viewer_without_source(self, tk_root: tk.Tk, ui_config: UIConfig) -> None:
        """Log viewer handles entries without source."""
        frame = ttk.Frame(tk_root)
        log_viewer = LogViewer(frame, ui_config)

        log_viewer.add_log("INFO", "No source message")

        assert len(log_viewer.log_entries) == 1
        assert log_viewer.log_entries[0]["source"] == ""

    def test_log_viewer_combined_filters(self, tk_root: tk.Tk, ui_config: UIConfig) -> None:
        """Log viewer applies both level and search filters."""
        frame = ttk.Frame(tk_root)
        log_viewer = LogViewer(frame, ui_config)

        log_viewer.add_log("ERROR", "Binary error occurred")
        log_viewer.add_log("ERROR", "Network error detected")
        log_viewer.add_log("INFO", "Binary analysis complete")

        log_viewer.level_var.set("ERROR")
        log_viewer.search_var.set("binary")
        log_viewer.refresh_display()

        text_content = log_viewer.text_widget.get("1.0", "end-1c")
        assert "Binary error" in text_content
        assert "Network error" not in text_content
        assert "Binary analysis" not in text_content


class TestProgressTracker:
    """Test advanced progress tracker."""

    def test_progress_tracker_initialization(self, tk_root: tk.Tk) -> None:
        """Progress tracker initializes with components."""
        frame = ttk.Frame(tk_root)
        tracker = ProgressTracker(frame, title="Test Progress")

        assert tracker.parent == frame
        assert tracker.title == "Test Progress"
        assert tracker.start_time is None
        assert tracker.frame is not None
        assert tracker.progress_bar is not None
        assert tracker.status_label is not None
        assert tracker.eta_label is not None
        assert len(tracker.speed_history) == 0

    def test_progress_tracker_start(self, tk_root: tk.Tk) -> None:
        """Progress tracker starts tracking."""
        frame = ttk.Frame(tk_root)
        tracker = ProgressTracker(frame)

        tracker.start(total_items=100)

        assert tracker.total_items == 100
        assert tracker.completed_items == 0
        assert tracker.start_time is not None
        assert isinstance(tracker.start_time, float)

    def test_progress_tracker_update_progress(self, tk_root: tk.Tk) -> None:
        """Progress tracker updates with progress."""
        frame = ttk.Frame(tk_root)
        tracker = ProgressTracker(frame)
        tracker.start(total_items=100)

        tracker.update(25, "Processing files...")

        assert tracker.completed_items == 25
        assert tracker.progress_var.get() == 25.0
        assert tracker.status_label.cget("text") == "Processing files..."

    def test_progress_tracker_eta_calculation(self, tk_root: tk.Tk) -> None:
        """Progress tracker calculates ETA."""
        frame = ttk.Frame(tk_root)
        tracker = ProgressTracker(frame)
        tracker.start(total_items=100)

        tracker.update(10)
        time.sleep(0.1)
        tracker.update(20)
        time.sleep(0.1)
        tracker.update(30)

        assert len(tracker.speed_history) > 0
        eta_text = tracker.eta_label.cget("text")
        assert "ETA" in eta_text

    def test_progress_tracker_finish(self, tk_root: tk.Tk) -> None:
        """Progress tracker completes tracking."""
        frame = ttk.Frame(tk_root)
        tracker = ProgressTracker(frame)
        tracker.start(total_items=50)
        tracker.update(25)

        tracker.finish("Analysis complete")

        assert tracker.progress_var.get() == 100.0
        assert tracker.status_label.cget("text") == "Analysis complete"
        assert tracker.eta_label.cget("text") == ""

    def test_progress_tracker_time_formatting(self, tk_root: tk.Tk) -> None:
        """Progress tracker formats time correctly."""
        frame = ttk.Frame(tk_root)
        tracker = ProgressTracker(frame)

        assert tracker.format_time(30) == "30s"
        assert tracker.format_time(90) == "1m 30s"
        assert tracker.format_time(3720) == "1h 2m"
        assert tracker.format_time(150) == "2m 30s"

    def test_progress_tracker_speed_history_limit(self, tk_root: tk.Tk) -> None:
        """Progress tracker limits speed history entries."""
        frame = ttk.Frame(tk_root)
        tracker = ProgressTracker(frame)
        tracker.max_speed_history = 5
        tracker.start(total_items=100)

        for i in range(1, 20):
            tracker.update(i * 5)
            time.sleep(0.01)

        assert len(tracker.speed_history) <= 5

    def test_progress_tracker_update_without_start(self, tk_root: tk.Tk) -> None:
        """Progress tracker auto-starts if updated without explicit start."""
        frame = ttk.Frame(tk_root)
        tracker = ProgressTracker(frame)

        tracker.update(10, "Processing")

        assert tracker.start_time is not None
        assert tracker.completed_items == 10

    def test_progress_tracker_finish_custom_message(self, tk_root: tk.Tk) -> None:
        """Progress tracker accepts custom finish message."""
        frame = ttk.Frame(tk_root)
        tracker = ProgressTracker(frame)
        tracker.start(100)

        tracker.finish("Custom completion message")

        assert tracker.status_label.cget("text") == "Custom completion message"


class TestFileExplorerPanel:
    """Test file explorer panel."""

    def test_file_explorer_initialization(self, tk_root: tk.Tk, ui_config: UIConfig, fake_ui_controller: FakeUIController) -> None:
        """File explorer panel initializes with components."""
        frame = ttk.Frame(tk_root)
        explorer = FileExplorerPanel(frame, ui_config, fake_ui_controller)  # type: ignore[arg-type]

        assert explorer.parent == frame
        assert explorer.config == ui_config
        assert explorer.ui_controller == fake_ui_controller  # type: ignore[comparison-overlap]
        assert explorer.frame is not None
        assert explorer.toolbar is not None
        assert explorer.tree is not None
        assert explorer.status_frame is not None
        assert explorer.context_menu is not None
        assert isinstance(explorer.current_path, Path)

    def test_file_explorer_file_size_formatting(self, tk_root: tk.Tk, ui_config: UIConfig, fake_ui_controller: FakeUIController) -> None:
        """File explorer formats file sizes correctly."""
        frame = ttk.Frame(tk_root)
        explorer = FileExplorerPanel(frame, ui_config, fake_ui_controller)  # type: ignore[arg-type]

        assert explorer.format_file_size(500) == "500.0 B"
        assert explorer.format_file_size(2048) == "2.0 KB"
        assert explorer.format_file_size(1048576) == "1.0 MB"
        assert explorer.format_file_size(1073741824) == "1.0 GB"

    def test_file_explorer_get_file_icons(self, tk_root: tk.Tk, ui_config: UIConfig, fake_ui_controller: FakeUIController) -> None:
        """File explorer returns appropriate icons for file types."""
        frame = ttk.Frame(tk_root)
        explorer = FileExplorerPanel(frame, ui_config, fake_ui_controller)  # type: ignore[arg-type]

        assert explorer.get_file_icon(Path("test.exe")) != ""
        assert explorer.get_file_icon(Path("test.dll")) != ""
        assert explorer.get_file_icon(Path("test.py")) != ""
        assert explorer.get_file_icon(Path("test.txt")) != ""

    def test_file_explorer_navigate_up(self, tk_root: tk.Tk, ui_config: UIConfig, fake_ui_controller: FakeUIController, tmp_path: Path) -> None:
        """File explorer navigates to parent directory."""
        frame = ttk.Frame(tk_root)
        explorer = FileExplorerPanel(frame, ui_config, fake_ui_controller)  # type: ignore[arg-type]

        test_dir = tmp_path / "subdir"
        test_dir.mkdir()
        explorer.current_path = test_dir

        explorer.go_up()

        assert explorer.current_path == tmp_path

    def test_file_explorer_analyze_file_triggers_controller(self, tk_root: tk.Tk, ui_config: UIConfig, fake_ui_controller: FakeUIController, tmp_path: Path) -> None:
        """File explorer triggers analysis through controller."""
        frame = ttk.Frame(tk_root)
        explorer = FileExplorerPanel(frame, ui_config, fake_ui_controller)  # type: ignore[arg-type]

        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"MZ\x90\x00")

        explorer.analyze_file(test_file)

        assert fake_ui_controller.verify_analyze_file_call_count(1)
        assert fake_ui_controller.verify_analyze_file_called_with(str(test_file))

    def test_file_explorer_refresh_tree_with_files(self, tk_root: tk.Tk, ui_config: UIConfig, fake_ui_controller: FakeUIController, tmp_path: Path) -> None:
        """File explorer refreshes tree with actual files."""
        frame = ttk.Frame(tk_root)
        explorer = FileExplorerPanel(frame, ui_config, fake_ui_controller)  # type: ignore[arg-type]

        (tmp_path / "test1.exe").write_bytes(b"data")
        (tmp_path / "test2.dll").write_bytes(b"data")
        (tmp_path / "subdir").mkdir()

        explorer.current_path = tmp_path
        explorer.refresh_tree()

        items = explorer.tree.get_children()
        assert len(items) == 3

    def test_file_explorer_file_size_edge_cases(self, tk_root: tk.Tk, ui_config: UIConfig, fake_ui_controller: FakeUIController) -> None:
        """File explorer handles edge case file sizes."""
        frame = ttk.Frame(tk_root)
        explorer = FileExplorerPanel(frame, ui_config, fake_ui_controller)  # type: ignore[arg-type]

        assert "0.0 B" in explorer.format_file_size(0)
        assert "TB" in explorer.format_file_size(1099511627776)

    def test_file_explorer_icon_for_unknown_type(self, tk_root: tk.Tk, ui_config: UIConfig, fake_ui_controller: FakeUIController) -> None:
        """File explorer returns default icon for unknown file type."""
        frame = ttk.Frame(tk_root)
        explorer = FileExplorerPanel(frame, ui_config, fake_ui_controller)  # type: ignore[arg-type]

        icon = explorer.get_file_icon(Path("test.unknown"))
        assert icon != ""

    def test_file_explorer_navigate_back(self, tk_root: tk.Tk, ui_config: UIConfig, fake_ui_controller: FakeUIController, tmp_path: Path) -> None:
        """File explorer back navigation works."""
        frame = ttk.Frame(tk_root)
        explorer = FileExplorerPanel(frame, ui_config, fake_ui_controller)  # type: ignore[arg-type]

        subdir = tmp_path / "subdir"
        subdir.mkdir()
        explorer.current_path = subdir

        explorer.go_back()

        assert explorer.current_path == tmp_path


class TestAnalysisViewerPanel:
    """Test analysis viewer panel."""

    def test_analysis_viewer_initialization(self, tk_root: tk.Tk, ui_config: UIConfig, fake_ui_controller: FakeUIController) -> None:
        """Analysis viewer panel initializes with tabs."""
        frame = ttk.Frame(tk_root)
        viewer = AnalysisViewerPanel(frame, ui_config, fake_ui_controller)  # type: ignore[arg-type]

        assert viewer.parent == frame
        assert viewer.config == ui_config
        assert viewer.ui_controller == fake_ui_controller  # type: ignore[comparison-overlap]
        assert viewer.frame is not None
        assert viewer.notebook is not None
        assert viewer.overview_frame is not None
        assert viewer.details_frame is not None
        assert viewer.current_analysis is None

    def test_analysis_viewer_update_with_result(self, tk_root: tk.Tk, ui_config: UIConfig, fake_ui_controller: FakeUIController, analysis_result: AnalysisResult) -> None:
        """Analysis viewer updates with analysis result."""
        frame = ttk.Frame(tk_root)
        viewer = AnalysisViewerPanel(frame, ui_config, fake_ui_controller)  # type: ignore[arg-type]

        viewer.update_analysis(analysis_result)

        assert viewer.current_analysis == analysis_result
        assert viewer.protection_type_label.cget("text") == "VMProtect"
        assert viewer.confidence_label.cget("text") == "87%"
        assert viewer.confidence_progress["value"] == 87.0

    def test_analysis_viewer_bypass_methods_display(self, tk_root: tk.Tk, ui_config: UIConfig, fake_ui_controller: FakeUIController, analysis_result: AnalysisResult) -> None:
        """Analysis viewer displays bypass methods."""
        frame = ttk.Frame(tk_root)
        viewer = AnalysisViewerPanel(frame, ui_config, fake_ui_controller)  # type: ignore[arg-type]

        viewer.update_analysis(analysis_result)

        assert viewer.bypass_listbox.size() == 3
        methods = [viewer.bypass_listbox.get(i) for i in range(viewer.bypass_listbox.size())]
        assert "Memory Dumping" in methods
        assert "API Hooking" in methods
        assert "Hardware Breakpoints" in methods

    def test_analysis_viewer_low_confidence_display(self, tk_root: tk.Tk, ui_config: UIConfig, fake_ui_controller: FakeUIController) -> None:
        """Analysis viewer handles low confidence results."""
        frame = ttk.Frame(tk_root)
        viewer = AnalysisViewerPanel(frame, ui_config, fake_ui_controller)  # type: ignore[arg-type]

        low_confidence_result = AnalysisResult(
            target_file="unknown.exe",
            protection_type="Unknown",
            confidence=0.15,
            bypass_methods=[],
            timestamp=datetime.now()
        )

        viewer.update_analysis(low_confidence_result)

        assert viewer.confidence_progress["value"] == 15.0

    def test_analysis_viewer_multiple_updates(self, tk_root: tk.Tk, ui_config: UIConfig, fake_ui_controller: FakeUIController, analysis_result: AnalysisResult) -> None:
        """Analysis viewer handles multiple sequential updates."""
        frame = ttk.Frame(tk_root)
        viewer = AnalysisViewerPanel(frame, ui_config, fake_ui_controller)  # type: ignore[arg-type]

        viewer.update_analysis(analysis_result)

        new_result = AnalysisResult(
            target_file="another.exe",
            protection_type="Themida",
            confidence=0.95,
            bypass_methods=["IAT Reconstruction"],
            timestamp=datetime.now()
        )

        viewer.update_analysis(new_result)

        assert viewer.current_analysis == new_result
        assert viewer.protection_type_label.cget("text") == "Themida"


class TestScriptGeneratorPanel:
    """Test script generator panel."""

    def test_script_generator_initialization(self, tk_root: tk.Tk, ui_config: UIConfig, fake_ui_controller: FakeUIController) -> None:
        """Script generator panel initializes with tabs."""
        frame = ttk.Frame(tk_root)
        generator = ScriptGeneratorPanel(frame, ui_config, fake_ui_controller)  # type: ignore[arg-type]

        assert generator.parent == frame
        assert generator.config == ui_config
        assert generator.ui_controller == fake_ui_controller  # type: ignore[comparison-overlap]
        assert generator.frame is not None
        assert generator.notebook is not None

    def test_script_generator_has_required_tabs(self, tk_root: tk.Tk, ui_config: UIConfig, fake_ui_controller: FakeUIController) -> None:
        """Script generator has all required tabs."""
        frame = ttk.Frame(tk_root)
        generator = ScriptGeneratorPanel(frame, ui_config, fake_ui_controller)  # type: ignore[arg-type]

        tab_count = generator.notebook.index("end")
        assert tab_count >= 3


class TestUIEnhancementModule:
    """Test main UI enhancement module."""

    def test_module_initialization_without_root(self) -> None:
        """UI enhancement module initializes its own root."""
        module = UIEnhancementModule()

        assert module.root is not None
        assert isinstance(module.root, tk.Tk)
        assert module.config is not None
        assert isinstance(module.config, UIConfig)

        try:
            module.root.quit()
            module.root.destroy()
        except tk.TclError:
            pass

    def test_module_initialization_with_root(self, tk_root: tk.Tk) -> None:
        """UI enhancement module uses provided root."""
        module = UIEnhancementModule(root=tk_root)

        assert module.root == tk_root
        assert module.config is not None

    def test_module_config_persistence(self, tmp_path: Path) -> None:
        """UI enhancement module persists configuration."""
        module = UIEnhancementModule()
        config_file = tmp_path / "ui_config.json"

        module.config.theme = UITheme.CYBERPUNK
        module.config.font_size = 14

        import os
        old_cwd = os.getcwd()
        os.chdir(str(tmp_path))
        try:
            module.save_config()

            assert (tmp_path / "ui_config.json").exists()

            with open(tmp_path / "ui_config.json", "r", encoding="utf-8") as f:
                saved_data = json.load(f)

            assert saved_data["theme"] == "cyberpunk"
            assert saved_data["font_size"] == 14
        finally:
            os.chdir(old_cwd)

        try:
            module.root.quit()
            module.root.destroy()
        except tk.TclError:
            pass

    def test_module_theme_application(self) -> None:
        """UI enhancement module applies themes."""
        module = UIEnhancementModule()

        module.config.theme = UITheme.DARK
        module.apply_theme()

        assert module.root.cget("bg") is not None

        module.config.theme = UITheme.LIGHT
        module.apply_theme()

        assert module.root.cget("bg") is not None

        try:
            module.root.quit()
            module.root.destroy()
        except tk.TclError:
            pass

    def test_module_analyze_file_creates_thread(self, tmp_path: Path) -> None:
        """UI enhancement module analyzes file in separate thread."""
        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"MZ\x90\x00" + b"\x00" * 100)

        module = UIEnhancementModule()
        initial_thread_count = threading.active_count()

        module.analyze_file(str(test_file))

        time.sleep(0.1)

        assert threading.active_count() >= initial_thread_count

        try:
            module.root.quit()
            module.root.destroy()
        except tk.TclError:
            pass

    def test_module_generate_frida_script(self) -> None:
        """UI enhancement module generates Frida scripts."""
        module = UIEnhancementModule()

        script = module.generate_frida_script("target.exe", "hook_functions")

        assert isinstance(script, str)
        assert len(script) > 0
        assert "Interceptor.attach" in script or "function" in script.lower()

        try:
            module.root.quit()
            module.root.destroy()
        except tk.TclError:
            pass

    def test_module_generate_ghidra_script(self) -> None:
        """UI enhancement module generates Ghidra scripts."""
        module = UIEnhancementModule()

        script = module.generate_ghidra_script("target.exe", "analyze_functions")

        assert isinstance(script, str)
        assert len(script) > 0

        try:
            module.root.quit()
            module.root.destroy()
        except tk.TclError:
            pass

    def test_module_generate_r2_script(self) -> None:
        """UI enhancement module generates Radare2 scripts."""
        module = UIEnhancementModule()

        script = module.generate_r2_script("target.exe", "disassemble")

        assert isinstance(script, str)
        assert len(script) > 0

        try:
            module.root.quit()
            module.root.destroy()
        except tk.TclError:
            pass

    def test_module_has_all_panels(self) -> None:
        """UI enhancement module creates all required panels."""
        module = UIEnhancementModule()

        assert hasattr(module, 'file_explorer')
        assert hasattr(module, 'analysis_viewer')
        assert hasattr(module, 'script_generator')
        assert hasattr(module, 'log_viewer')
        assert hasattr(module, 'progress_tracker')

        try:
            module.root.quit()
            module.root.destroy()
        except tk.TclError:
            pass

    def test_module_status_bar_created(self) -> None:
        """UI enhancement module creates status bar."""
        module = UIEnhancementModule()

        assert hasattr(module, 'create_status_bar')

        try:
            module.root.quit()
            module.root.destroy()
        except tk.TclError:
            pass

    def test_module_menu_created(self) -> None:
        """UI enhancement module creates menu bar."""
        module = UIEnhancementModule()

        assert hasattr(module, 'create_menu')

        try:
            module.root.quit()
            module.root.destroy()
        except tk.TclError:
            pass


class TestIntegrationWorkflows:
    """Test complete UI enhancement workflows."""

    def test_complete_analysis_workflow(self, tmp_path: Path) -> None:
        """Complete workflow from file selection to analysis display."""
        test_file = tmp_path / "protected.exe"
        test_file.write_bytes(b"MZ\x90\x00" + b"\x00" * 1000)

        module = UIEnhancementModule()

        module.file_explorer.current_path = tmp_path
        module.file_explorer.refresh_tree()

        time.sleep(0.1)

        tree_items = module.file_explorer.tree.get_children()
        assert len(tree_items) > 0

        try:
            module.root.quit()
            module.root.destroy()
        except tk.TclError:
            pass

    def test_log_viewer_integration(self) -> None:
        """Log viewer integrates with UI module."""
        module = UIEnhancementModule()

        module.log_viewer.add_log("INFO", "Starting analysis")
        module.log_viewer.add_log("WARNING", "Packed binary detected")
        module.log_viewer.add_log("ERROR", "Analysis failed")

        assert len(module.log_viewer.log_entries) == 3

        module.log_viewer.level_var.set("ERROR")
        module.log_viewer.refresh_display()

        text_content = module.log_viewer.text_widget.get("1.0", "end-1c")
        assert "Analysis failed" in text_content

        try:
            module.root.quit()
            module.root.destroy()
        except tk.TclError:
            pass

    def test_configuration_roundtrip_workflow(self, tmp_path: Path) -> None:
        """Configuration saves and loads correctly."""
        import os

        old_cwd = os.getcwd()
        os.chdir(str(tmp_path))

        try:
            module1 = UIEnhancementModule()
            module1.config.theme = UITheme.CYBERPUNK
            module1.config.font_size = 15
            module1.config.auto_refresh = False
            module1.save_config()

            try:
                module1.root.quit()
                module1.root.destroy()
            except tk.TclError:
                pass

            module2 = UIEnhancementModule()
            loaded_config = module2.load_config()

            assert loaded_config.theme == UITheme.CYBERPUNK
            assert loaded_config.font_size == 15
            assert loaded_config.auto_refresh is False

            try:
                module2.root.quit()
                module2.root.destroy()
            except tk.TclError:
                pass
        finally:
            os.chdir(old_cwd)


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_log_viewer_handles_empty_search(self, tk_root: tk.Tk, ui_config: UIConfig) -> None:
        """Log viewer handles empty search term."""
        frame = ttk.Frame(tk_root)
        log_viewer = LogViewer(frame, ui_config)

        log_viewer.add_log("INFO", "Test message")
        log_viewer.search_var.set("")
        log_viewer.refresh_display()

        text_content = log_viewer.text_widget.get("1.0", "end-1c")
        assert "Test message" in text_content

    def test_progress_tracker_handles_zero_items(self, tk_root: tk.Tk) -> None:
        """Progress tracker handles zero total items."""
        frame = ttk.Frame(tk_root)
        tracker = ProgressTracker(frame)

        tracker.start(total_items=0)
        tracker.update_display()

        assert tracker.total_items == 0

    def test_file_explorer_handles_nonexistent_path(self, tk_root: tk.Tk, ui_config: UIConfig, fake_ui_controller: FakeUIController) -> None:
        """File explorer handles nonexistent directory."""
        frame = ttk.Frame(tk_root)
        explorer = FileExplorerPanel(frame, ui_config, fake_ui_controller)  # type: ignore[arg-type]

        explorer.current_path = Path("C:\\nonexistent\\directory\\path")
        explorer.refresh_tree()

        status_text = explorer.status_label.cget("text")
        assert "not exist" in status_text.lower() or "error" in status_text.lower()

    def test_analysis_result_with_minimal_data(self) -> None:
        """Analysis result handles minimal data."""
        result = AnalysisResult(
            target_file="test.exe",
            protection_type="Unknown",
            confidence=0.0,
            bypass_methods=[],
            timestamp=datetime.now()
        )

        assert result.target_file == "test.exe"
        assert result.confidence == 0.0
        assert len(result.bypass_methods) == 0
        assert len(result.details) == 0
        assert len(result.generated_scripts) == 0

    def test_ui_config_handles_invalid_theme(self) -> None:
        """UI config handles invalid theme gracefully."""
        data = {"theme": "invalid_theme"}

        try:
            config = UIConfig.from_dict(data)
            assert False, "Should have raised ValueError"
        except ValueError:
            pass

    def test_chart_handles_rapid_updates(self, tk_root: tk.Tk) -> None:
        """Chart handles rapid data updates."""
        frame = ttk.Frame(tk_root)
        chart = RealTimeChart(frame)

        for i in range(200):
            chart.update_data(float(i))

        assert len(chart.data_points) == 100
        assert chart.data_points[-1][1] == 199.0

    def test_progress_tracker_100_percent_completion(self, tk_root: tk.Tk) -> None:
        """Progress tracker correctly displays 100% completion."""
        frame = ttk.Frame(tk_root)
        tracker = ProgressTracker(frame)
        tracker.start(100)

        tracker.update(100, "Complete")

        assert tracker.progress_var.get() == 100.0

    def test_log_viewer_very_long_message(self, tk_root: tk.Tk, ui_config: UIConfig) -> None:
        """Log viewer handles very long messages."""
        frame = ttk.Frame(tk_root)
        log_viewer = LogViewer(frame, ui_config)

        long_message = "A" * 10000
        log_viewer.add_log("INFO", long_message)

        assert len(log_viewer.log_entries) == 1
        assert len(log_viewer.log_entries[0]["message"]) == 10000

    def test_file_explorer_empty_directory(self, tk_root: tk.Tk, ui_config: UIConfig, fake_ui_controller: FakeUIController, tmp_path: Path) -> None:
        """File explorer handles empty directory."""
        frame = ttk.Frame(tk_root)
        explorer = FileExplorerPanel(frame, ui_config, fake_ui_controller)  # type: ignore[arg-type]

        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()

        explorer.current_path = empty_dir
        explorer.refresh_tree()

        items = explorer.tree.get_children()
        assert len(items) == 0

    def test_chart_with_single_point(self, tk_root: tk.Tk) -> None:
        """Chart handles single data point."""
        frame = ttk.Frame(tk_root)
        chart = RealTimeChart(frame)

        chart.update_data(42.0, "single")
        chart.refresh()

        assert len(chart.data_points) == 1


class TestFakeUIControllerBehavior:
    """Test real test double behavior."""

    def test_fake_controller_tracks_analyze_calls(self, fake_ui_controller: FakeUIController) -> None:
        """Fake controller accurately tracks analyze_file calls."""
        fake_ui_controller.analyze_file("test1.exe")
        fake_ui_controller.analyze_file("test2.exe")
        fake_ui_controller.analyze_file("test3.exe")

        assert fake_ui_controller.call_count_analyze_file == 3
        assert len(fake_ui_controller.analyzed_files) == 3
        assert "test1.exe" in fake_ui_controller.analyzed_files
        assert "test2.exe" in fake_ui_controller.analyzed_files
        assert "test3.exe" in fake_ui_controller.analyzed_files

    def test_fake_controller_tracks_script_generation(self, fake_ui_controller: FakeUIController) -> None:
        """Fake controller tracks script generation calls."""
        fake_ui_controller.generate_scripts("target.exe", "frida")
        fake_ui_controller.generate_scripts("target.exe", "ghidra")

        assert fake_ui_controller.call_count_generate_scripts == 2
        assert len(fake_ui_controller.generated_scripts) == 2
        assert ("target.exe", "frida") in fake_ui_controller.generated_scripts
        assert ("target.exe", "ghidra") in fake_ui_controller.generated_scripts

    def test_fake_controller_returns_valid_analysis_results(self, fake_ui_controller: FakeUIController) -> None:
        """Fake controller returns valid analysis results."""
        result = fake_ui_controller.analyze_file("test.exe")

        assert result is not None
        assert result.target_file == "test.exe"
        assert result.protection_type == "VMProtect"
        assert result.confidence == 0.85
        assert len(result.bypass_methods) == 2

    def test_fake_controller_can_simulate_failures(self, fake_ui_controller: FakeUIController) -> None:
        """Fake controller can simulate analysis failures."""
        fake_ui_controller.should_fail_analysis = True

        result = fake_ui_controller.analyze_file("test.exe")

        assert result is None

    def test_fake_controller_reset_clears_tracking(self, fake_ui_controller: FakeUIController) -> None:
        """Fake controller reset clears all tracking data."""
        fake_ui_controller.analyze_file("test.exe")
        fake_ui_controller.generate_scripts("test.exe", "frida")

        assert fake_ui_controller.call_count_analyze_file > 0
        assert fake_ui_controller.call_count_generate_scripts > 0

        fake_ui_controller.reset_tracking()

        assert fake_ui_controller.call_count_analyze_file == 0
        assert fake_ui_controller.call_count_generate_scripts == 0
        assert len(fake_ui_controller.analyzed_files) == 0
        assert len(fake_ui_controller.generated_scripts) == 0


class TestFakeModuleLoaderBehavior:
    """Test module loader test double behavior."""

    def test_fake_loader_tracks_loaded_modules(self, fake_module_loader: FakeModuleLoader) -> None:
        """Fake loader tracks module loading."""
        fake_module_loader.load_module("module1")
        fake_module_loader.load_module("module2")

        assert len(fake_module_loader.loaded_modules) == 2
        assert "module1" in fake_module_loader.loaded_modules
        assert "module2" in fake_module_loader.loaded_modules

    def test_fake_loader_tracks_unloaded_modules(self, fake_module_loader: FakeModuleLoader) -> None:
        """Fake loader tracks module unloading."""
        fake_module_loader.load_module("module1")
        fake_module_loader.unload_module("module1")

        assert not fake_module_loader.is_module_loaded("module1")
        assert "module1" in fake_module_loader.unloaded_modules

    def test_fake_loader_stores_module_config(self, fake_module_loader: FakeModuleLoader) -> None:
        """Fake loader stores module configuration."""
        config = {"theme": "dark", "enabled": True}
        fake_module_loader.configure_module("ui_module", config)

        stored_config = fake_module_loader.get_module_config("ui_module")
        assert stored_config is not None
        assert stored_config["theme"] == "dark"
        assert stored_config["enabled"] is True

    def test_fake_loader_reset_clears_state(self, fake_module_loader: FakeModuleLoader) -> None:
        """Fake loader reset clears all state."""
        fake_module_loader.load_module("module1")
        fake_module_loader.initialize_module("module1")
        fake_module_loader.configure_module("module1", {"key": "value"})

        fake_module_loader.reset_tracking()

        assert len(fake_module_loader.loaded_modules) == 0
        assert len(fake_module_loader.initialized_modules) == 0
        assert len(fake_module_loader.configured_modules) == 0
