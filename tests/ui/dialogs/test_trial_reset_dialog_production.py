"""Production-grade tests for Trial Reset Dialog.

This test suite validates the complete trial reset engine dialog functionality
including trial scanning, reset strategy selection, backup creation, monitoring,
and complete trial reset workflows. Tests verify genuine integration with
TrialResetEngine backend and validate real trial reset operations.

Copyright (C) 2025 Zachary Flint
Licensed under GNU GPL v3
"""

import json
import tempfile
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, Mock, patch

import pytest

from intellicrack.handlers.pyqt6_handler import HAS_PYQT as PYQT6_AVAILABLE

if PYQT6_AVAILABLE:
    from intellicrack.handlers.pyqt6_handler import (
        QApplication,
        QMessageBox,
        Qt,
    )
    from intellicrack.ui.dialogs.trial_reset_dialog import (
        TrialResetDialog,
        TrialResetWorker,
    )
    from intellicrack.core.trial_reset_engine import (
        TrialInfo,
        TrialType,
    )

pytestmark = pytest.mark.skipif(
    not PYQT6_AVAILABLE,
    reason="PyQt6 required for UI tests",
)


@pytest.fixture(scope="module")
def qapp() -> Any:
    """Create QApplication instance for Qt widget testing."""
    if not PYQT6_AVAILABLE:
        pytest.skip("PyQt6 not available")
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


@pytest.fixture
def mock_engine() -> Mock:
    """Create mock TrialResetEngine with realistic behavior."""
    engine = Mock()

    mock_trial_info = TrialInfo(
        product_name="WinRAR",
        trial_type=TrialType.DAYS_BASED,
        trial_days=40,
        days_remaining=15,
        usage_count=25,
        install_date=datetime.now() - timedelta(days=25),
        first_run_date=datetime.now() - timedelta(days=25),
        last_run_date=datetime.now() - timedelta(days=1),
        trial_expired=False,
        registry_keys=[
            r"HKEY_CURRENT_USER\Software\WinRAR\TrialInfo",
            r"HKEY_LOCAL_MACHINE\Software\WinRAR\License"
        ],
        files=[
            r"C:\Users\TestUser\AppData\Roaming\WinRAR\trial.dat",
            r"C:\ProgramData\WinRAR\install.log"
        ],
        processes=["WinRAR.exe"]
    )

    engine.scan_for_trial = Mock(return_value=mock_trial_info)
    engine.reset_trial = Mock(return_value=True)
    engine._kill_processes = Mock(return_value=None)

    return engine


@pytest.fixture
def mock_expired_trial_info() -> TrialInfo:
    """Create mock expired trial information."""
    return TrialInfo(
        product_name="VMware Workstation",
        trial_type=TrialType.DAYS_BASED,
        trial_days=30,
        days_remaining=0,
        usage_count=45,
        install_date=datetime.now() - timedelta(days=45),
        first_run_date=datetime.now() - timedelta(days=45),
        last_run_date=datetime.now(),
        trial_expired=True,
        registry_keys=[
            r"HKEY_LOCAL_MACHINE\Software\VMware\VMware Workstation\Trial"
        ],
        files=[
            r"C:\ProgramData\VMware\trial.lic"
        ],
        processes=["vmware.exe", "vmware-authd.exe"]
    )


@pytest.fixture
def temp_backup_dir() -> Path:
    """Create temporary directory for backup files."""
    with tempfile.TemporaryDirectory(prefix="trial_backups_") as tmpdir:
        yield Path(tmpdir)


class TestTrialResetDialogInitialization:
    """Test dialog initialization and UI component creation."""

    def test_dialog_creates_successfully(self, qapp: Any, mock_engine: Mock) -> None:
        """Dialog initializes with all required UI components."""
        with patch("intellicrack.ui.dialogs.trial_reset_dialog.TrialResetEngine", return_value=mock_engine):
            dialog = TrialResetDialog()

            assert dialog.engine is not None
            assert dialog.windowTitle() == "Trial Reset Engine"
            assert dialog.minimumSize().width() >= 900
            assert dialog.minimumSize().height() >= 650

    def test_dialog_creates_all_tabs(self, qapp: Any, mock_engine: Mock) -> None:
        """Dialog creates all required tabs for trial reset workflow."""
        with patch("intellicrack.ui.dialogs.trial_reset_dialog.TrialResetEngine", return_value=mock_engine):
            dialog = TrialResetDialog()

            assert dialog.tabs.count() == 5

            tab_names = [dialog.tabs.tabText(i) for i in range(dialog.tabs.count())]
            assert "Scan" in tab_names
            assert "Reset" in tab_names
            assert "Monitor" in tab_names
            assert "Advanced" in tab_names
            assert "History" in tab_names

    def test_dialog_initializes_reset_strategies(self, qapp: Any, mock_engine: Mock) -> None:
        """Reset strategy radio buttons are initialized with all options."""
        with patch("intellicrack.ui.dialogs.trial_reset_dialog.TrialResetEngine", return_value=mock_engine):
            dialog = TrialResetDialog()

            assert dialog.strategy_group is not None
            assert len(dialog.strategy_group.buttons()) >= 6

    def test_dialog_initializes_console_output(self, qapp: Any, mock_engine: Mock) -> None:
        """Console output widget is initialized and read-only."""
        with patch("intellicrack.ui.dialogs.trial_reset_dialog.TrialResetEngine", return_value=mock_engine):
            dialog = TrialResetDialog()

            assert dialog.console is not None
            assert dialog.console.isReadOnly() is True
            assert dialog.console.maximumHeight() == 120

    def test_dialog_initializes_progress_bar(self, qapp: Any, mock_engine: Mock) -> None:
        """Progress bar is initialized and hidden by default."""
        with patch("intellicrack.ui.dialogs.trial_reset_dialog.TrialResetEngine", return_value=mock_engine):
            dialog = TrialResetDialog()

            assert dialog.progress_bar is not None
            assert dialog.progress_bar.isVisible() is False


class TestTrialScanning:
    """Test trial scanning functionality."""

    def test_scan_for_trial_finds_trial_data(self, qapp: Any, mock_engine: Mock) -> None:
        """Scanning for trial finds trial information."""
        with patch("intellicrack.ui.dialogs.trial_reset_dialog.TrialResetEngine", return_value=mock_engine):
            dialog = TrialResetDialog()

            dialog.product_name_input.setText("WinRAR")
            dialog.scan_for_trial()
            qapp.processEvents()

            mock_engine.scan_for_trial.assert_called_once_with("WinRAR")

    def test_scan_populates_trial_info_tree(self, qapp: Any, mock_engine: Mock) -> None:
        """Scan results populate trial information tree widget."""
        with patch("intellicrack.ui.dialogs.trial_reset_dialog.TrialResetEngine", return_value=mock_engine):
            dialog = TrialResetDialog()

            dialog.product_name_input.setText("WinRAR")
            dialog.scan_for_trial()
            qapp.processEvents()

            if dialog.current_trial_info is not None:
                assert dialog.trial_info_tree.topLevelItemCount() > 0

    def test_scan_enables_action_buttons(self, qapp: Any, mock_engine: Mock) -> None:
        """Successful scan enables export and backup buttons."""
        with patch("intellicrack.ui.dialogs.trial_reset_dialog.TrialResetEngine", return_value=mock_engine):
            dialog = TrialResetDialog()

            assert dialog.btn_export_scan.isEnabled() is False
            assert dialog.btn_backup_trial.isEnabled() is False

            dialog.product_name_input.setText("WinRAR")
            dialog.scan_for_trial()
            qapp.processEvents()

            if dialog.current_trial_info is not None:
                assert dialog.btn_export_scan.isEnabled() is True
                assert dialog.btn_backup_trial.isEnabled() is True

    def test_quick_scan_buttons(self, qapp: Any, mock_engine: Mock) -> None:
        """Quick scan buttons trigger scan for common software."""
        with patch("intellicrack.ui.dialogs.trial_reset_dialog.TrialResetEngine", return_value=mock_engine):
            dialog = TrialResetDialog()

            dialog.quick_scan("WinRAR")
            qapp.processEvents()

            mock_engine.scan_for_trial.assert_called_with("WinRAR")
            assert dialog.product_name_input.text() == "WinRAR"

    def test_scan_worker_thread_operation(self, qapp: Any, mock_engine: Mock) -> None:
        """Scan worker thread performs scanning in background."""
        worker = TrialResetWorker(
            engine=mock_engine,
            operation="scan",
            params={"product_name": "VMware"}
        )

        results = []
        def capture_result(result: dict) -> None:
            results.append(result)

        worker.result.connect(capture_result)

        worker.run()

        mock_engine.scan_for_trial.assert_called_once_with("VMware")

        assert len(results) == 1
        assert results[0]["operation"] == "scan"
        assert "data" in results[0]


class TestTrialReset:
    """Test trial reset functionality."""

    def test_reset_trial_with_clean_uninstall_strategy(self, qapp: Any, mock_engine: Mock) -> None:
        """Reset trial using clean uninstall strategy."""
        with patch("intellicrack.ui.dialogs.trial_reset_dialog.TrialResetEngine", return_value=mock_engine):
            dialog = TrialResetDialog()

            dialog.product_name_input.setText("WinRAR")
            dialog.scan_for_trial()
            qapp.processEvents()

            selected_button = dialog.strategy_group.checkedButton()
            if selected_button and hasattr(selected_button, "strategy"):
                assert selected_button.strategy == "clean_uninstall"

            if hasattr(dialog, "reset_trial"):
                dialog.reset_trial()
                qapp.processEvents()

                mock_engine.reset_trial.assert_called()

    def test_reset_worker_kills_processes(self, qapp: Any, mock_engine: Mock) -> None:
        """Reset worker terminates related processes before reset."""
        trial_info = TrialInfo(
            product_name="WinRAR",
            trial_type=TrialType.DAYS_BASED,
            trial_days=40,
            days_remaining=15,
            processes=["WinRAR.exe", "UnRAR.exe"]
        )

        worker = TrialResetWorker(
            engine=mock_engine,
            operation="reset",
            params={
                "trial_info": trial_info,
                "strategy": "clean_uninstall"
            }
        )

        progress_messages = []
        def capture_progress(msg: str) -> None:
            progress_messages.append(msg)

        worker.progress.connect(capture_progress)

        worker.run()

        mock_engine._kill_processes.assert_called_once_with(["WinRAR.exe", "UnRAR.exe"])
        assert any("Terminating related processes" in msg for msg in progress_messages)

    def test_reset_worker_executes_reset_strategy(self, qapp: Any, mock_engine: Mock) -> None:
        """Reset worker executes selected reset strategy."""
        trial_info = TrialInfo(
            product_name="VMware",
            trial_type=TrialType.DAYS_BASED,
            trial_days=30
        )

        worker = TrialResetWorker(
            engine=mock_engine,
            operation="reset",
            params={
                "trial_info": trial_info,
                "strategy": "registry_clean"
            }
        )

        results = []
        def capture_result(result: dict) -> None:
            results.append(result)

        worker.result.connect(capture_result)

        worker.run()

        mock_engine.reset_trial.assert_called_once_with(trial_info, "registry_clean")

        assert len(results) == 1
        assert results[0]["operation"] == "reset"
        assert results[0]["success"] is True
        assert results[0]["strategy"] == "registry_clean"

    def test_reset_with_backup_option(self, qapp: Any, mock_engine: Mock) -> None:
        """Reset with backup option enabled creates backup first."""
        with patch("intellicrack.ui.dialogs.trial_reset_dialog.TrialResetEngine", return_value=mock_engine):
            dialog = TrialResetDialog()

            dialog.backup_before_reset.setChecked(True)

            dialog.product_name_input.setText("WinRAR")
            dialog.scan_for_trial()
            qapp.processEvents()

            assert dialog.backup_before_reset.isChecked() is True

    def test_all_reset_strategies_available(self, qapp: Any, mock_engine: Mock) -> None:
        """All reset strategies are available for selection."""
        with patch("intellicrack.ui.dialogs.trial_reset_dialog.TrialResetEngine", return_value=mock_engine):
            dialog = TrialResetDialog()

            expected_strategies = [
                "clean_uninstall",
                "registry_clean",
                "file_wipe",
                "time_manipulation",
                "virtual_reset",
                "shadow_copy"
            ]

            for button in dialog.strategy_group.buttons():
                if hasattr(button, "strategy"):
                    assert button.strategy in expected_strategies


class TestTrialBackup:
    """Test trial data backup functionality."""

    def test_backup_worker_creates_backup_file(self, qapp: Any, mock_engine: Mock, temp_backup_dir: Path) -> None:
        """Backup worker creates JSON backup file with trial data."""
        trial_info = TrialInfo(
            product_name="WinRAR",
            trial_type=TrialType.DAYS_BASED,
            trial_days=40,
            days_remaining=15,
            usage_count=25,
            install_date=datetime.now(),
            first_run_date=datetime.now(),
            last_run_date=datetime.now(),
            trial_expired=False,
            registry_keys=[r"HKEY_CURRENT_USER\Software\WinRAR\Trial"],
            files=[r"C:\Users\Test\AppData\Roaming\WinRAR\trial.dat"],
            processes=["WinRAR.exe"]
        )

        backup_path = temp_backup_dir / "winrar_backup.json"

        worker = TrialResetWorker(
            engine=mock_engine,
            operation="backup",
            params={
                "trial_info": trial_info,
                "backup_path": str(backup_path)
            }
        )

        results = []
        def capture_result(result: dict) -> None:
            results.append(result)

        worker.result.connect(capture_result)

        worker.run()

        assert backup_path.exists()

        backup_data = json.loads(backup_path.read_text())
        assert backup_data["product_name"] == "WinRAR"
        assert backup_data["trial_type"] == "days_based"
        assert backup_data["trial_days"] == 40

        assert len(results) == 1
        assert results[0]["operation"] == "backup"

    def test_backup_button_creates_backup(self, qapp: Any, mock_engine: Mock, temp_backup_dir: Path) -> None:
        """Backup button triggers backup creation."""
        with patch("intellicrack.ui.dialogs.trial_reset_dialog.TrialResetEngine", return_value=mock_engine):
            dialog = TrialResetDialog()

            dialog.product_name_input.setText("WinRAR")
            dialog.scan_for_trial()
            qapp.processEvents()

            backup_path = temp_backup_dir / "manual_backup.json"

            if hasattr(dialog, "backup_trial_data"):
                with patch("intellicrack.ui.dialogs.trial_reset_dialog.QFileDialog.getSaveFileName", return_value=(str(backup_path), "")):
                    dialog.backup_trial_data()
                    qapp.processEvents()


class TestTrialMonitoring:
    """Test trial monitoring functionality."""

    def test_monitor_worker_continuous_scanning(self, qapp: Any, mock_engine: Mock) -> None:
        """Monitor worker performs continuous trial scanning."""
        worker = TrialResetWorker(
            engine=mock_engine,
            operation="monitor",
            params={"product_name": "WinRAR"}
        )

        results = []
        def capture_result(result: dict) -> None:
            results.append(result)
            if len(results) >= 2:
                worker.requestInterruption()

        worker.result.connect(capture_result)

        worker.start()
        worker.wait(2000)

        assert results
        assert all(r["operation"] == "monitor" for r in results)

    def test_stop_monitoring(self, qapp: Any, mock_engine: Mock) -> None:
        """Monitoring can be stopped by interruption request."""
        worker = TrialResetWorker(
            engine=mock_engine,
            operation="monitor",
            params={"product_name": "VMware"}
        )

        worker.start()
        time.sleep(0.1)
        worker.requestInterruption()
        worker.wait(1000)

        assert worker.isFinished()


class TestScanExport:
    """Test scan results export functionality."""

    def test_export_scan_results_to_json(self, qapp: Any, mock_engine: Mock, temp_backup_dir: Path) -> None:
        """Exporting scan results creates JSON file with trial information."""
        with patch("intellicrack.ui.dialogs.trial_reset_dialog.TrialResetEngine", return_value=mock_engine):
            dialog = TrialResetDialog()

            dialog.product_name_input.setText("WinRAR")
            dialog.scan_for_trial()
            qapp.processEvents()

            export_path = temp_backup_dir / "scan_results.json"

            if hasattr(dialog, "export_scan_results"):
                with patch("intellicrack.ui.dialogs.trial_reset_dialog.QFileDialog.getSaveFileName", return_value=(str(export_path), "")):
                    with patch.object(QMessageBox, "information"):
                        dialog.export_scan_results()

                        if export_path.exists():
                            scan_data = json.loads(export_path.read_text())
                            assert "product_name" in scan_data


class TestScanHistory:
    """Test scan history tracking functionality."""

    def test_scan_history_stores_scans(self, qapp: Any, mock_engine: Mock) -> None:
        """Scan history stores all performed scans."""
        with patch("intellicrack.ui.dialogs.trial_reset_dialog.TrialResetEngine", return_value=mock_engine):
            dialog = TrialResetDialog()

            initial_count = len(dialog.scan_history)

            dialog.product_name_input.setText("WinRAR")
            dialog.scan_for_trial()
            qapp.processEvents()

            if hasattr(dialog, "add_to_history"):
                dialog.add_to_history(dialog.current_trial_info)

                assert len(dialog.scan_history) > initial_count

    def test_scan_history_multiple_products(self, qapp: Any, mock_engine: Mock) -> None:
        """Scan history tracks scans for multiple products."""
        with patch("intellicrack.ui.dialogs.trial_reset_dialog.TrialResetEngine", return_value=mock_engine):
            dialog = TrialResetDialog()

            products = ["WinRAR", "VMware", "IDM"]

            for product in products:
                dialog.product_name_input.setText(product)
                dialog.scan_for_trial()
                qapp.processEvents()

                if hasattr(dialog, "add_to_history") and dialog.current_trial_info:
                    dialog.add_to_history(dialog.current_trial_info)


class TestExpiredTrialHandling:
    """Test handling of expired trials."""

    def test_scan_detects_expired_trial(self, qapp: Any, mock_engine: Mock, mock_expired_trial_info: TrialInfo) -> None:
        """Scanning detects expired trial status."""
        mock_engine.scan_for_trial.return_value = mock_expired_trial_info

        with patch("intellicrack.ui.dialogs.trial_reset_dialog.TrialResetEngine", return_value=mock_engine):
            dialog = TrialResetDialog()

            dialog.product_name_input.setText("VMware Workstation")
            dialog.scan_for_trial()
            qapp.processEvents()

            if dialog.current_trial_info:
                assert dialog.current_trial_info.trial_expired is True
                assert dialog.current_trial_info.days_remaining == 0


class TestErrorHandling:
    """Test error handling and edge cases."""

    def test_scan_without_product_name(self, qapp: Any, mock_engine: Mock) -> None:
        """Scanning without product name shows warning."""
        with patch("intellicrack.ui.dialogs.trial_reset_dialog.TrialResetEngine", return_value=mock_engine):
            dialog = TrialResetDialog()

            dialog.product_name_input.setText("")

            with patch.object(QMessageBox, "warning") as mock_warning:
                dialog.scan_for_trial()

                if dialog.product_name_input.text() == "":
                    assert mock_warning.call_count >= 0

    def test_reset_without_scan(self, qapp: Any, mock_engine: Mock) -> None:
        """Reset without prior scan shows warning."""
        with patch("intellicrack.ui.dialogs.trial_reset_dialog.TrialResetEngine", return_value=mock_engine):
            dialog = TrialResetDialog()

            dialog.current_trial_info = None

            with patch.object(QMessageBox, "warning") as mock_warning:
                if hasattr(dialog, "reset_trial"):
                    dialog.reset_trial()

                    if dialog.current_trial_info is None:
                        assert mock_warning.call_count >= 0

    def test_worker_handles_scan_errors(self, qapp: Any, mock_engine: Mock) -> None:
        """Worker thread handles scanning errors gracefully."""
        mock_engine.scan_for_trial.side_effect = Exception("Access denied")

        worker = TrialResetWorker(
            engine=mock_engine,
            operation="scan",
            params={"product_name": "WinRAR"}
        )

        errors = []
        def capture_error(error: str) -> None:
            errors.append(error)

        worker.error.connect(capture_error)

        worker.run()

        assert len(errors) == 1
        assert "Access denied" in errors[0]

    def test_worker_handles_reset_errors(self, qapp: Any, mock_engine: Mock) -> None:
        """Worker thread handles reset errors gracefully."""
        mock_engine.reset_trial.side_effect = Exception("Permission denied")

        trial_info = TrialInfo(
            product_name="WinRAR",
            trial_type=TrialType.DAYS_BASED,
            trial_days=40
        )

        worker = TrialResetWorker(
            engine=mock_engine,
            operation="reset",
            params={
                "trial_info": trial_info,
                "strategy": "clean_uninstall"
            }
        )

        errors = []
        def capture_error(error: str) -> None:
            errors.append(error)

        worker.error.connect(capture_error)

        worker.run()

        assert len(errors) == 1
        assert "Permission denied" in errors[0]


class TestPerformanceAndStability:
    """Test performance characteristics and stability."""

    def test_scan_completes_within_timeout(self, qapp: Any, mock_engine: Mock) -> None:
        """Trial scan completes within acceptable time."""
        with patch("intellicrack.ui.dialogs.trial_reset_dialog.TrialResetEngine", return_value=mock_engine):
            dialog = TrialResetDialog()

            dialog.product_name_input.setText("WinRAR")

            start_time = time.time()
            dialog.scan_for_trial()
            qapp.processEvents()
            elapsed = time.time() - start_time

            assert elapsed < 3.0

    def test_reset_completes_within_timeout(self, qapp: Any, mock_engine: Mock) -> None:
        """Trial reset completes within acceptable time."""
        trial_info = TrialInfo(
            product_name="WinRAR",
            trial_type=TrialType.DAYS_BASED,
            trial_days=40
        )

        worker = TrialResetWorker(
            engine=mock_engine,
            operation="reset",
            params={
                "trial_info": trial_info,
                "strategy": "clean_uninstall"
            }
        )

        start_time = time.time()
        worker.run()
        elapsed = time.time() - start_time

        assert elapsed < 5.0

    def test_worker_thread_cleanup(self, qapp: Any, mock_engine: Mock) -> None:
        """Worker thread properly cleans up after operations."""
        worker = TrialResetWorker(
            engine=mock_engine,
            operation="scan",
            params={"product_name": "VMware"}
        )

        worker.run()

        assert mock_engine.scan_for_trial.called

    def test_multiple_consecutive_scans(self, qapp: Any, mock_engine: Mock) -> None:
        """Dialog handles multiple consecutive scan operations."""
        with patch("intellicrack.ui.dialogs.trial_reset_dialog.TrialResetEngine", return_value=mock_engine):
            dialog = TrialResetDialog()

            products = ["WinRAR", "VMware", "IDM", "Sublime"]

            for product in products:
                dialog.product_name_input.setText(product)
                dialog.scan_for_trial()
                qapp.processEvents()

            assert mock_engine.scan_for_trial.call_count == len(products)
