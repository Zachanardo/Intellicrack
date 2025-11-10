"""Test script to verify CPU and GPU metrics are updating live."""

import sys
import time
from pathlib import Path

# Add intellicrack to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from intellicrack.handlers.pyqt6_handler import QApplication, QMainWindow, QVBoxLayout, QWidget, QHBoxLayout
from intellicrack.ui.widgets.cpu_status_widget import CPUStatusWidget
from intellicrack.ui.widgets.gpu_status_widget import GPUStatusWidget


def test_live_metrics():
    """Test that CPU and GPU metrics update live."""
    print("=" * 60)
    print("Testing Live CPU/GPU Metrics")
    print("=" * 60)

    # Create Qt application
    app = QApplication(sys.argv)

    # Create main window
    main_window = QMainWindow()
    main_window.setWindowTitle("Live Metrics Test")
    main_window.resize(800, 900)

    # Create central widget with layout
    central_widget = QWidget()
    layout = QHBoxLayout(central_widget)

    # Create CPU widget
    print("\n1. Creating CPU status widget...")
    cpu_widget = CPUStatusWidget()
    layout.addWidget(cpu_widget)

    # Create GPU widget
    print("2. Creating GPU status widget...")
    gpu_widget = GPUStatusWidget()
    layout.addWidget(gpu_widget)

    main_window.setCentralWidget(central_widget)
    main_window.show()

    # Test data collection
    print("\n3. Testing initial data collection...")

    # Check CPU widget has monitoring thread
    if hasattr(cpu_widget, 'monitor_thread') and cpu_widget.monitor_thread.isRunning():
        print("OK CPU monitoring thread is running")
    else:
        print("FAIL CPU monitoring thread not running")

    # Check GPU widget has monitoring thread
    if hasattr(gpu_widget, 'monitor_thread') and gpu_widget.monitor_thread.isRunning():
        print("OK GPU monitoring thread is running")
    else:
        print("FAIL GPU monitoring thread not running")

    # Check for scroll areas
    print("\n4. Checking for scroll areas...")

    cpu_has_scroll = any(child.__class__.__name__ == "QScrollArea" for child in cpu_widget.children())
    gpu_has_scroll = any(child.__class__.__name__ == "QScrollArea" for child in gpu_widget.children())

    if cpu_has_scroll:
        print("OK CPU widget has scroll area")
    else:
        print("FAIL CPU widget missing scroll area")

    if gpu_has_scroll:
        print("OK GPU widget has scroll area")
    else:
        print("FAIL GPU widget missing scroll area")

    # Check GPU dropdown
    print("\n5. Checking GPU dropdown...")
    if hasattr(gpu_widget, 'gpu_combo'):
        count = gpu_widget.gpu_combo.count()
        print(f"OK GPU dropdown has {count} items")
        for i in range(count):
            print(f"   - {gpu_widget.gpu_combo.itemText(i)}")
    else:
        print("FAIL GPU dropdown not found")

    # Monitor for updates
    print("\n6. Monitoring for live updates...")
    print("   Watch the window for 10 seconds to verify:")
    print("   - CPU utilization changes")
    print("   - CPU per-core usage updates")
    print("   - GPU utilization changes (if GPU detected)")
    print("   - Memory usage updates")
    print("   - Temperature readings change")
    print("   - Process list updates")

    # Create timer to check for updates
    from intellicrack.handlers.pyqt6_handler import QTimer

    update_count = [0, 0]  # CPU updates, GPU updates
    last_cpu_value = [0]
    last_gpu_value = [0]

    def check_cpu_updates():
        """Check if CPU values are updating."""
        if hasattr(cpu_widget, 'total_cpu_bar'):
            current = cpu_widget.total_cpu_bar.value()
            if current != last_cpu_value[0]:
                update_count[0] += 1
                last_cpu_value[0] = current
                print(f"   CPU updated: {current}%")

    def check_gpu_updates():
        """Check if GPU values are updating."""
        if hasattr(gpu_widget, 'utilization_bar'):
            current = gpu_widget.utilization_bar.value()
            if current != last_gpu_value[0]:
                update_count[1] += 1
                last_gpu_value[0] = current
                print(f"   GPU updated: {current}%")

    # Set up timer to check for updates
    check_timer = QTimer()
    check_timer.timeout.connect(check_cpu_updates)
    check_timer.timeout.connect(check_gpu_updates)
    check_timer.start(500)  # Check every 500ms

    # Stop checking after 10 seconds
    QTimer.singleShot(10000, check_timer.stop)
    QTimer.singleShot(10500, lambda: print_results(update_count))

    def print_results(counts):
        """Print test results."""
        print("\n" + "=" * 60)
        print("Test Results:")
        print("=" * 60)
        if counts[0] > 5:
            print(f"OK CPU metrics updating live ({counts[0]} updates in 10s)")
        else:
            print(f"FAIL CPU metrics not updating properly ({counts[0]} updates in 10s)")

        if counts[1] > 5:
            print(f"OK GPU metrics updating live ({counts[1]} updates in 10s)")
        else:
            print(f"WARNING  GPU metrics limited updates ({counts[1]} updates in 10s)")
            print("   (This is normal if no dedicated GPU is present)")

        print("\nPlease verify visually that:")
        print("- All values are realistic (not all zeros)")
        print("- Scroll areas work for both widgets")
        print("- GPU dropdown maintains selection")
        print("=" * 60)

    # Run the application
    return app.exec()


if __name__ == "__main__":
    try:
        sys.exit(test_live_metrics())
    except Exception as e:
        print(f"\nFAIL Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
