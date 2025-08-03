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
Unit tests for the NetworkTrafficAnalyzer class.

Tests the network traffic capture and analysis functionality
of the Intellicrack framework.
"""

import os
import tempfile
import unittest
from unittest.mock import MagicMock, Mock, patch

# Try to import the module under test
try:
    from intellicrack.core.network.traffic_analyzer import NetworkTrafficAnalyzer
except ImportError:
    NetworkTrafficAnalyzer = None


class TestNetworkTrafficAnalyzer(unittest.TestCase):
    """Test cases for NetworkTrafficAnalyzer."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.capture_file = os.path.join(self.temp_dir, "test_capture.pcap")

        if NetworkTrafficAnalyzer:
            self.analyzer = NetworkTrafficAnalyzer()

    def tearDown(self):
        """Clean up test fixtures."""
        # Clean up temp files
        if os.path.exists(self.capture_file):
            os.remove(self.capture_file)
        if os.path.exists(self.temp_dir):
            os.rmdir(self.temp_dir)

    @unittest.skipIf(NetworkTrafficAnalyzer is None, "NetworkTrafficAnalyzer not available")
    def test_initialization(self):
        """Test analyzer initialization."""
        self.assertIsNotNone(self.analyzer)
        self.assertIsInstance(self.analyzer.captured_packets, list)
        self.assertIsInstance(self.analyzer.license_packets, list)

    @unittest.skipIf(NetworkTrafficAnalyzer is None, "NetworkTrafficAnalyzer not available")
    @patch('intellicrack.core.network.traffic_analyzer.pyshark')
    def test_start_capture_with_pyshark(self, mock_pyshark):
        """Test starting packet capture with pyshark."""
        # Mock pyshark capture
        mock_capture = MagicMock()
        mock_pyshark.LiveCapture.return_value = mock_capture

        # Start capture
        result = self.analyzer.start_capture(interface='eth0', use_pyshark=True)

        # Verify
        self.assertTrue(result)
        mock_pyshark.LiveCapture.assert_called_once()
        self.assertTrue(self.analyzer.is_capturing)

    @unittest.skipIf(NetworkTrafficAnalyzer is None, "NetworkTrafficAnalyzer not available")
    @patch('intellicrack.core.network.traffic_analyzer.scapy')
    def test_start_capture_with_scapy(self, mock_scapy):
        """Test starting packet capture with Scapy."""
        # Mock Scapy functions
        mock_scapy.sniff = MagicMock()

        # Start capture
        result = self.analyzer.start_capture(interface='eth0', use_pyshark=False)

        # Verify
        self.assertTrue(result)
        self.assertTrue(self.analyzer.is_capturing)

    @unittest.skipIf(NetworkTrafficAnalyzer is None, "NetworkTrafficAnalyzer not available")
    def test_stop_capture(self):
        """Test stopping packet capture."""
        # Set up analyzer as if capture is running
        self.analyzer.is_capturing = True
        self.analyzer.capture_thread = Mock()

        # Stop capture
        self.analyzer.stop_capture()

        # Verify
        self.assertFalse(self.analyzer.is_capturing)

    @unittest.skipIf(NetworkTrafficAnalyzer is None, "NetworkTrafficAnalyzer not available")
    def test_save_capture(self):
        """Test saving captured packets."""
        # Add some mock packets
        mock_packet = Mock()
        mock_packet.summary = lambda: "Test packet"
        self.analyzer.captured_packets = [mock_packet, mock_packet]

        # Save capture
        result = self.analyzer.save_capture(self.capture_file)

        # Verify
        self.assertTrue(result)

    @unittest.skipIf(NetworkTrafficAnalyzer is None, "NetworkTrafficAnalyzer not available")
    def test_analyze_license_traffic(self):
        """Test license traffic analysis."""
        # Create mock packets
        license_packet = Mock()
        license_packet.haslayer = lambda x: x == 'TCP'
        license_packet.__getitem__ = lambda self, x: Mock(dport=1947)  # HASP port

        normal_packet = Mock()
        normal_packet.haslayer = lambda x: x == 'TCP'
        normal_packet.__getitem__ = lambda self, x: Mock(dport=80)

        self.analyzer.captured_packets = [license_packet, normal_packet]

        # Analyze
        self.analyzer.analyze_license_traffic()

        # Verify
        self.assertEqual(len(self.analyzer.license_packets), 1)

    @unittest.skipIf(NetworkTrafficAnalyzer is None, "NetworkTrafficAnalyzer not available")
    def test_generate_report(self):
        """Test report generation."""
        # Add some analysis results
        self.analyzer.analysis_results = {
            'total_packets': 100,
            'license_packets': 10,
            'protocols': ['TCP', 'UDP'],
            'license_servers': ['192.168.1.100']
        }

        # Generate report
        report = self.analyzer.generate_report()

        # Verify
        self.assertIn('total_packets', report)
        self.assertIn('license_packets', report)
        self.assertEqual(report['total_packets'], 100)

    @unittest.skipIf(NetworkTrafficAnalyzer is None, "NetworkTrafficAnalyzer not available")
    def test_clear_capture(self):
        """Test clearing captured data."""
        # Add some data
        self.analyzer.captured_packets = [Mock(), Mock()]
        self.analyzer.license_packets = [Mock()]
        self.analyzer.analysis_results = {'test': 'data'}

        # Clear
        self.analyzer.clear_capture()

        # Verify
        self.assertEqual(len(self.analyzer.captured_packets), 0)
        self.assertEqual(len(self.analyzer.license_packets), 0)
        self.assertEqual(len(self.analyzer.analysis_results), 0)


if __name__ == '__main__':
    unittest.main()
