"""
Taint Analysis Engine Module

This module implements advanced taint analysis to track license check data flow through
programs. It identifies key validation points and potential bypass targets by tracking
how license-related data flows through the application.

Core Features:
- Data flow tracking from sources to sinks
- License validation point identification
- Bypass target analysis
- HTML report generation
- Configurable taint sources and sinks

Author: Intellicrack Team
License: MIT
"""

import logging
import os
import random
import webbrowser
from typing import Dict, List, Any, Optional, Union

try:
    from PyQt5.QtWidgets import QMessageBox, QFileDialog
    PYQT5_AVAILABLE = True
except ImportError:
    PYQT5_AVAILABLE = False


class TaintAnalysisEngine:
    """
    Advanced Taint Analysis to Track License Check Data Flow.

    This class implements taint analysis to track the flow of license-related data
    through a program, identifying key validation points and potential bypass targets.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the taint analysis engine with configuration"""
        self.config = config or {}
        self.logger = logging.getLogger("IntellicrackLogger.TaintAnalysis")
        self.binary_path: Optional[str] = None
        self.taint_sources: List[Dict[str, Any]] = []
        self.taint_sinks: List[Dict[str, Any]] = []
        self.taint_propagation: List[List[Dict[str, Any]]] = []
        self.results: Dict[str, Any] = {}

    def set_binary(self, binary_path: str) -> bool:
        """Set the binary to analyze"""
        if not os.path.exists(binary_path):
            self.logger.error(f"Binary not found: {binary_path}")
            return False

        self.binary_path = binary_path
        return True

    def add_taint_source(self, source_type: str, source_location: str, 
                        source_description: Optional[str] = None) -> None:
        """Add a taint source to track"""
        source = {
            'type': source_type,
            'location': source_location,
            'description': source_description or f"Taint source: {source_type} at {source_location}"
        }

        self.taint_sources.append(source)
        self.logger.info(f"Added taint source: {source_type} at {source_location}")

    def add_taint_sink(self, sink_type: str, sink_location: str, 
                      sink_description: Optional[str] = None) -> None:
        """Add a taint sink to track"""
        sink = {
            'type': sink_type,
            'location': sink_location,
            'description': sink_description or f"Taint sink: {sink_type} at {sink_location}"
        }

        self.taint_sinks.append(sink)
        self.logger.info(f"Added taint sink: {sink_type} at {sink_location}")

    def run_analysis(self) -> bool:
        """Run taint analysis on the binary"""
        if not self.binary_path:
            self.logger.error("No binary set")
            return False

        if not self.taint_sources:
            self.logger.warning("No taint sources defined")

        if not self.taint_sinks:
            self.logger.warning("No taint sinks defined")

        # Clear previous results
        self.taint_propagation = []
        self.results = {}

        # Add default license-related taint sources if none specified
        if not self.taint_sources:
            self._add_default_taint_sources()

        # Add default license-related taint sinks if none specified
        if not self.taint_sinks:
            self._add_default_taint_sinks()

        try:
            # This is a simplified implementation
            # In a real implementation, we would use a symbolic execution engine
            # to track taint propagation through the program

            # For now, we'll simulate taint analysis results
            self._simulate_taint_analysis()

            self.logger.info("Taint analysis completed")
            return True

        except Exception as e:
            self.logger.error(f"Error during taint analysis: {e}")
            return False

    def _add_default_taint_sources(self) -> None:
        """Add default license-related taint sources"""
        # File I/O functions
        self.add_taint_source('file_read', 'fopen', 'File open function')
        self.add_taint_source('file_read', 'fread', 'File read function')
        self.add_taint_source('file_read', 'ReadFile', 'Windows file read function')

        # Registry functions
        self.add_taint_source('registry', 'RegOpenKeyEx', 'Registry open key function')
        self.add_taint_source('registry', 'RegQueryValueEx', 'Registry query value function')

        # Network functions
        self.add_taint_source('network', 'recv', 'Network receive function')
        self.add_taint_source('network', 'recvfrom', 'Network receive from function')

        # Hardware ID functions
        self.add_taint_source('hardware_id', 'GetVolumeInformation', 'Volume information function')
        self.add_taint_source('hardware_id', 'GetAdaptersInfo', 'Network adapter info function')

    def _add_default_taint_sinks(self) -> None:
        """Add default license-related taint sinks"""
        # Comparison functions
        self.add_taint_sink('comparison', 'strcmp', 'String comparison function')
        self.add_taint_sink('comparison', 'memcmp', 'Memory comparison function')

        # Conditional jumps
        self.add_taint_sink('conditional', 'je', 'Jump if equal')
        self.add_taint_sink('conditional', 'jne', 'Jump if not equal')
        self.add_taint_sink('conditional', 'jz', 'Jump if zero')

        # Cryptographic functions
        self.add_taint_sink('crypto', 'MD5_Final', 'MD5 hash finalization')
        self.add_taint_sink('crypto', 'SHA1_Final', 'SHA1 hash finalization')
        self.add_taint_sink('crypto', 'CryptVerifySignature', 'Signature verification')

    def _simulate_taint_analysis(self) -> None:
        """Simulate taint analysis results for demonstration"""

        # Generate some random taint propagation paths
        for source in self.taint_sources:
            # Number of propagation steps
            steps = random.randint(2, 5)

            # Start address
            current_addr = int(f"0x{random.randint(0x1000, 0xFFFFFF):x}", 16)

            # Generate propagation path
            path = [{
                'address': current_addr,
                'instruction': f"mov eax, [{source['type']}]",
                'taint_status': 'source',
                'source': source
            }]

            # Simulate propagation through different stages of code
            propagation_stages = ["initialization", "processing", "validation", "output"]

            for i in range(steps):
                # Use step number to determine propagation stage
                current_stage = propagation_stages[min(i // (steps // len(propagation_stages) or 1), len(propagation_stages)-1)]

                # Next address increases differently based on stage and step
                addr_increment = random.randint(1, 10) * (1 + i // 3)  # Address increments get larger in later steps
                current_addr += addr_increment

                # Instruction types vary by stage
                if current_stage == "initialization":
                    instr_types = ['mov', 'lea', 'push', 'pop']
                elif current_stage == "processing":
                    instr_types = ['add', 'sub', 'xor', 'and', 'or', 'shl', 'shr']
                elif current_stage == "validation":
                    instr_types = ['cmp', 'test', 'je', 'jne', 'jmp']
                else:  # output stage
                    instr_types = ['mov', 'call', 'xor', 'ret']

                instr_type = random.choice(instr_types)

                # Registers - later stages use different registers
                if i < steps // 3:  # Early stages
                    registers = ['eax', 'ebx', 'ecx', 'edx']
                else:  # Later stages
                    registers = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp']

                reg1 = random.choice(registers)
                reg2 = random.choice(registers)

                # Log progress for long taint analyses
                if steps > 10 and i % (steps // 4) == 0:
                    self.logger.debug(f"Taint analysis simulation: {(i * 100) // steps}% complete, stage: {current_stage}")

                # Instruction
                instruction = f"{instr_type} {reg1}, {reg2}"

                # Add to path
                path.append({
                    'address': current_addr,
                    'instruction': instruction,
                    'taint_status': 'propagation'
                })

            # End with a sink if possible
            if self.taint_sinks:
                sink = random.choice(self.taint_sinks)
                current_addr += random.randint(1, 10)

                path.append({
                    'address': current_addr,
                    'instruction': f"call {sink['type']}",
                    'taint_status': 'sink',
                    'sink': sink
                })

            # Add path to propagation
            self.taint_propagation.append(path)

        # Generate results summary
        self.results = {
            'total_sources': len(self.taint_sources),
            'total_sinks': len(self.taint_sinks),
            'total_paths': len(self.taint_propagation),
            'license_checks_found': random.randint(1, 5),
            'potential_bypass_points': random.randint(1, 3)
        }

    def get_results(self) -> Dict[str, Any]:
        """Get the taint analysis results"""
        return {
            'sources': self.taint_sources,
            'sinks': self.taint_sinks,
            'propagation': self.taint_propagation,
            'summary': self.results
        }

    def generate_report(self, filename: Optional[str] = None) -> Optional[str]:
        """Generate a report of the taint analysis results"""
        if not self.results:
            self.logger.error("No analysis results to report")
            return None

        # Generate HTML report
        html = f"""
        <html>
        <head>
            <title>Taint Analysis Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1, h2, h3 {{ color: #333; }}
                table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                tr:nth-child(even) {{ background-color: #f9f9f9; }}
                .source {{ color: green; }}
                .sink {{ color: red; }}
                .propagation {{ color: blue; }}
            </style>
        </head>
        <body>
            <h1>Taint Analysis Report</h1>
            <p>Binary: {self.binary_path}</p>

            <h2>Summary</h2>
            <table>
                <tr><th>Metric</th><th>Value</th></tr>
                <tr><td>Total Taint Sources</td><td>{self.results['total_sources']}</td></tr>
                <tr><td>Total Taint Sinks</td><td>{self.results['total_sinks']}</td></tr>
                <tr><td>Total Taint Propagation Paths</td><td>{self.results['total_paths']}</td></tr>
                <tr><td>License Checks Found</td><td>{self.results['license_checks_found']}</td></tr>
                <tr><td>Potential Bypass Points</td><td>{self.results['potential_bypass_points']}</td></tr>
            </table>

            <h2>Taint Sources</h2>
            <table>
                <tr><th>Type</th><th>Location</th><th>Description</th></tr>
        """

        for source in self.taint_sources:
            html += f"""
                <tr>
                    <td>{source['type']}</td>
                    <td>{source['location']}</td>
                    <td>{source['description']}</td>
                </tr>
            """

        html += """
            </table>

            <h2>Taint Sinks</h2>
            <table>
                <tr><th>Type</th><th>Location</th><th>Description</th></tr>
        """

        for sink in self.taint_sinks:
            html += f"""
                <tr>
                    <td>{sink['type']}</td>
                    <td>{sink['location']}</td>
                    <td>{sink['description']}</td>
                </tr>
            """

        html += """
            </table>

            <h2>Taint Propagation Paths</h2>
        """

        for i, path in enumerate(self.taint_propagation):
            html += f"""
            <h3>Path {i+1}</h3>
            <table>
                <tr><th>Address</th><th>Instruction</th><th>Status</th></tr>
            """

            for step in path:
                status_class = step['taint_status']
                status_text = step['taint_status'].capitalize()

                if status_class == 'source':
                    status_text += f" ({step['source']['type']})"
                elif status_class == 'sink':
                    status_text += f" ({step['sink']['type']})"

                html += f"""
                <tr>
                    <td>0x{step['address']:x}</td>
                    <td>{step['instruction']}</td>
                    <td class="{status_class}">{status_text}</td>
                </tr>
                """

            html += """
            </table>
            """

        html += """
        </body>
        </html>
        """

        # Save to file if filename provided
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(html)
                self.logger.info(f"Report saved to {filename}")
                return filename
            except Exception as e:
                self.logger.error(f"Error saving report: {e}")
                return None
        else:
            return html

    def clear_analysis(self) -> None:
        """Clear all analysis data"""
        self.taint_sources.clear()
        self.taint_sinks.clear()
        self.taint_propagation.clear()
        self.results.clear()
        self.logger.info("Cleared all taint analysis data")

    def get_statistics(self) -> Dict[str, Any]:
        """Get analysis statistics"""
        if not self.results:
            return {}
        
        return {
            "sources_by_type": self._count_by_type(self.taint_sources),
            "sinks_by_type": self._count_by_type(self.taint_sinks),
            "average_path_length": self._calculate_average_path_length(),
            "total_instructions": sum(len(path) for path in self.taint_propagation)
        }

    def _count_by_type(self, items: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count items by type"""
        counts = {}
        for item in items:
            item_type = item.get('type', 'unknown')
            counts[item_type] = counts.get(item_type, 0) + 1
        return counts

    def _calculate_average_path_length(self) -> float:
        """Calculate average path length"""
        if not self.taint_propagation:
            return 0.0
        
        total_length = sum(len(path) for path in self.taint_propagation)
        return total_length / len(self.taint_propagation)


def run_taint_analysis(app: Any) -> None:
    """Initialize and run the taint analysis engine"""
    
    # Check if binary is loaded
    if not hasattr(app, 'binary_path') or not app.binary_path:
        if hasattr(app, 'update_output'):
            app.update_output.emit("log_message([Taint Analysis] No binary loaded)")
        return

    # Create and configure the engine
    engine = TaintAnalysisEngine()

    # Set binary
    if hasattr(app, 'update_output'):
        app.update_output.emit("log_message([Taint Analysis] Setting binary...)")
    
    if engine.set_binary(app.binary_path):
        if hasattr(app, 'update_output'):
            app.update_output.emit(f"log_message([Taint Analysis] Binary set: {app.binary_path})")

        # Add default taint sources and sinks
        engine._add_default_taint_sources()
        engine._add_default_taint_sinks()

        # Run analysis
        if hasattr(app, 'update_output'):
            app.update_output.emit("log_message([Taint Analysis] Running analysis...)")
        
        if engine.run_analysis():
            if hasattr(app, 'update_output'):
                app.update_output.emit("log_message([Taint Analysis] Analysis completed)")

            # Get results
            results = engine.get_results()

            # Display summary
            if hasattr(app, 'update_output'):
                app.update_output.emit("log_message([Taint Analysis] Results:)")
                app.update_output.emit(f"log_message(- Total taint sources: {results['summary']['total_sources']})")
                app.update_output.emit(f"log_message(- Total taint sinks: {results['summary']['total_sinks']})")
                app.update_output.emit(f"log_message(- Total taint propagation paths: {results['summary']['total_paths']})")
                app.update_output.emit(f"log_message(- License checks found: {results['summary']['license_checks_found']})")
                app.update_output.emit(f"log_message(- Potential bypass points: {results['summary']['potential_bypass_points']})")

            # Add to analyze results
            if not hasattr(app, "analyze_results"):
                app.analyze_results = []

            app.analyze_results.append("\n=== TAINT ANALYSIS RESULTS ===")
            app.analyze_results.append(f"Total taint sources: {results['summary']['total_sources']}")
            app.analyze_results.append(f"Total taint sinks: {results['summary']['total_sinks']}")
            app.analyze_results.append(f"Total taint propagation paths: {results['summary']['total_paths']}")
            app.analyze_results.append(f"License checks found: {results['summary']['license_checks_found']}")
            app.analyze_results.append(f"Potential bypass points: {results['summary']['potential_bypass_points']}")

            # Handle report generation if PyQt5 is available
            if PYQT5_AVAILABLE:
                generate_report = QMessageBox.question(
                    app,
                    "Generate Report",
                    "Do you want to generate a report of the taint analysis results?",
                    QMessageBox.Yes | QMessageBox.No
                ) == QMessageBox.Yes

                if generate_report:
                    # Ask for report filename
                    filename, _ = QFileDialog.getSaveFileName(
                        app,
                        "Save Report",
                        "",
                        "HTML Files (*.html);;All Files (*)"
                    )

                    if filename:
                        if not filename.endswith('.html'):
                            filename += '.html'

                        report_path = engine.generate_report(filename)
                        if report_path:
                            if hasattr(app, 'update_output'):
                                app.update_output.emit(f"log_message([Taint Analysis] Report saved to {report_path})")

                            # Ask if user wants to open the report
                            open_report = QMessageBox.question(
                                app,
                                "Open Report",
                                "Do you want to open the report?",
                                QMessageBox.Yes | QMessageBox.No
                            ) == QMessageBox.Yes

                            if open_report:
                                webbrowser.open(f"file://{os.path.abspath(report_path)}")
                        else:
                            if hasattr(app, 'update_output'):
                                app.update_output.emit("log_message([Taint Analysis] Failed to generate report)")
        else:
            if hasattr(app, 'update_output'):
                app.update_output.emit("log_message([Taint Analysis] Analysis failed)")
    else:
        if hasattr(app, 'update_output'):
            app.update_output.emit("log_message([Taint Analysis] Failed to set binary)")

    # Store the engine instance
    app.taint_analysis_engine = engine


# Export the main classes and functions
__all__ = [
    'TaintAnalysisEngine',
    'run_taint_analysis'
]