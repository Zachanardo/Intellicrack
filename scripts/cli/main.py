"""
Comprehensive Command-Line Interface for Intellicrack. 

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

#!/usr/bin/env python3
"""
Comprehensive Command-Line Interface for Intellicrack.

This enhanced CLI provides access to ALL feasible Intellicrack features,
enabling complete functionality without the GUI for testing, automation,
and server deployments.
"""

import os
import sys
import argparse
import json
import logging
import time

# Import optional performance/debugging modules
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    import tracemalloc
    import cProfile
    import pstats
    import io
    PROFILING_AVAILABLE = True
except ImportError:
    PROFILING_AVAILABLE = False

# Add parent directories to path for imports
script_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(script_dir, '..', '..'))
sys.path.insert(0, project_root)

try:
    # Core imports - essential for CLI
    from intellicrack.utils.binary_analysis import analyze_binary
    from intellicrack.utils.report_generator import generate_report
    from intellicrack.config import CONFIG

    # Import available runner functions
    from intellicrack.utils.runner_functions import (
        run_comprehensive_analysis,
        run_deep_license_analysis,
        run_symbolic_execution,
        run_taint_analysis,
        run_ghidra_analysis,
        run_radare2_analysis,
        run_frida_script
    )

    # Import additional runners from the correct location
    from intellicrack.utils.additional_runners import (
        run_detect_packing,
        run_vulnerability_scan,
        run_cfg_analysis,
        run_rop_gadget_finder,
        run_multi_format_analysis,
        run_section_analysis,
        run_import_export_analysis,
        run_weak_crypto_detection,
        run_comprehensive_protection_scan,
        run_ml_vulnerability_prediction,
        run_generate_patch_suggestions,
        run_ml_similarity_search
    )

    # Core analysis classes (fix import names to match actual exports)
    from intellicrack.core.analysis import (
        SymbolicExecutionEngine,
        ConcolicExecutionEngine,
        TaintAnalysisEngine,
        ROPChainGenerator,
        CFGExplorer,
        VulnerabilityEngine,
        MultiFormatBinaryAnalyzer,
        SimilaritySearcher,  # Actual name, not BinarySimilaritySearch
        IncrementalAnalysisManager
    )

    # Network classes (fix import name)
    from intellicrack.core.network import (
        TrafficAnalyzer,  # Actual name, not NetworkTrafficAnalyzer
        ProtocolFingerprinter,
        LicenseServerEmulator,
        SSLInterceptor,
        CloudLicenseHooker
    )

    # Patching classes
    from intellicrack.core.patching import (
        PayloadGenerator,
        WindowsActivator,
        AdobeInjector
    )

    # Protection bypass (fix import names)
    from intellicrack.core.protection_bypass import (
        TPMAnalyzer,  # Actual name, not TPMBypass
        VMDetector   # Actual name, not VMBypass
    )

    # Processing classes
    from intellicrack.core.processing import (
        DistributedAnalysisManager,
        GPUAccelerator,
        QEMUSystemEmulator,
        MemoryOptimizedLoader
    )

    # AI classes (fix import names)
    from intellicrack.ai import (
        VulnerabilityPredictor,  # Actual name, not MLVulnerabilityPredictor
        ModelManager
    )

    # Plugin system
    from intellicrack.plugins.plugin_system import PluginSystem

    # Utility modules
    from intellicrack.utils import (
        protection_detection,
        protection_utils,
        exploitation,
        system_utils
    )

    # Import hashlib for payload hashing
    import hashlib

except ImportError as e:
    print(f"Error importing Intellicrack modules: {e}")
    print("Some features may not be available.")
    print("Run: cd dependencies && INSTALL.bat")

    # Try to continue with minimal functionality
    try:
        from intellicrack.utils.binary_analysis import analyze_binary
        from intellicrack.config import CONFIG
        import hashlib
        print("Basic analysis functionality available.")
    except ImportError:
        print("Critical imports failed. Cannot continue.")
        sys.exit(1)
except ImportError as e:
    print(f"Error importing Intellicrack modules: {e}")
    print("Please ensure Intellicrack is properly installed.")
    print("Run: cd dependencies && INSTALL.bat")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class IntellicrackCLI:
    """Enhanced CLI handler with all features."""

    def __init__(self, args):
        self.args = args
        self.results = {}
        self.binary_path = args.binary
        self.profiler = None
        self.memory_tracer = None
        self.performance_stats = {}

        # Initialize debug mode
        if args.debug_mode:
            self.enable_debug_mode()

        # Initialize performance profiling
        if args.profile_performance:
            if PROFILING_AVAILABLE:
                self.profiler = cProfile.Profile()
                self.profiler.enable()
            else:
                logger.warning("Performance profiling not available. Install cProfile.")
                args.profile_performance = False

        # Initialize memory tracing
        if args.memory_trace:
            if PSUTIL_AVAILABLE and PROFILING_AVAILABLE:
                tracemalloc.start()
                self.memory_baseline = psutil.Process().memory_info().rss / 1024 / 1024  # MB
            else:
                logger.warning("Memory tracing not available. Install psutil.")
                args.memory_trace = False

        # Load custom config if provided
        if args.config:
            self.load_custom_config(args.config)

        # Set up output handling
        self.setup_output()

        # Initialize components based on args
        self.init_components()

    def load_custom_config(self, config_path):
        """Load custom configuration from file."""
        try:
            with open(config_path, 'r') as f:
                custom_config = json.load(f)
            CONFIG.update(custom_config)
            logger.info(f"Loaded custom configuration from {config_path}")
        except Exception as e:
            logger.error(f"Failed to load custom configuration: {e}")
            if not self.args.ignore_errors:
                sys.exit(1)

    def enable_debug_mode(self):
        """Enable developer debug mode with detailed tracing."""
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
            force=True
        )
        logger.debug("Debug mode enabled")

        # Enable import debugging
        import sys
        sys.settrace(self._trace_calls)

    def _trace_calls(self, frame, event, arg):
        """Trace function calls for debug mode."""
        if event == 'call':
            code = frame.f_code
            logger.debug(f"Calling: {code.co_filename}:{code.co_name}")
        return self._trace_calls

    def setup_output(self):
        """Set up output handling based on arguments."""
        self.verbose = self.args.verbose
        self.quiet = self.args.quiet

        if self.quiet:
            logging.getLogger().setLevel(logging.ERROR)
        elif self.verbose:
            logging.getLogger().setLevel(logging.DEBUG)

    def init_components(self):
        """Initialize components based on arguments."""
        # GPU acceleration
        if self.args.gpu_accelerate:
            try:
                self.gpu = GPUAccelerator()
                logger.info("GPU acceleration enabled")
            except (ImportError, RuntimeError, AttributeError):
                logger.warning("GPU acceleration not available, using CPU")
                self.gpu = None

        # Distributed processing
        if self.args.distributed:
            self.dist_manager = DistributedAnalysisManager()
            self.dist_manager.initialize(
                max_workers=self.args.threads,
                backend='ray' if self.args.distributed_backend == 'ray' else 'dask'
            )
            logger.info(f"Distributed processing enabled with {self.args.threads} workers")

    def run(self):
        """Main execution method."""
        start_time = time.time()

        # Validate binary exists
        if not os.path.exists(self.binary_path):
            logger.error(f"Binary not found: {self.binary_path}")
            sys.exit(1)

        logger.info(f"Analyzing: {self.binary_path}")

        # Run requested analyses
        self.run_core_analysis()
        self.run_vulnerability_detection()
        self.run_protection_analysis()
        self.run_network_analysis()
        self.run_patching_operations()
        self.run_bypass_operations()
        self.run_ml_analysis()
        self.run_external_tools()
        self.run_advanced_features()

        # Generate output
        elapsed = time.time() - start_time
        self.results['analysis_time'] = elapsed
        logger.info(f"Analysis completed in {elapsed:.2f} seconds")

        # Finalize analysis (performance/memory reports)
        self.finalize_analysis()

        self.generate_output()

    # pylint: disable=too-complex
    def run_core_analysis(self):
        """Run core analysis features."""
        # Basic analysis (always run unless --skip-basic)
        if not self.args.skip_basic:
            logger.info("Running basic analysis...")
            self.results['basic'] = analyze_binary(self.binary_path)

        # Comprehensive analysis
        if self.args.comprehensive:
            logger.info("Running comprehensive analysis...")
            self.results['comprehensive'] = run_comprehensive_analysis(self.binary_path)

        # Control Flow Graph
        if self.args.cfg_analysis:
            logger.info("Generating control flow graph...")
            cfg_explorer = CFGExplorer()
            cfg = cfg_explorer.analyze(self.binary_path)

            if self.args.cfg_output:
                # Export CFG to file
                if self.args.cfg_format == 'dot':
                    cfg_explorer.export_dot(cfg, self.args.cfg_output)
                elif self.args.cfg_format == 'json':
                    cfg_explorer.export_json(cfg, self.args.cfg_output)
                logger.info(f"CFG exported to {self.args.cfg_output}")

            self.results['cfg'] = cfg

        # Symbolic Execution
        if self.args.symbolic_execution:
            logger.info("Running symbolic execution...")
            sym_engine = SymbolicExecutionEngine()
            if self.args.symbolic_address:
                # Start from specific address
                sym_results = sym_engine.explore_from(
                    self.binary_path, 
                    int(self.args.symbolic_address, 16)
                )
            else:
                sym_results = run_symbolic_execution(self.binary_path)
            self.results['symbolic'] = sym_results

        # Concolic Execution
        if self.args.concolic_execution:
            logger.info("Running concolic execution...")
            concolic_engine = ConcolicExecutionEngine()
            concolic_results = concolic_engine.analyze(
                self.binary_path,
                target_coverage=self.args.concolic_coverage
            )
            self.results['concolic'] = concolic_results

        # Taint Analysis
        if self.args.taint_analysis:
            logger.info("Running taint analysis...")
            taint_engine = TaintAnalysisEngine()
            if self.args.taint_sources:
                sources = self.args.taint_sources.split(',')
                taint_results = taint_engine.analyze_with_sources(
                    self.binary_path, sources
                )
            else:
                taint_results = run_taint_analysis(self.binary_path)
            self.results['taint'] = taint_results

        # ROP Gadgets
        if self.args.rop_gadgets:
            logger.info("Finding ROP gadgets...")
            rop_gen = ROPChainGenerator()
            gadgets = rop_gen.find_gadgets(
                self.binary_path,
                max_gadgets=self.args.rop_max_gadgets
            )

            if self.args.rop_chain:
                # Generate ROP chain for specific goal
                chain = rop_gen.generate_chain(gadgets, self.args.rop_chain)
                self.results['rop_chain'] = chain

            self.results['rop_gadgets'] = gadgets

        # Binary Similarity
        if self.args.similarity_search and self.args.similarity_db:
            logger.info("Running binary similarity search...")
            sim_search = SimilaritySearcher()
            similar = sim_search.find_similar(
                self.binary_path,
                self.args.similarity_db,
                threshold=self.args.similarity_threshold
            )
            self.results['similar_binaries'] = similar

        # Multi-format analysis
        if self.args.multi_format:
            logger.info("Running multi-format analysis...")
            mf_analyzer = MultiFormatBinaryAnalyzer()
            mf_results = mf_analyzer.analyze(self.binary_path)
            self.results['multi_format'] = mf_results

        # Section analysis
        if self.args.section_analysis:
            logger.info("Analyzing sections...")
            self.results['sections'] = run_section_analysis(self.binary_path)

        # Import/Export analysis
        if self.args.import_export:
            logger.info("Analyzing imports and exports...")
            self.results['imports_exports'] = run_import_export_analysis(self.binary_path)

    def run_vulnerability_detection(self):
        """Run vulnerability detection features."""
        if self.args.vulnerability_scan:
            logger.info("Scanning for vulnerabilities...")
            vuln_engine = VulnerabilityEngine()
            vulns = vuln_engine.scan_binary(
                self.binary_path,
                scan_depth=self.args.vuln_scan_depth
            )
            self.results['vulnerabilities'] = vulns

        if self.args.weak_crypto:
            logger.info("Detecting weak cryptography...")
            self.results['weak_crypto'] = run_weak_crypto_detection(self.binary_path)

        if self.args.ml_vulnerability:
            logger.info("Running ML-based vulnerability prediction...")
            ml_predictor = VulnerabilityPredictor()
            if self.args.ml_model:
                ml_predictor.load_model(self.args.ml_model)
            predictions = ml_predictor.predict(self.binary_path)
            self.results['ml_vulnerabilities'] = predictions

    def run_protection_analysis(self):
        """Run protection detection and analysis."""
        if self.args.detect_packing:
            logger.info("Detecting packing and obfuscation...")
            self.results['packing'] = run_detect_packing(self.binary_path)

        if self.args.detect_protections:
            logger.info("Scanning for all known protections...")
            self.results['protections'] = run_comprehensive_protection_scan(self.binary_path)

        if self.args.commercial_protections:
            logger.info("Detecting commercial protection systems...")
            self.results['commercial_protections'] = protection_detection.detect_commercial_protections(
                self.binary_path
            )

        if self.args.anti_debug:
            logger.info("Detecting anti-debugging techniques...")
            self.results['anti_debug'] = protection_detection.detect_anti_debugging(
                self.binary_path
            )

        if self.args.license_analysis:
            logger.info("Analyzing license mechanisms...")
            self.results['license'] = run_deep_license_analysis(self.binary_path)

    def run_network_analysis(self):
        """Run network analysis features."""
        if self.args.network_capture:
            logger.info(f"Starting network capture on {self.args.network_interface}...")
            analyzer = TrafficAnalyzer()

            if self.args.capture_duration:
                # Capture for specified duration
                analyzer.start_capture(
                    interface=self.args.network_interface,
                    filter_expr=self.args.capture_filter
                )
                time.sleep(self.args.capture_duration)
                analyzer.stop_capture()
            else:
                logger.warning("Use --capture-duration to specify capture time")

            self.results['network_capture'] = analyzer.get_results()

        if self.args.protocol_fingerprint:
            logger.info("Fingerprinting network protocols...")
            fingerprinter = ProtocolFingerprinter()
            if self.args.pcap_file:
                protocols = fingerprinter.analyze_pcap(self.args.pcap_file)
            else:
                protocols = fingerprinter.analyze_binary(self.binary_path)
            self.results['protocols'] = protocols

        if self.args.ssl_intercept:
            logger.info("Setting up SSL/TLS interception...")
            interceptor = SSLInterceptor()
            interceptor.configure(
                port=self.args.ssl_port,
                cert_file=self.args.ssl_cert
            )
            self.results['ssl_config'] = interceptor.get_config()

    def run_patching_operations(self):
        """Run patching and modification operations."""
        if self.args.suggest_patches:
            logger.info("Generating patch suggestions...")
            self.results['patch_suggestions'] = run_generate_patch_suggestions(
                self.binary_path
            )

        if self.args.apply_patch:
            logger.info(f"Applying patch: {self.args.patch_file}...")
            # Load patch definition
            with open(self.args.patch_file, 'r') as f:
                patch_def = json.load(f)

            # Use memory patching utility functions
            from intellicrack.core.patching.memory_patcher import apply_memory_patches
            results = apply_memory_patches(
                self.binary_path,
                patch_def,
                memory_mode=self.args.memory_patch
            )
            self.results['patching'] = results

        if self.args.generate_payload:
            logger.info(f"Generating {self.args.payload_type} payload...")
            gen = PayloadGenerator()
            payload = gen.generate(
                self.args.payload_type,
                target=self.binary_path,
                options=self.args.payload_options
            )

            if self.args.payload_output:
                with open(self.args.payload_output, 'wb') as f:
                    f.write(payload)
                logger.info(f"Payload saved to {self.args.payload_output}")

            self.results['payload'] = {
                'type': self.args.payload_type,
                'size': len(payload),
                'hash': hashlib.sha256(payload).hexdigest()
            }

    def run_bypass_operations(self):
        """Run protection bypass operations."""
        if self.args.bypass_tpm:
            logger.info("Generating TPM bypass...")
            analyzer = TPMAnalyzer()
            self.results['tpm_bypass'] = analyzer.generate_bypass(
                self.binary_path,
                method=self.args.tpm_method
            )

        if self.args.bypass_vm_detection:
            logger.info("Generating VM detection bypass...")
            detector = VMDetector()
            self.results['vm_bypass'] = detector.generate_bypass(
                self.binary_path,
                aggressive=self.args.aggressive_bypass
            )

        if self.args.emulate_dongle:
            logger.info(f"Setting up {self.args.dongle_type} dongle emulation...")
            # Use protection_utils for dongle emulation
            config = protection_utils.emulate_hardware_dongle(
                self.args.dongle_type,
                self.binary_path,
                dongle_id=self.args.dongle_id
            )
            self.results['dongle_emulation'] = config

        if self.args.hwid_spoof:
            logger.info("Generating HWID spoofing configuration...")
            self.results['hwid_spoof'] = protection_utils.generate_hwid_spoof_config(
                self.binary_path,
                target_hwid=self.args.target_hwid
            )

        if self.args.time_bomb_defuser:
            logger.info("Generating time bomb defusion scripts...")
            self.results['time_bomb_defuser'] = protection_utils.generate_time_bomb_defuser(
                self.binary_path
            )

        if self.args.telemetry_blocker:
            logger.info("Generating telemetry blocking configuration...")
            self.results['telemetry_blocker'] = protection_utils.generate_telemetry_blocker(
                self.binary_path
            )

    def run_ml_analysis(self):
        """Run machine learning analysis."""
        if self.args.ml_similarity:
            logger.info("Running ML-based similarity analysis...")
            # Extract features and find similar samples
            self.results['ml_similarity'] = run_ml_similarity_search(
                self.binary_path,
                database=self.args.ml_database
            )

        if self.args.train_model:
            logger.info("Training custom ML model...")
            manager = ModelManager()
            model = manager.train_model(
                self.args.training_data,
                model_type=self.args.model_type,
                epochs=self.args.training_epochs
            )

            if self.args.save_model:
                manager.save_model(model, self.args.save_model)
                logger.info(f"Model saved to {self.args.save_model}")

    def run_external_tools(self):
        """Run external tool integrations."""
        if self.args.ghidra_analysis:
            logger.info("Running Ghidra analysis...")
            self.results['ghidra'] = run_ghidra_analysis(
                self.binary_path,
                script=self.args.ghidra_script
            )

        if self.args.radare2_analysis:
            logger.info("Running Radare2 analysis...")
            self.results['radare2'] = run_radare2_analysis(
                self.binary_path,
                commands=self.args.r2_commands
            )

        if self.args.qemu_emulate:
            logger.info("Setting up QEMU emulation...")
            emulator = QEMUSystemEmulator()
            self.results['qemu'] = emulator.emulate_binary(
                self.binary_path,
                arch=self.args.qemu_arch,
                snapshot=self.args.qemu_snapshot
            )

        if self.args.frida_script:
            logger.info(f"Running Frida script: {self.args.frida_script}...")
            self.results['frida'] = run_frida_script(
                self.binary_path,
                self.args.frida_script,
                spawn=self.args.frida_spawn
            )

    # pylint: disable=too-complex
    def run_advanced_features(self):
        """Run advanced and utility features."""
        if self.args.extract_icon:
            logger.info("Extracting executable icon...")
            icon_path = system_utils.extract_executable_icon(
                self.binary_path,
                output_path=self.args.icon_output
            )
            self.results['icon'] = {'path': icon_path}

        if self.args.generate_license_key:
            logger.info("Generating license key...")
            from intellicrack.utils.exploitation import generate_license_key
            algorithm = self.args.license_algorithm or 'auto-detect'
            license_key = generate_license_key(
                self.binary_path,
                algorithm=algorithm
            )
            self.results['license_key'] = {
                'key': license_key,
                'algorithm': algorithm
            }

        if self.args.ai_assistant:
            logger.info("Running AI Assistant...")
            from intellicrack.ai.ai_tools import AIAssistant
            assistant = AIAssistant()

            question = self.args.ai_question or "Analyze this binary"
            context = self.args.ai_context or str(self.results)

            response = assistant.ask_question(
                question=question,
                context=context,
                binary_path=self.binary_path
            )
            self.results['ai_assistant'] = {
                'question': question,
                'response': response
            }

        if self.args.plugin_run:
            logger.info(f"Running plugin: {self.args.plugin_run}...")
            plugin_sys = PluginSystem()
            plugin_sys.discover_plugins()

            if self.args.plugin_remote:
                # Remote plugin execution
                result = plugin_sys.execute_remote_plugin(
                    self.args.plugin_run,
                    self.binary_path,
                    server=self.args.plugin_server,
                    port=self.args.plugin_port,
                    params=self.args.plugin_params
                )
            elif self.args.plugin_sandbox:
                # Sandboxed execution
                result = plugin_sys.execute_sandboxed_plugin(
                    self.args.plugin_run,
                    self.binary_path,
                    params=self.args.plugin_params
                )
            else:
                # Standard execution
                result = plugin_sys.execute_plugin(
                    self.args.plugin_run,
                    self.binary_path,
                    params=self.args.plugin_params
                )

            self.results['plugin'] = result

        if self.args.generate_report:
            logger.info("Generating detailed report...")
            # This will be handled in generate_output()
            self.args.format = self.args.report_format or 'pdf'

        # GUI Integration features
        if self.args.launch_gui:
            logger.info("Launching GUI with analysis results...")
            self.launch_gui_with_results()

        if self.args.gui_export:
            logger.info(f"Exporting results to GUI format: {self.args.gui_export}...")
            self.export_gui_format(self.args.gui_export)

        if self.args.visual_cfg and 'cfg' in self.results:
            logger.info("Generating visual CFG...")
            output = self.args.visual_cfg_output or 'cfg.png'
            self.generate_visual_cfg(output)

        if self.args.interactive_hex:
            logger.info("Launching interactive hex editor...")
            self.launch_hex_editor()

    def generate_output(self):
        """Generate output in requested format."""
        if self.args.format == 'json':
            output = json.dumps(self.results, indent=2, default=str)
        elif self.args.format == 'text':
            output = self.format_text_output()
        elif self.args.format in ['pdf', 'html']:
            output = generate_report(
                self.results,
                self.binary_path,
                format=self.args.format
            )
        else:
            output = str(self.results)

        # Write output
        if self.args.output:
            if self.args.format in ['pdf']:
                mode = 'wb'
            else:
                mode = 'w'

            with open(self.args.output, mode) as f:
                f.write(output if isinstance(output, bytes) else output)

            logger.info(f"Output written to {self.args.output}")
        else:
            if not isinstance(output, bytes):
                print(output)

    def format_text_output(self):
        """Format results as human-readable text."""
        lines = []
        lines.append(f"=== Intellicrack Analysis Results ===")
        lines.append(f"Binary: {self.binary_path}")
        lines.append(f"Analysis Time: {self.results.get('analysis_time', 0):.2f}s")
        lines.append("")

        # Format each result section
        for section, data in self.results.items():
            if section == 'analysis_time':
                continue

            lines.append(f"[{section.upper()}]")

            if isinstance(data, dict):
                for key, value in data.items():
                    lines.append(f"  {key}: {value}")
            elif isinstance(data, list):
                for item in data:
                    lines.append(f"  - {item}")
            else:
                lines.append(f"  {data}")

            lines.append("")

        return '\n'.join(lines)

    def launch_gui_with_results(self):
        """Launch GUI with analysis results preloaded."""
        try:
            # Save results to temporary file
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json.dump(self.results, f, indent=2, default=str)
                results_file = f.name

            # Launch GUI with results
            from intellicrack.ui.main_app import launch_with_results
            logger.info(f"Launching GUI with results from {results_file}")
            launch_with_results(results_file, self.binary_path)

        except ImportError:
            logger.error("GUI components not available. Install PyQt5.")
        except Exception as e:
            logger.error(f"Failed to launch GUI: {e}")

    def export_gui_format(self, output_path):
        """Export results to GUI-compatible format."""
        gui_data = {
            'version': '2.0',
            'binary_path': self.binary_path,
            'analysis_time': self.results.get('analysis_time', 0),
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'results': self.results,
            'metadata': {
                'cli_version': '1.0',
                'features_used': self._get_features_used(),
                'command_line': ' '.join(sys.argv)
            }
        }

        with open(output_path, 'w') as f:
            json.dump(gui_data, f, indent=2, default=str)

        logger.info(f"GUI-compatible results exported to {output_path}")

    def _get_features_used(self):
        """Get list of features used in this analysis."""
        features = []
        for attr in dir(self.args):
            if not attr.startswith('_') and getattr(self.args, attr):
                features.append(attr)
        return features

    def generate_visual_cfg(self, output_path):
        """Generate visual CFG image from analysis results."""
        try:
            import matplotlib.pyplot as plt
            import networkx as nx
            from matplotlib.patches import FancyBboxPatch

            if 'cfg' not in self.results:
                logger.error("No CFG data available. Run --cfg-analysis first.")
                return

            cfg_data = self.results['cfg']

            # Create directed graph
            G = nx.DiGraph()

            # Add nodes and edges from CFG data
            for node in cfg_data.get('nodes', []):
                G.add_node(node['id'], **node)

            for edge in cfg_data.get('edges', []):
                G.add_edge(edge['source'], edge['target'], **edge)

            # Create visualization
            plt.figure(figsize=(12, 10))
            pos = nx.spring_layout(G, k=2, iterations=50)

            # Draw nodes with different colors based on type
            node_colors = []
            for node in G.nodes():
                if G.nodes[node].get('type') == 'entry':
                    node_colors.append('lightgreen')
                elif G.nodes[node].get('type') == 'exit':
                    node_colors.append('lightcoral')
                else:
                    node_colors.append('lightblue')

            nx.draw_networkx_nodes(G, pos, node_color=node_colors, 
                                 node_size=1000, alpha=0.9)
            nx.draw_networkx_edges(G, pos, edge_color='gray', 
                                 arrows=True, arrowsize=20, alpha=0.6)
            nx.draw_networkx_labels(G, pos, font_size=8)

            plt.title(f"Control Flow Graph - {os.path.basename(self.binary_path)}")
            plt.axis('off')
            plt.tight_layout()
            plt.savefig(output_path, dpi=300, bbox_inches='tight')
            plt.close()

            logger.info(f"Visual CFG saved to {output_path}")
            self.results['visual_cfg'] = {'path': output_path}

        except ImportError as e:
            logger.error(f"Missing visualization dependencies: {e}")
            logger.info("Install matplotlib and networkx for CFG visualization")
        except Exception as e:
            logger.error(f"Failed to generate visual CFG: {e}")

    def launch_hex_editor(self):
        """Launch interactive hex editor with the binary file."""
        try:
            # Try to use the integrated hex viewer
            from intellicrack.hexview.hex_widget import HexViewerWidget
            from PyQt5.QtWidgets import QApplication

            app = QApplication.instance()
            if not app:
                app = QApplication(sys.argv)

            hex_viewer = HexViewerWidget()
            hex_viewer.load_file(self.binary_path)
            hex_viewer.show()

            logger.info(f"Launched hex editor for {self.binary_path}")
            app.exec_()

        except ImportError:
            # Fallback to external hex editor
            logger.info("Trying external hex editor...")
            import subprocess
            import platform

            if platform.system() == 'Windows':
                # Try HxD or other Windows hex editors
                try:
                    subprocess.Popen(['hxd.exe', self.binary_path])
                except (FileNotFoundError, OSError):
                    subprocess.Popen(['notepad++.exe', '-nohex', self.binary_path])
            elif platform.system() == 'Linux':
                # Try hexedit, xxd, or hexdump
                try:
                    subprocess.Popen(['hexedit', self.binary_path])
                except (FileNotFoundError, OSError):
                    subprocess.Popen(['ghex', self.binary_path])
            else:
                logger.error("No suitable hex editor found")

    def finalize_analysis(self):
        """Finalize analysis and generate performance/memory reports."""
        # Stop performance profiling
        if self.args.profile_performance and self.profiler and PROFILING_AVAILABLE:
            self.profiler.disable()

            # Generate performance report
            s = io.StringIO()
            ps = pstats.Stats(self.profiler, stream=s).sort_stats('cumulative')
            ps.print_stats(30)  # Top 30 functions

            perf_report = s.getvalue()
            logger.info("\n=== PERFORMANCE PROFILE ===")
            logger.info(perf_report)

            # Add to results
            self.results['performance_profile'] = {
                'top_functions': perf_report,
                'total_time': ps.total_tt
            }

        # Generate memory trace report
        if self.args.memory_trace and PSUTIL_AVAILABLE and PROFILING_AVAILABLE:
            current_mem = psutil.Process().memory_info().rss / 1024 / 1024  # MB
            mem_increase = current_mem - self.memory_baseline

            # Get top memory allocations
            snapshot = tracemalloc.take_snapshot()
            top_stats = snapshot.statistics('lineno')

            logger.info("\n=== MEMORY TRACE ===")
            logger.info(f"Memory baseline: {self.memory_baseline:.2f} MB")
            logger.info(f"Current memory: {current_mem:.2f} MB")
            logger.info(f"Memory increase: {mem_increase:.2f} MB")
            logger.info("\nTop 10 memory allocations:")

            for stat in top_stats[:10]:
                logger.info(f"{stat}")

            self.results['memory_trace'] = {
                'baseline_mb': self.memory_baseline,
                'final_mb': current_mem,
                'increase_mb': mem_increase,
                'top_allocations': [str(stat) for stat in top_stats[:10]]
            }

            tracemalloc.stop()

        # Disable debug mode tracing
        if self.args.debug_mode:
            sys.settrace(None)


def show_feature_categories():
    """Show organized feature categories and examples."""
    categories = {
        "Core Analysis": [
            "--comprehensive                    # Full analysis suite",
            "--cfg-analysis                     # Control flow graph",
            "--symbolic-execution               # Symbolic execution (Angr)",
            "--concolic-execution               # Concolic execution (Manticore)",
            "--taint-analysis                   # Taint analysis",
            "--rop-gadgets                      # ROP gadget finding",
            "--similarity-search                # Binary similarity",
            "--multi-format                     # Multi-format analysis",
            "--section-analysis                 # Section analysis",
            "--import-export                    # Import/export analysis"
        ],
        "Vulnerability Detection": [
            "--vulnerability-scan               # Static vulnerability scan",
            "--weak-crypto                      # Weak cryptography detection",
            "--ml-vulnerability                 # ML-based prediction",
            "--vuln-scan-depth {quick,normal,deep}  # Scan depth"
        ],
        "Protection Analysis": [
            "--detect-packing                   # Packing/obfuscation detection",
            "--detect-protections               # All known protections",
            "--commercial-protections           # Commercial systems",
            "--anti-debug                       # Anti-debugging techniques",
            "--license-analysis                 # License mechanisms"
        ],
        "Network Analysis": [
            "--network-capture                  # Traffic capture",
            "--protocol-fingerprint             # Protocol fingerprinting",
            "--ssl-intercept                    # SSL/TLS interception",
            "--capture-duration SECS            # Capture duration",
            "--pcap-file FILE                   # Analyze PCAP file"
        ],
        "Protection Bypass": [
            "--bypass-tpm                       # TPM bypass",
            "--bypass-vm-detection              # VM detection bypass",
            "--emulate-dongle                   # Hardware dongle emulation",
            "--hwid-spoof                       # HWID spoofing",
            "--time-bomb-defuser                # Time bomb defusion",
            "--telemetry-blocker                # Telemetry blocking"
        ],
        "Patching & Exploitation": [
            "--suggest-patches                  # Generate patch suggestions",
            "--apply-patch                      # Apply patches",
            "--generate-payload                 # Generate exploit payload",
            "--memory-patch                     # Memory-only patching"
        ],
        "Machine Learning": [
            "--ml-similarity                    # ML-based similarity",
            "--train-model                      # Train custom model",
            "--ml-model PATH                    # Use custom model"
        ],
        "External Tools": [
            "--ghidra-analysis                  # Ghidra integration",
            "--qemu-emulate                     # QEMU emulation",
            "--frida-script SCRIPT              # Frida scripting"
        ],
        "Plugin System": [
            "--plugin-list                      # List plugins",
            "--plugin-run PLUGIN                # Run plugin",
            "--plugin-remote                    # Remote execution",
            "--plugin-sandbox                   # Sandboxed execution"
        ],
        "Processing Options": [
            "--gpu-accelerate                   # GPU acceleration",
            "--distributed                      # Distributed processing",
            "--threads NUM                      # Number of threads",
            "--memory-optimized                 # Memory optimization"
        ],
        "Utilities": [
            "--extract-icon                     # Extract executable icon",
            "--generate-license-key             # Generate license key",
            "--ai-assistant                     # AI assistant Q&A",
            "--generate-report                  # Generate report"
        ],
        "Output & Batch": [
            "--format {text,json,pdf,html}      # Output format",
            "--batch FILE                       # Batch processing",
            "--server                           # REST API server",
            "--watch                            # Watch file changes"
        ]
    }

    print("🚀 INTELLICRACK CLI - COMPLETE FEATURE REFERENCE")
    print("=" * 80)
    print("Access to ALL 78 Intellicrack features via command line")
    print()

    for category, commands in categories.items():
        print(f"📁 {category.upper()}")
        print("-" * len(category))
        for command in commands:
            print(f"  {command}")
        print()

    print("🔥 QUICK START EXAMPLES:")
    print("-" * 25)
    examples = [
        "# Complete security assessment",
        "intellicrack-cli malware.exe --comprehensive --vulnerability-scan --detect-protections",
        "",
        "# License analysis and bypass",
        "intellicrack-cli software.exe --license-analysis --generate-license-key --bypass-tpm",
        "",
        "# Advanced binary analysis",
        "intellicrack-cli binary.exe --cfg-analysis --symbolic-execution --ai-assistant",
        "",
        "# Network protocol analysis",
        "intellicrack-cli client.exe --network-capture --protocol-fingerprint --ssl-intercept",
        "",
        "# Batch malware analysis",
        "intellicrack-cli --batch samples.txt --comprehensive --gpu-accelerate --threads 16",
        "",
        "# Interactive help",
        "intellicrack-cli --help                    # Full help",
        "intellicrack-cli --help-category analysis  # Category help",
        "intellicrack-cli --list-commands           # All commands"
    ]

    for example in examples:
        print(example)

    print()
    print("📚 DOCUMENTATION:")
    print("- README.md      - Complete overview and usage guide")
    print("- commands.md    - Full command reference")
    print("- examples.md    - Detailed usage examples")
    print()
    print("💡 TIP: Use --verbose for detailed output, --debug for troubleshooting")
    print("=" * 80)


def parse_arguments():
    """Parse command-line arguments with all feature flags."""
    parser = argparse.ArgumentParser(
        description="Intellicrack Comprehensive CLI - Access ALL 78 Features",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
🚀 QUICK EXAMPLES:
  %(prog)s binary.exe --comprehensive                    # Full analysis
  %(prog)s binary.exe --cfg-analysis --cfg-output cfg.dot   # Export CFG
  %(prog)s binary.exe --symbolic-execution --taint-analysis # Advanced analysis
  %(prog)s binary.exe --detect-protections --suggest-patches # Protection & patching
  %(prog)s binary.exe --ml-vulnerability --gpu-accelerate   # ML with GPU
  %(prog)s binary.exe --ghidra-analysis --qemu-emulate     # External tools
  %(prog)s --batch files.txt --comprehensive --threads 16   # Batch processing

📚 HELP OPTIONS:
  %(prog)s --help-categories              # Show organized feature categories
  %(prog)s --list-commands               # List all available commands
  %(prog)s --help-category analysis      # Help for specific category

🔥 FEATURE COVERAGE: ALL 78 Intellicrack features available via CLI!
        """
    )

    # Positional arguments
    parser.add_argument(
        'binary',
        nargs='?',
        help='Path to the binary file to analyze'
    )

    # Core Analysis Options
    analysis_group = parser.add_argument_group('Core Analysis')
    analysis_group.add_argument('--comprehensive', '-c', action='store_true',
                               help='Run comprehensive analysis (all basic modules)')
    analysis_group.add_argument('--skip-basic', action='store_true',
                               help='Skip basic binary analysis')
    analysis_group.add_argument('--cfg-analysis', action='store_true',
                               help='Generate control flow graph')
    analysis_group.add_argument('--cfg-output', metavar='FILE',
                               help='Output file for CFG')
    analysis_group.add_argument('--cfg-format', choices=['dot', 'json'], default='dot',
                               help='CFG output format')
    analysis_group.add_argument('--symbolic-execution', action='store_true',
                               help='Run symbolic execution')
    analysis_group.add_argument('--symbolic-address', metavar='ADDR',
                               help='Start symbolic execution from address (hex)')
    analysis_group.add_argument('--concolic-execution', action='store_true',
                               help='Run concolic execution')
    analysis_group.add_argument('--concolic-coverage', type=float, default=0.8,
                               help='Target code coverage (0.0-1.0)')
    analysis_group.add_argument('--taint-analysis', action='store_true',
                               help='Perform taint analysis')
    analysis_group.add_argument('--taint-sources', metavar='SOURCES',
                               help='Comma-separated taint sources')
    analysis_group.add_argument('--rop-gadgets', action='store_true',
                               help='Find ROP gadgets')
    analysis_group.add_argument('--rop-max-gadgets', type=int, default=1000,
                               help='Maximum gadgets to find')
    analysis_group.add_argument('--rop-chain', metavar='GOAL',
                               help='Generate ROP chain for goal')
    analysis_group.add_argument('--similarity-search', action='store_true',
                               help='Search for similar binaries')
    analysis_group.add_argument('--similarity-db', metavar='PATH',
                               help='Database for similarity search')
    analysis_group.add_argument('--similarity-threshold', type=float, default=0.8,
                               help='Similarity threshold (0.0-1.0)')
    analysis_group.add_argument('--multi-format', action='store_true',
                               help='Multi-format binary analysis')
    analysis_group.add_argument('--section-analysis', action='store_true',
                               help='Analyze binary sections')
    analysis_group.add_argument('--import-export', action='store_true',
                               help='Analyze imports and exports')

    # Vulnerability Detection
    vuln_group = parser.add_argument_group('Vulnerability Detection')
    vuln_group.add_argument('--vulnerability-scan', '-v', action='store_true',
                           help='Scan for security vulnerabilities')
    vuln_group.add_argument('--vuln-scan-depth', choices=['quick', 'normal', 'deep'],
                           default='normal', help='Vulnerability scan depth')
    vuln_group.add_argument('--weak-crypto', action='store_true',
                           help='Detect weak cryptography')
    vuln_group.add_argument('--ml-vulnerability', action='store_true',
                           help='ML-based vulnerability prediction')
    vuln_group.add_argument('--ml-model', metavar='PATH',
                           help='Custom ML model for prediction')

    # Protection Detection
    protection_group = parser.add_argument_group('Protection Detection')
    protection_group.add_argument('--detect-packing', '-p', action='store_true',
                                 help='Detect packing and obfuscation')
    protection_group.add_argument('--detect-protections', action='store_true',
                                 help='Scan for all known protections')
    protection_group.add_argument('--commercial-protections', action='store_true',
                                 help='Detect commercial protection systems')
    protection_group.add_argument('--anti-debug', action='store_true',
                                 help='Detect anti-debugging techniques')
    protection_group.add_argument('--license-analysis', '-l', action='store_true',
                                 help='Analyze license mechanisms')

    # Network Analysis
    network_group = parser.add_argument_group('Network Analysis')
    network_group.add_argument('--network-capture', action='store_true',
                              help='Capture network traffic')
    network_group.add_argument('--network-interface', metavar='IFACE',
                              default='eth0', help='Network interface')
    network_group.add_argument('--capture-duration', type=int,
                              help='Capture duration in seconds')
    network_group.add_argument('--capture-filter', metavar='FILTER',
                              help='BPF filter expression')
    network_group.add_argument('--protocol-fingerprint', action='store_true',
                              help='Fingerprint network protocols')
    network_group.add_argument('--pcap-file', metavar='FILE',
                              help='Analyze protocols from PCAP')
    network_group.add_argument('--ssl-intercept', action='store_true',
                              help='Setup SSL/TLS interception')
    network_group.add_argument('--ssl-port', type=int, default=8443,
                              help='SSL interception port')
    network_group.add_argument('--ssl-cert', metavar='FILE',
                              help='SSL certificate file')

    # Patching Operations
    patch_group = parser.add_argument_group('Patching Operations')
    patch_group.add_argument('--suggest-patches', action='store_true',
                            help='Generate patch suggestions')
    patch_group.add_argument('--apply-patch', action='store_true',
                            help='Apply patch from file')
    patch_group.add_argument('--patch-file', metavar='FILE',
                            help='Patch definition file (JSON)')
    patch_group.add_argument('--memory-patch', action='store_true',
                            help='Apply patches in memory only')
    patch_group.add_argument('--generate-payload', action='store_true',
                            help='Generate exploit payload')
    patch_group.add_argument('--payload-type', choices=['license', 'bypass', 'hook'],
                            help='Payload type')
    patch_group.add_argument('--payload-options', metavar='OPTS',
                            help='Payload options (JSON)')
    patch_group.add_argument('--payload-output', metavar='FILE',
                            help='Save payload to file')

    # Protection Bypass
    bypass_group = parser.add_argument_group('Protection Bypass')
    bypass_group.add_argument('--bypass-tpm', action='store_true',
                             help='Generate TPM bypass')
    bypass_group.add_argument('--tpm-method', choices=['api', 'virtual', 'patch'],
                             default='api', help='TPM bypass method')
    bypass_group.add_argument('--bypass-vm-detection', action='store_true',
                             help='Bypass VM detection')
    bypass_group.add_argument('--aggressive-bypass', action='store_true',
                             help='Use aggressive bypass techniques')
    bypass_group.add_argument('--emulate-dongle', action='store_true',
                             help='Emulate hardware dongle')
    bypass_group.add_argument('--dongle-type', choices=['safenet', 'hasp', 'codemeter'],
                             help='Dongle type to emulate')
    bypass_group.add_argument('--dongle-id', metavar='ID',
                             help='Dongle ID to emulate')
    bypass_group.add_argument('--hwid-spoof', action='store_true',
                             help='Generate HWID spoofing')
    bypass_group.add_argument('--target-hwid', metavar='HWID',
                             help='Target HWID to spoof')
    bypass_group.add_argument('--time-bomb-defuser', action='store_true',
                             help='Generate time bomb defusion scripts')
    bypass_group.add_argument('--telemetry-blocker', action='store_true',
                             help='Generate telemetry blocking configuration')

    # Machine Learning
    ml_group = parser.add_argument_group('Machine Learning')
    ml_group.add_argument('--ml-similarity', action='store_true',
                         help='ML-based similarity analysis')
    ml_group.add_argument('--ml-database', metavar='PATH',
                         help='ML feature database')
    ml_group.add_argument('--train-model', action='store_true',
                         help='Train custom ML model')
    ml_group.add_argument('--training-data', metavar='PATH',
                         help='Training data directory')
    ml_group.add_argument('--model-type', choices=['rf', 'nn', 'svm'],
                         default='rf', help='Model type to train')
    ml_group.add_argument('--training-epochs', type=int, default=100,
                         help='Training epochs')
    ml_group.add_argument('--save-model', metavar='PATH',
                         help='Save trained model')

    # External Tools
    tools_group = parser.add_argument_group('External Tools')
    tools_group.add_argument('--ghidra-analysis', action='store_true',
                            help='Run Ghidra analysis')
    tools_group.add_argument('--ghidra-script', metavar='SCRIPT',
                            help='Ghidra script to run')
    tools_group.add_argument('--radare2-analysis', action='store_true',
                            help='Run Radare2 analysis')
    tools_group.add_argument('--r2-commands', metavar='CMDS',
                            help='Radare2 commands to execute')
    tools_group.add_argument('--qemu-emulate', action='store_true',
                            help='Emulate with QEMU')
    tools_group.add_argument('--qemu-arch', metavar='ARCH',
                            help='QEMU architecture')
    tools_group.add_argument('--qemu-snapshot', action='store_true',
                            help='Create QEMU snapshot')
    tools_group.add_argument('--frida-script', metavar='SCRIPT',
                            help='Run Frida script')
    tools_group.add_argument('--frida-spawn', action='store_true',
                            help='Spawn process for Frida')

    # Processing Options
    processing_group = parser.add_argument_group('Processing Options')
    processing_group.add_argument('--gpu-accelerate', '-g', action='store_true',
                                 help='Use GPU acceleration')
    processing_group.add_argument('--distributed', action='store_true',
                                 help='Use distributed processing')
    processing_group.add_argument('--distributed-backend', choices=['ray', 'dask'],
                                 default='ray', help='Distributed backend')
    processing_group.add_argument('--threads', '-t', type=int, default=4,
                                 help='Number of analysis threads')
    processing_group.add_argument('--incremental', action='store_true',
                                 help='Use incremental analysis cache')
    processing_group.add_argument('--memory-optimized', action='store_true',
                                 help='Use memory-optimized loading')

    # Plugin System
    plugin_group = parser.add_argument_group('Plugin System')
    plugin_group.add_argument('--plugin-list', action='store_true',
                             help='List available plugins')
    plugin_group.add_argument('--plugin-run', metavar='PLUGIN',
                             help='Run specific plugin')
    plugin_group.add_argument('--plugin-params', metavar='PARAMS',
                             help='Plugin parameters (JSON)')
    plugin_group.add_argument('--plugin-install', metavar='PATH',
                             help='Install plugin from path')
    plugin_group.add_argument('--plugin-remote', action='store_true',
                             help='Execute plugin on remote server')
    plugin_group.add_argument('--plugin-server', metavar='SERVER',
                             help='Remote plugin server address')
    plugin_group.add_argument('--plugin-port', type=int, default=9999,
                             help='Remote plugin server port')
    plugin_group.add_argument('--plugin-sandbox', action='store_true',
                             help='Run plugin in sandboxed environment')

    # Utility Features
    utility_group = parser.add_argument_group('Utility Features')
    utility_group.add_argument('--extract-icon', action='store_true',
                              help='Extract executable icon')
    utility_group.add_argument('--icon-output', metavar='FILE',
                              help='Icon output path')
    utility_group.add_argument('--generate-report', action='store_true',
                              help='Generate detailed report')
    utility_group.add_argument('--report-format', choices=['pdf', 'html'],
                              help='Report format')
    utility_group.add_argument('--generate-license-key', action='store_true',
                              help='Generate license key using detected algorithm')
    utility_group.add_argument('--license-algorithm', metavar='ALG',
                              help='License algorithm to use (auto-detect if not specified)')
    utility_group.add_argument('--ai-assistant', action='store_true',
                              help='AI assistant Q&A mode (non-interactive)')
    utility_group.add_argument('--ai-question', metavar='QUESTION',
                              help='Question for AI assistant')
    utility_group.add_argument('--ai-context', metavar='CONTEXT',
                              help='Context for AI assistant (analysis results, etc.)')

    # GUI Integration
    gui_group = parser.add_argument_group('GUI Integration')
    gui_group.add_argument('--launch-gui', action='store_true',
                          help='Launch GUI with analysis results preloaded')
    gui_group.add_argument('--gui-export', metavar='FILE',
                          help='Export results to GUI-compatible format')
    gui_group.add_argument('--visual-cfg', action='store_true',
                          help='Generate visual CFG images (PNG/SVG)')
    gui_group.add_argument('--visual-cfg-output', metavar='FILE',
                          help='Output path for visual CFG (default: cfg.png)')
    gui_group.add_argument('--interactive-hex', action='store_true',
                          help='Launch interactive hex editor with file')

    # Batch Processing
    batch_group = parser.add_argument_group('Batch Processing')
    batch_group.add_argument('--batch', metavar='FILE',
                            help='Batch process files from list')
    batch_group.add_argument('--batch-output-dir', metavar='DIR',
                            help='Output directory for batch results')
    batch_group.add_argument('--batch-parallel', action='store_true',
                            help='Process batch files in parallel')

    # Output Options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument('--output', '-o', metavar='FILE',
                             help='Output file path')
    output_group.add_argument('--format', '-f', 
                             choices=['text', 'json', 'pdf', 'html'],
                             default='text', help='Output format')
    output_group.add_argument('--verbose', '-V', action='store_true',
                             help='Enable verbose output')
    output_group.add_argument('--quiet', '-q', action='store_true',
                             help='Suppress non-essential output')
    output_group.add_argument('--no-color', action='store_true',
                             help='Disable colored output')

    # Advanced Options
    advanced_group = parser.add_argument_group('Advanced Options')
    advanced_group.add_argument('--config', metavar='FILE',
                               help='Custom configuration file')
    advanced_group.add_argument('--timeout', type=int, default=300,
                               help='Analysis timeout in seconds')
    advanced_group.add_argument('--ignore-errors', action='store_true',
                               help='Continue on errors')
    advanced_group.add_argument('--debug', action='store_true',
                               help='Enable debug mode')
    advanced_group.add_argument('--debug-mode', action='store_true',
                               help='Developer debug mode with detailed tracing')
    advanced_group.add_argument('--profile-performance', action='store_true',
                               help='Profile performance and show timing metrics')
    advanced_group.add_argument('--memory-trace', action='store_true',
                               help='Track and report memory usage during analysis')

    # Help and Information
    help_group = parser.add_argument_group('Help and Information')
    help_group.add_argument('--help-categories', action='store_true',
                           help='Show organized feature categories with examples')
    help_group.add_argument('--list-commands', action='store_true',
                           help='List all available commands')
    help_group.add_argument('--help-category', metavar='CATEGORY',
                           choices=['analysis', 'vulnerability', 'protection', 'network', 
                                  'bypass', 'patching', 'ml', 'tools', 'plugins', 'processing'],
                           help='Show help for specific category')

    # Special modes
    parser.add_argument('--server', action='store_true',
                       help='Run as REST API server')
    parser.add_argument('--server-port', type=int, default=8080,
                       help='API server port')
    parser.add_argument('--watch', action='store_true',
                       help='Watch file for changes')
    parser.add_argument('--watch-interval', type=int, default=5,
                       help='Watch interval in seconds')
    parser.add_argument('--ai-mode', action='store_true',
                       help='Run in AI-controlled mode with confirmation safeguards')
    parser.add_argument('--ai-auto-approve-low-risk', action='store_true',
                       help='Auto-approve low-risk actions in AI mode')

    return parser.parse_args()


# pylint: disable=too-complex
def handle_batch_processing(args):
    """Handle batch file processing."""
    if not args.batch:
        return False

    logger.info(f"Processing batch file: {args.batch}")

    # Read file list
    with open(args.batch, 'r') as f:
        files = [line.strip() for line in f if line.strip()]

    logger.info(f"Found {len(files)} files to process")

    # Create output directory
    if args.batch_output_dir:
        os.makedirs(args.batch_output_dir, exist_ok=True)

    # Process files
    results = {}

    if args.batch_parallel and args.threads > 1:
        # Parallel processing
        from concurrent.futures import ProcessPoolExecutor
        with ProcessPoolExecutor(max_workers=args.threads) as executor:
            futures = {}
            for file_path in files:
                # Create args copy for this file
                file_args = argparse.Namespace(**vars(args))
                file_args.binary = file_path
                file_args.batch = None  # Prevent recursion

                if args.batch_output_dir:
                    base_name = os.path.basename(file_path)
                    file_args.output = os.path.join(
                        args.batch_output_dir,
                        f"{base_name}.{args.format}"
                    )

                future = executor.submit(process_single_file, file_args)
                futures[future] = file_path

            # Collect results
            for future in futures:
                file_path = futures[future]
                try:
                    result = future.result(timeout=args.timeout)
                    results[file_path] = result
                    logger.info(f"Completed: {file_path}")
                except Exception as e:
                    logger.error(f"Failed: {file_path} - {e}")
                    if not args.ignore_errors:
                        raise
    else:
        # Sequential processing
        for file_path in files:
            try:
                # Create args copy for this file
                file_args = argparse.Namespace(**vars(args))
                file_args.binary = file_path
                file_args.batch = None  # Prevent recursion

                if args.batch_output_dir:
                    base_name = os.path.basename(file_path)
                    file_args.output = os.path.join(
                        args.batch_output_dir,
                        f"{base_name}.{args.format}"
                    )

                result = process_single_file(file_args)
                results[file_path] = result
                logger.info(f"Completed: {file_path}")
            except Exception as e:
                logger.error(f"Failed: {file_path} - {e}")
                if not args.ignore_errors:
                    raise

    # Save batch summary
    if args.output:
        summary = {
            'batch_file': args.batch,
            'total_files': len(files),
            'successful': len(results),
            'failed': len(files) - len(results),
            'results': results
        }

        with open(args.output, 'w') as f:
            json.dump(summary, f, indent=2, default=str)

        logger.info(f"Batch summary saved to {args.output}")

    return True


def process_single_file(args):
    """Process a single file (used for batch processing)."""
    cli = IntellicrackCLI(args)
    cli.run()
    return cli.results


def run_server_mode(args):
    """Run as REST API server."""
    from flask import Flask, request, jsonify
    import tempfile

    app = Flask(__name__)

    @app.route('/analyze', methods=['POST'])
    def analyze():
        """Analyze uploaded binary."""
        try:
            # Save uploaded file
            file = request.files['binary']
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                file.save(tmp.name)

                # Create args for analysis
                analysis_args = argparse.Namespace(**vars(args))
                analysis_args.binary = tmp.name
                analysis_args.server = False  # Prevent recursion

                # Get analysis options from request
                for key in request.form:
                    if hasattr(analysis_args, key):
                        value = request.form[key]
                        # Convert string to bool for flags
                        if value.lower() in ['true', '1', 'yes']:
                            value = True
                        elif value.lower() in ['false', '0', 'no']:
                            value = False
                        setattr(analysis_args, key, value)

                # Run analysis
                cli = IntellicrackCLI(analysis_args)
                cli.run()

                # Clean up
                os.unlink(tmp.name)

                return jsonify(cli.results)

        except Exception as e:
            # Log the full exception details server-side for debugging
            logger.error(f"Analysis endpoint error: {str(e)}", exc_info=True)
            
            # Return generic error message to user (don't expose stack trace)
            return jsonify({
                'error': 'An internal error occurred during analysis',
                'status': 'failed'
            }), 500

    @app.route('/health', methods=['GET'])
    def health():
        """Health check endpoint."""
        return jsonify({'status': 'healthy', 'version': '2.0'})

    logger.info(f"Starting API server on port {args.server_port}")
    app.run(host='0.0.0.0', port=args.server_port, debug=args.debug)
    return True


def run_watch_mode(args):
    """Watch file for changes and re-analyze."""
    import time
    import hashlib

    if not args.binary:
        logger.error("Binary path required for watch mode")
        return False

    logger.info(f"Watching {args.binary} for changes...")
    last_hash = None

    while True:
        try:
            # Calculate file hash
            with open(args.binary, 'rb') as f:
                current_hash = hashlib.md5(f.read()).hexdigest()

            if current_hash != last_hash:
                logger.info("File changed, re-analyzing...")

                # Run analysis
                watch_args = argparse.Namespace(**vars(args))
                watch_args.watch = False  # Prevent recursion

                cli = IntellicrackCLI(watch_args)
                cli.run()

                last_hash = current_hash
                logger.info("Analysis complete, watching for changes...")

            time.sleep(args.watch_interval)

        except KeyboardInterrupt:
            logger.info("Watch mode terminated")
            break
        except Exception as e:
            logger.error(f"Watch error: {e}")
            if not args.ignore_errors:
                break
            time.sleep(args.watch_interval)

    return True


def show_category_help(category):
    """Show help for specific category."""
    category_help = {
        'analysis': {
            'title': 'CORE ANALYSIS FEATURES',
            'commands': [
                ('--comprehensive', 'Run complete analysis suite'),
                ('--cfg-analysis', 'Generate control flow graph'),
                ('--symbolic-execution', 'Symbolic execution with Angr'),
                ('--concolic-execution', 'Concolic execution with Manticore'),
                ('--taint-analysis', 'Data flow taint analysis'),
                ('--rop-gadgets', 'Find ROP gadgets'),
                ('--similarity-search', 'Binary similarity search'),
                ('--multi-format', 'Multi-format binary analysis'),
                ('--section-analysis', 'Binary section analysis'),
                ('--import-export', 'Import/export table analysis')
            ]
        },
        'vulnerability': {
            'title': 'VULNERABILITY DETECTION',
            'commands': [
                ('--vulnerability-scan', 'Static vulnerability scanning'),
                ('--weak-crypto', 'Weak cryptography detection'),
                ('--ml-vulnerability', 'ML-based vulnerability prediction'),
                ('--vuln-scan-depth', 'Vulnerability scan depth')
            ]
        },
        'protection': {
            'title': 'PROTECTION ANALYSIS',
            'commands': [
                ('--detect-packing', 'Detect packing and obfuscation'),
                ('--detect-protections', 'Scan for all protections'),
                ('--commercial-protections', 'Commercial protection systems'),
                ('--anti-debug', 'Anti-debugging techniques'),
                ('--license-analysis', 'License mechanism analysis')
            ]
        },
        'network': {
            'title': 'NETWORK ANALYSIS',
            'commands': [
                ('--network-capture', 'Network traffic capture'),
                ('--protocol-fingerprint', 'Protocol fingerprinting'),
                ('--ssl-intercept', 'SSL/TLS interception'),
                ('--capture-duration', 'Capture duration in seconds'),
                ('--pcap-file', 'Analyze existing PCAP file')
            ]
        },
        'bypass': {
            'title': 'PROTECTION BYPASS',
            'commands': [
                ('--bypass-tpm', 'TPM protection bypass'),
                ('--bypass-vm-detection', 'VM detection bypass'),
                ('--emulate-dongle', 'Hardware dongle emulation'),
                ('--hwid-spoof', 'HWID spoofing'),
                ('--time-bomb-defuser', 'Time bomb defusion'),
                ('--telemetry-blocker', 'Telemetry blocking')
            ]
        },
        'patching': {
            'title': 'PATCHING & EXPLOITATION',
            'commands': [
                ('--suggest-patches', 'Generate patch suggestions'),
                ('--apply-patch', 'Apply patches from file'),
                ('--generate-payload', 'Generate exploit payload'),
                ('--memory-patch', 'Memory-only patching')
            ]
        },
        'ml': {
            'title': 'MACHINE LEARNING',
            'commands': [
                ('--ml-similarity', 'ML-based similarity analysis'),
                ('--train-model', 'Train custom ML model'),
                ('--ml-model', 'Use custom ML model'),
                ('--ml-database', 'ML feature database')
            ]
        },
        'tools': {
            'title': 'EXTERNAL TOOLS',
            'commands': [
                ('--ghidra-analysis', 'Ghidra integration'),
                ('--qemu-emulate', 'QEMU system emulation'),
                ('--frida-script', 'Frida dynamic instrumentation')
            ]
        },
        'plugins': {
            'title': 'PLUGIN SYSTEM',
            'commands': [
                ('--plugin-list', 'List available plugins'),
                ('--plugin-run', 'Run specific plugin'),
                ('--plugin-remote', 'Remote plugin execution'),
                ('--plugin-sandbox', 'Sandboxed plugin execution')
            ]
        },
        'processing': {
            'title': 'PROCESSING OPTIONS',
            'commands': [
                ('--gpu-accelerate', 'GPU acceleration'),
                ('--distributed', 'Distributed processing'),
                ('--threads', 'Number of processing threads'),
                ('--memory-optimized', 'Memory optimization')
            ]
        }
    }

    if category in category_help:
        info = category_help[category]
        print(f"📁 {info['title']}")
        print("=" * len(info['title']))
        print()
        for cmd, desc in info['commands']:
            print(f"  {cmd:<25} {desc}")
        print()
        print(f"Example: intellicrack-cli binary.exe {info['commands'][0][0]}")
    else:
        print(f"Unknown category: {category}")
        print("Available categories: analysis, vulnerability, protection, network, bypass, patching, ml, tools, plugins, processing")


def list_all_commands():
    """List all available commands organized by type."""
    print("🚀 INTELLICRACK CLI - ALL COMMANDS")
    print("=" * 50)
    print("Total: 78 features accessible via CLI")
    print()

    # Import the parser to get all arguments
    parser = argparse.ArgumentParser()
    # We would add all arguments here, but it's complex
    # For now, just show the main categories
    commands = [
        "Analysis Commands:",
        "  --comprehensive, --cfg-analysis, --symbolic-execution, --concolic-execution",
        "  --taint-analysis, --rop-gadgets, --similarity-search, --multi-format",
        "",
        "Vulnerability Detection:",
        "  --vulnerability-scan, --weak-crypto, --ml-vulnerability",
        "",
        "Protection Analysis:",
        "  --detect-packing, --detect-protections, --commercial-protections, --anti-debug",
        "",
        "Network Analysis:",
        "  --network-capture, --protocol-fingerprint, --ssl-intercept",
        "",
        "Protection Bypass:",
        "  --bypass-tpm, --bypass-vm-detection, --emulate-dongle, --hwid-spoof",
        "",
        "Patching & Exploitation:",
        "  --suggest-patches, --apply-patch, --generate-payload, --memory-patch",
        "",
        "Machine Learning:",
        "  --ml-similarity, --train-model, --ml-model, --ml-database",
        "",
        "External Tools:",
        "  --ghidra-analysis, --qemu-emulate, --frida-script",
        "",
        "Plugin System:",
        "  --plugin-list, --plugin-run, --plugin-remote, --plugin-sandbox",
        "",
        "Processing Options:",
        "  --gpu-accelerate, --distributed, --threads, --memory-optimized",
        "",
        "Output & Utilities:",
        "  --format, --output, --batch, --server, --watch, --extract-icon"
    ]

    for line in commands:
        print(line)

    print()
    print("💡 Use --help-category <category> for detailed help on specific features")
    print("💡 Use --help-categories for organized view with examples")


def run_ai_mode(args):
    """Run in AI-controlled mode."""
    from ai_wrapper import IntellicrackAIInterface, ConfirmationManager
    from ai_integration import IntellicrackAIServer, create_ai_system_prompt

    logger.info("Starting Intellicrack in AI-controlled mode")

    # Create confirmation manager
    manager = ConfirmationManager(auto_approve_low_risk=args.ai_auto_approve_low_risk)

    # Create AI server
    server = IntellicrackAIServer(args.ai_auto_approve_low_risk)

    print("🤖 Intellicrack AI Mode Active")
    print("=" * 80)
    print(create_ai_system_prompt())
    print("=" * 80)
    print("\nAI models can now control Intellicrack with confirmation safeguards.")
    print("Low-risk auto-approval:", "ENABLED" if args.ai_auto_approve_low_risk else "DISABLED")
    print("\nPress Ctrl+C to exit AI mode.\n")

    try:
        # Keep the AI mode running
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nExiting AI mode...")
        return True


# pylint: disable=too-complex
def main():
    """Main entry point."""
    args = parse_arguments()

    # Handle help options first
    if args.help_categories:
        show_feature_categories()
        return

    if args.list_commands:
        list_all_commands()
        return

    if args.help_category:
        show_category_help(args.help_category)
        return

    # Handle special modes
    if args.ai_mode:
        return run_ai_mode(args)

    if args.server:
        return run_server_mode(args)

    if args.watch:
        return run_watch_mode(args)

    if args.batch:
        return handle_batch_processing(args)

    # Handle plugin operations without binary
    if args.plugin_list:
        plugin_sys = PluginSystem()
        plugin_sys.discover_plugins()
        plugins = plugin_sys.list_plugins()
        print("🔌 AVAILABLE PLUGINS:")
        print("=" * 30)
        for name, info in plugins.items():
            print(f"  {name:<20} {info.get('description', 'No description')}")
        print()
        print("💡 Use --plugin-run <plugin> to execute a plugin")
        return

    if args.plugin_install:
        plugin_sys = PluginSystem()
        success = plugin_sys.install_plugin(args.plugin_install)
        if success:
            print(f"✅ Plugin installed from {args.plugin_install}")
        else:
            print(f"❌ Failed to install plugin from {args.plugin_install}")
        return

    # Require binary for analysis
    if not args.binary:
        print("❌ Error: Binary path required for analysis")
        print()
        print("🚀 QUICK START:")
        print("  intellicrack-cli binary.exe --comprehensive")
        print("  intellicrack-cli --help-categories")
        print("  intellicrack-cli --help")
        sys.exit(1)

    # Run analysis
    try:
        cli = IntellicrackCLI(args)
        cli.run()
    except KeyboardInterrupt:
        logger.info("Analysis interrupted by user")
        if hasattr(cli, 'finalize_analysis'):
            cli.finalize_analysis()
        sys.exit(1)
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        if args.debug or args.debug_mode:
            import traceback
            traceback.print_exc()
        if 'cli' in locals() and hasattr(cli, 'finalize_analysis'):
            cli.finalize_analysis()
        sys.exit(1)


if __name__ == '__main__':
    main()