"""
Help and Documentation Widget

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



from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTabWidget,
    QTextBrowser,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

__all__ = ['HelpDocumentationWidget']


class HelpDocumentationWidget(QWidget):
    """
    Comprehensive help and documentation widget for Intellicrack.

    Provides organized access to all features, tutorials, guides,
    and troubleshooting information.
    """

    # Signal emitted when user clicks on a feature to try it
    feature_selected = pyqtSignal(str, str)  # category, feature_name

    def __init__(self, parent=None):
        """Initialize the help documentation widget."""
        super().__init__(parent)
        self.parent = parent
        self.setup_ui()
        self.load_documentation()

    def setup_ui(self):
        """Set up the user interface."""

        # Initialize UI attributes
        self.issues_tree = None
        self.solution_viewer = None
        self.tutorial_viewer = None
        layout = QVBoxLayout(self)

        # Header with search
        header_layout = QHBoxLayout()

        title_label = QLabel("<h2>Help & Documentation</h2>")
        header_layout.addWidget(title_label)

        header_layout.addStretch()

        # Search box
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Search documentation...")
        self.search_edit.setMaximumWidth(300)
        self.search_edit.textChanged.connect(self.on_search_changed)

        search_button = QPushButton("Search")
        search_button.clicked.connect(self.perform_search)

        header_layout.addWidget(QLabel("Search:"))
        header_layout.addWidget(self.search_edit)
        header_layout.addWidget(search_button)

        layout.addLayout(header_layout)

        # Main content area with splitter
        splitter = QSplitter(Qt.Horizontal)

        # Left panel - Navigation tree
        self.nav_tree = QTreeWidget()
        self.nav_tree.setHeaderLabel("Topics")
        self.nav_tree.itemClicked.connect(self.on_nav_item_clicked)
        splitter.addWidget(self.nav_tree)

        # Right panel - Content display
        self.content_tabs = QTabWidget()

        # Documentation tab
        self.doc_browser = QTextBrowser()
        self.doc_browser.setOpenExternalLinks(True)
        self.content_tabs.addTab(self.doc_browser, "Documentation")

        # Features tab
        self.features_widget = self.create_features_widget()
        self.content_tabs.addTab(self.features_widget, "Features")

        # Tutorials tab
        self.tutorials_widget = self.create_tutorials_widget()
        self.content_tabs.addTab(self.tutorials_widget, "Tutorials")

        # Troubleshooting tab
        self.troubleshooting_widget = self.create_troubleshooting_widget()
        self.content_tabs.addTab(self.troubleshooting_widget, "Troubleshooting")

        splitter.addWidget(self.content_tabs)
        splitter.setSizes([300, 700])

        layout.addWidget(splitter)

    def create_features_widget(self) -> QWidget:
        """Create the features documentation widget."""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Features organized by category
        self.features_tree = QTreeWidget()
        self.features_tree.setHeaderLabels(["Feature", "Status", "Description"])
        self.features_tree.itemDoubleClicked.connect(self.on_feature_double_clicked)

        layout.addWidget(QLabel("<h3>All Features by Category</h3>"))
        layout.addWidget(self.features_tree)

        # Feature details panel
        self.feature_details = QTextBrowser()
        self.feature_details.setMaximumHeight(200)
        layout.addWidget(QLabel("<h4>Feature Details</h4>"))
        layout.addWidget(self.feature_details)

        return widget

    def create_tutorials_widget(self) -> QWidget:
        """Create the tutorials widget."""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Tutorial categories
        self.tutorial_tabs = QTabWidget()

        # Getting Started tutorials
        getting_started_list = QListWidget()
        self.populate_getting_started_tutorials(getting_started_list)
        self.tutorial_tabs.addTab(getting_started_list, "Getting Started")

        # Analysis tutorials
        analysis_list = QListWidget()
        self.populate_analysis_tutorials(analysis_list)
        self.tutorial_tabs.addTab(analysis_list, "Analysis")

        # Patching tutorials
        patching_list = QListWidget()
        self.populate_patching_tutorials(patching_list)
        self.tutorial_tabs.addTab(patching_list, "Patching")

        # Advanced tutorials
        advanced_list = QListWidget()
        self.populate_advanced_tutorials(advanced_list)
        self.tutorial_tabs.addTab(advanced_list, "Advanced")

        layout.addWidget(self.tutorial_tabs)

        # Tutorial content viewer
        self.tutorial_viewer = QTextBrowser()
        self.tutorial_viewer.setMaximumHeight(300)
        layout.addWidget(QLabel("<h4>Tutorial Content</h4>"))
        layout.addWidget(self.tutorial_viewer)

        # Connect tutorial selection
        for _i in range(self.tutorial_tabs.count()):
            list_widget = self.tutorial_tabs.widget(_i)
            list_widget.itemClicked.connect(self.on_tutorial_selected)

        return widget

    def create_troubleshooting_widget(self) -> QWidget:
        """Create the troubleshooting widget."""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Common issues list
        self.issues_tree = QTreeWidget()
        self.issues_tree.setHeaderLabels(["Issue", "Category"])
        self.issues_tree.itemClicked.connect(self.on_issue_selected)

        layout.addWidget(QLabel("<h3>Common Issues & Solutions</h3>"))
        layout.addWidget(self.issues_tree)

        # Solution viewer
        self.solution_viewer = QTextBrowser()
        layout.addWidget(QLabel("<h4>Solution</h4>"))
        layout.addWidget(self.solution_viewer)

        return widget

    def load_documentation(self):
        """Load all documentation content."""
        self.populate_navigation_tree()
        self.populate_features_tree()
        self.populate_troubleshooting_tree()
        self.load_welcome_content()

    def populate_navigation_tree(self):
        """Populate the navigation tree."""
        # Overview
        overview = QTreeWidgetItem(self.nav_tree, ["Overview"])
        QTreeWidgetItem(overview, ["Welcome"])
        QTreeWidgetItem(overview, ["Getting Started"])
        QTreeWidgetItem(overview, ["System Requirements"])
        QTreeWidgetItem(overview, ["Installation"])

        # Features
        features = QTreeWidgetItem(self.nav_tree, ["Features"])
        QTreeWidgetItem(features, ["Binary Analysis"])
        QTreeWidgetItem(features, ["Protection Detection"])
        QTreeWidgetItem(features, ["Dynamic Analysis"])
        QTreeWidgetItem(features, ["Network Analysis"])
        QTreeWidgetItem(features, ["Vulnerability Detection"])
        QTreeWidgetItem(features, ["Patching"])
        QTreeWidgetItem(features, ["AI Integration"])
        QTreeWidgetItem(features, ["Plugin System"])

        # User Guide
        guide = QTreeWidgetItem(self.nav_tree, ["User Guide"])
        QTreeWidgetItem(guide, ["Basic Workflow"])
        QTreeWidgetItem(guide, ["Analysis Guide"])
        QTreeWidgetItem(guide, ["Patching Guide"])
        QTreeWidgetItem(guide, ["Network Analysis Guide"])
        QTreeWidgetItem(guide, ["AI Assistant Guide"])

        # Tool Integration
        tools = QTreeWidgetItem(self.nav_tree, ["Tool Integration"])
        QTreeWidgetItem(tools, ["Ghidra Setup"])
        QTreeWidgetItem(tools, ["Radare2 Setup"])
        QTreeWidgetItem(tools, ["Frida Setup"])
        QTreeWidgetItem(tools, ["QEMU Setup"])

        # API Reference
        api = QTreeWidgetItem(self.nav_tree, ["API Reference"])
        QTreeWidgetItem(api, ["Core API"])
        QTreeWidgetItem(api, ["Plugin API"])
        QTreeWidgetItem(api, ["Analysis API"])
        QTreeWidgetItem(api, ["Patching API"])

        # Troubleshooting
        troubleshoot = QTreeWidgetItem(self.nav_tree, ["Troubleshooting"])
        QTreeWidgetItem(troubleshoot, ["Common Issues"])
        QTreeWidgetItem(troubleshoot, ["Error Messages"])
        QTreeWidgetItem(troubleshoot, ["Performance"])
        QTreeWidgetItem(troubleshoot, ["Compatibility"])

        self.nav_tree.expandAll()

    def populate_features_tree(self):
        """Populate the features tree with all 78 features."""
        # Binary Analysis (11 features)
        binary_analysis = QTreeWidgetItem(self.features_tree, ["Binary Analysis", "", "Core analysis capabilities"])
        self.add_feature(binary_analysis, "Static Binary Analysis", "✓", "PE, ELF, Mach-O format analysis")
        self.add_feature(binary_analysis, "Control Flow Graph", "✓", "CFG generation and visualization")
        self.add_feature(binary_analysis, "Symbolic Execution", "✓", "Path exploration with Angr")
        self.add_feature(binary_analysis, "Taint Analysis", "✓", "Data flow tracking")
        self.add_feature(binary_analysis, "ROP Gadget Finder", "✓", "Return-oriented programming chains")
        self.add_feature(binary_analysis, "Binary Similarity Search", "✓", "Find similar code patterns")
        self.add_feature(binary_analysis, "Multi-Format Analysis", "✓", "LIEF-based manipulation")
        self.add_feature(binary_analysis, "Import/Export Analysis", "✓", "API usage detection")
        self.add_feature(binary_analysis, "Section Analysis", "✓", "Entropy and permissions")
        self.add_feature(binary_analysis, "Concolic Execution", "✓", "Precise path finding")
        self.add_feature(binary_analysis, "Ghidra Integration", "✓", "Advanced decompilation")

        # License & Protection Detection (8 features)
        protection = QTreeWidgetItem(self.features_tree, ["Protection Detection", "", "License and protection mechanisms"])
        self.add_feature(protection, "Deep License Analysis", "✓", "Pattern recognition")
        self.add_feature(protection, "Commercial Protection", "✓", "Themida, VMProtect, etc.")
        self.add_feature(protection, "Hardware Dongle Detection", "✓", "SafeNet, HASP, CodeMeter")
        self.add_feature(protection, "TPM Protection", "✓", "Trusted Platform Module")
        self.add_feature(protection, "Obfuscation Detection", "✓", "Packing and encryption")
        self.add_feature(protection, "Anti-Debug Detection", "✓", "Debug prevention techniques")
        self.add_feature(protection, "VM/Sandbox Detection", "✓", "Environment checks")
        self.add_feature(protection, "License Weakness Detection", "✓", "Trial periods, activation")

        # Dynamic Analysis (6 features)
        dynamic = QTreeWidgetItem(self.features_tree, ["Dynamic Analysis", "", "Runtime monitoring and instrumentation"])
        self.add_feature(dynamic, "API Hooking", "✓", "Runtime API interception")
        self.add_feature(dynamic, "Deep Runtime Monitoring", "✓", "Process behavior analysis")
        self.add_feature(dynamic, "Dynamic Memory Analysis", "✓", "Memory pattern scanning")
        self.add_feature(dynamic, "Frida Instrumentation", "✓", "Dynamic code injection")
        self.add_feature(dynamic, "Process Behavior Analysis", "✓", "Real-time monitoring")
        self.add_feature(dynamic, "Memory Keyword Scan", "✓", "Search process memory")

        # Network Analysis (7 features)
        network = QTreeWidgetItem(self.features_tree, ["Network Analysis", "", "Network traffic and protocols"])
        self.add_feature(network, "Traffic Capture", "✓", "Packet sniffing")
        self.add_feature(network, "Protocol Fingerprinting", "✓", "License protocol detection")
        self.add_feature(network, "License Server Emulation", "✓", "Mock server responses")
        self.add_feature(network, "Cloud License Interception", "✓", "Online verification bypass")
        self.add_feature(network, "SSL/TLS Interception", "✓", "Encrypted traffic analysis")
        self.add_feature(network, "Network API Hooking", "✓", "Winsock, WinINet hooks")
        self.add_feature(network, "Traffic Report Generation", "✓", "Detailed analysis reports")

        # Vulnerability Detection (5 features)
        vulnerability = QTreeWidgetItem(self.features_tree, ["Vulnerability Detection", "", "Security weakness identification"])
        self.add_feature(vulnerability, "Static Vulnerability Scan", "✓", "Code analysis")
        self.add_feature(vulnerability, "Weak Crypto Detection", "✓", "Insecure algorithms")
        self.add_feature(vulnerability, "ML Vulnerability Prediction", "✓", "AI-based detection")
        self.add_feature(vulnerability, "Self-Healing Code", "✓", "Dynamic code detection")
        self.add_feature(vulnerability, "Checksum Verification", "✓", "Integrity checks")

        # Patching & Modification (7 features)
        patching = QTreeWidgetItem(self.features_tree, ["Patching", "", "Binary modification capabilities"])
        self.add_feature(patching, "Automated Patch Planning", "✓", "Intelligent patch generation")
        self.add_feature(patching, "AI-Driven Patching", "✓", "ML-based suggestions")
        self.add_feature(patching, "Static File Patching", "✓", "Direct binary modification")
        self.add_feature(patching, "Memory Patching", "✓", "Runtime modifications")
        self.add_feature(patching, "Visual Patch Editor", "✓", "GUI-based editing")
        self.add_feature(patching, "Patch Verification", "✓", "Test and validate")
        self.add_feature(patching, "Payload Generation", "✓", "Custom patch creation")

        # AI & ML Integration (5 features)
        ai_ml = QTreeWidgetItem(self.features_tree, ["AI Integration", "", "Machine learning features"])
        self.add_feature(ai_ml, "AI Assistant", "✓", "Interactive guidance")
        self.add_feature(ai_ml, "ML Vulnerability Prediction", "✓", "Pattern-based detection")
        self.add_feature(ai_ml, "Binary Similarity ML", "✓", "Code pattern matching")
        self.add_feature(ai_ml, "Feature Extraction", "✓", "Automated ML features")
        self.add_feature(ai_ml, "Model Fine-tuning", "✓", "Custom training")

        # Distributed & Performance (4 features)
        distributed = QTreeWidgetItem(self.features_tree, ["Performance", "", "Optimization and scaling"])
        self.add_feature(distributed, "Distributed Processing", "✓", "Multi-core analysis")
        self.add_feature(distributed, "GPU Acceleration", "✓", "CUDA/OpenCL support")
        self.add_feature(distributed, "Incremental Caching", "✓", "Analysis optimization")
        self.add_feature(distributed, "Memory Optimization", "✓", "Large file handling")

        # Reporting (4 features)
        reporting = QTreeWidgetItem(self.features_tree, ["Reporting", "", "Documentation and reports"])
        self.add_feature(reporting, "PDF Report Generation", "✓", "Professional reports")
        self.add_feature(reporting, "HTML Reports", "✓", "Interactive reports")
        self.add_feature(reporting, "Network Reports", "✓", "Traffic analysis")
        self.add_feature(reporting, "Custom Templates", "✓", "Report customization")

        # Plugin System (4 features)
        plugins = QTreeWidgetItem(self.features_tree, ["Plugin System", "", "Extensibility framework"])
        self.add_feature(plugins, "Python Plugins", "✓", "Custom modules")
        self.add_feature(plugins, "Frida Scripts", "✓", "Dynamic plugins")
        self.add_feature(plugins, "Ghidra Scripts", "✓", "Analysis plugins")
        self.add_feature(plugins, "Remote Execution", "✓", "Distributed plugins")

        # User Interface (7 features)
        ui = QTreeWidgetItem(self.features_tree, ["User Interface", "", "GUI components"])
        self.add_feature(ui, "Multi-Tab Interface", "✓", "Organized workspace")
        self.add_feature(ui, "Guided Wizard", "✓", "Step-by-step guide")
        self.add_feature(ui, "Hex Editor", "✓", "Binary editing")
        self.add_feature(ui, "CFG Visualizer", "✓", "Graph display")
        self.add_feature(ui, "Theme Support", "✓", "Light/Dark modes")
        self.add_feature(ui, "Dashboard", "✓", "Overview panel")
        self.add_feature(ui, "License Generator", "✓", "Key creation tool")

        # Utility Features (6 features)
        utility = QTreeWidgetItem(self.features_tree, ["Utilities", "", "Helper tools"])
        self.add_feature(utility, "Dependency Manager", "✓", "Auto-installation")
        self.add_feature(utility, "Logging System", "✓", "Comprehensive logs")
        self.add_feature(utility, "Multi-threading", "✓", "Async operations")
        self.add_feature(utility, "Icon Extraction", "✓", "Binary resources")
        self.add_feature(utility, "QEMU Integration", "✓", "Full emulation")
        self.add_feature(utility, "Script Extraction", "✓", "Embedded scripts")

        # Advanced Features (4 features)
        advanced = QTreeWidgetItem(self.features_tree, ["Advanced", "", "Research capabilities"])
        self.add_feature(advanced, "Dongle Emulation", "✓", "Hardware bypass")
        self.add_feature(advanced, "TPM Bypass", "✓", "Security chip bypass")
        self.add_feature(advanced, "HWID Spoofing", "✓", "Hardware ID faker")
        self.add_feature(advanced, "Time Bomb Defuser", "✓", "Expiration bypass")

        self.features_tree.expandAll()

    def add_feature(self, parent: QTreeWidgetItem, name: str, status: str, description: str):
        """Add a feature to the tree."""
        item = QTreeWidgetItem(parent, [name, status, description])
        # Color code based on status
        if status == "✓":
            item.setForeground(1, Qt.green)
        else:
            item.setForeground(1, Qt.red)

    def populate_getting_started_tutorials(self, list_widget: QListWidget):
        """Populate getting started tutorials."""
        tutorials = [
            "1. First Time Setup",
            "2. Loading Your First Binary",
            "3. Basic Static Analysis",
            "4. Understanding the Dashboard",
            "5. Using the Guided Wizard",
            "6. Setting Up External Tools",
            "7. Creating Your First Patch",
            "8. Using the AI Assistant"
        ]
        for _tutorial in tutorials:
            list_widget.addItem(_tutorial)

    def populate_analysis_tutorials(self, list_widget: QListWidget):
        """Populate analysis tutorials."""
        tutorials = [
            "1. PE File Analysis",
            "2. ELF Binary Analysis",
            "3. Control Flow Graph Analysis",
            "4. Symbolic Execution Basics",
            "5. Finding Vulnerabilities",
            "6. Protection Detection",
            "7. Dynamic Analysis with Frida",
            "8. Network Traffic Analysis",
            "9. Using Ghidra Integration",
            "10. Binary Similarity Search"
        ]
        for _tutorial in tutorials:
            list_widget.addItem(_tutorial)

    def populate_patching_tutorials(self, list_widget: QListWidget):
        """Populate patching tutorials."""
        tutorials = [
            "1. Understanding Patch Types",
            "2. Static Binary Patching",
            "3. Memory Patching Techniques",
            "4. Using the Visual Patch Editor",
            "5. License Check Bypass",
            "6. Time Limitation Removal",
            "7. Feature Unlocking",
            "8. Anti-Debug Bypass",
            "9. Creating Patch Scripts",
            "10. Verifying Patches"
        ]
        for _tutorial in tutorials:
            list_widget.addItem(_tutorial)

    def populate_advanced_tutorials(self, list_widget: QListWidget):
        """Populate advanced tutorials."""
        tutorials = [
            "1. Hardware Dongle Emulation",
            "2. TPM Protection Bypass",
            "3. Custom Plugin Development",
            "4. ML Model Training",
            "5. Distributed Analysis Setup",
            "6. GPU Acceleration Setup",
            "7. Advanced Frida Scripting",
            "8. Protocol Reverse Engineering",
            "9. Exploit Development",
            "10. Custom Report Templates"
        ]
        for _tutorial in tutorials:
            list_widget.addItem(_tutorial)

    def populate_troubleshooting_tree(self):
        """Populate troubleshooting tree."""
        # Installation issues
        install = QTreeWidgetItem(self.issues_tree, ["Installation Issues", "Setup"])
        QTreeWidgetItem(install, ["Dependencies not installing", "Setup"])
        QTreeWidgetItem(install, ["GPU not detected", "Setup"])
        QTreeWidgetItem(install, ["Qt initialization errors", "Setup"])

        # Analysis issues
        analysis = QTreeWidgetItem(self.issues_tree, ["Analysis Issues", "Analysis"])
        QTreeWidgetItem(analysis, ["Binary not loading", "Analysis"])
        QTreeWidgetItem(analysis, ["Analysis hanging", "Analysis"])
        QTreeWidgetItem(analysis, ["Out of memory errors", "Analysis"])

        # Tool integration
        tools = QTreeWidgetItem(self.issues_tree, ["Tool Integration", "Tools"])
        QTreeWidgetItem(tools, ["Ghidra not found", "Tools"])
        QTreeWidgetItem(tools, ["Radare2 errors", "Tools"])
        QTreeWidgetItem(tools, ["Frida connection failed", "Tools"])

        # Network issues
        network = QTreeWidgetItem(self.issues_tree, ["Network Issues", "Network"])
        QTreeWidgetItem(network, ["Capture not working", "Network"])
        QTreeWidgetItem(network, ["SSL interception failing", "Network"])

        self.issues_tree.expandAll()

    def load_welcome_content(self):
        """Load the welcome content."""
        welcome_html = """
        <h1>Welcome to Intellicrack Help & Documentation</h1>

        <p>Intellicrack is a comprehensive binary analysis and security research tool that provides:</p>

        <ul>
            <li><b>78 Powerful Features</b> for analysis, patching, and research</li>
            <li><b>AI Integration</b> for intelligent guidance and automation</li>
            <li><b>Multi-Format Support</b> for PE, ELF, and Mach-O binaries</li>
            <li><b>Advanced Analysis</b> including symbolic execution and vulnerability detection</li>
            <li><b>Network Analysis</b> for protocol reverse engineering</li>
            <li><b>Extensible Plugin System</b> for custom functionality</li>
        </ul>

        <h2>Getting Started</h2>
        <p>New to Intellicrack? Start with these resources:</p>
        <ul>
            <li>Click <b>Features</b> tab to explore all capabilities</li>
            <li>Check <b>Tutorials</b> for step-by-step guides</li>
            <li>Use <b>Troubleshooting</b> if you encounter issues</li>
            <li>Navigate topics using the tree on the left</li>
        </ul>

        <h2>Quick Links</h2>
        <ul>
            <li><a href="#guided-wizard">Run the Guided Wizard</a></li>
            <li><a href="#first-analysis">Your First Analysis</a></li>
            <li><a href="#ai-assistant">Using the AI Assistant</a></li>
            <li><a href="#plugin-dev">Developing Plugins</a></li>
        </ul>

        <p><i>Use the search box above to quickly find specific topics.</i></p>
        """
        self.doc_browser.setHtml(welcome_html)

    def on_nav_item_clicked(self, item: QTreeWidgetItem, column: int):
        """Handle navigation item click."""
        # Note: column parameter is required by Qt signal but not used
        _ = column  # Acknowledge unused parameter
        if item.parent():
            category = item.parent().text(0)
            topic = item.text(0)
            self.load_documentation_content(category, topic)

    def on_feature_double_clicked(self, item: QTreeWidgetItem, column: int):
        """Handle feature double-click to launch it."""
        # Note: column parameter is required by Qt signal but not used
        _ = column  # Acknowledge unused parameter
        if item.parent():
            category = item.parent().text(0)
            feature = item.text(0)

            # Show how to use this feature
            self.show_feature_details(category, feature)

            # Ask if user wants to try the feature
            reply = QMessageBox.question(
                self,
                "Try Feature",
                f"Would you like to try '{feature}' now?",
                QMessageBox.Yes | QMessageBox.No
            )

            if reply == QMessageBox.Yes:
                self.feature_selected.emit(category, feature)

    def show_feature_details(self, category: str, feature: str):
        """Show detailed information about a feature."""
        _ = category
        # Feature documentation mapping
        feature_docs = {
            "Static Binary Analysis": """
                <h3>Static Binary Analysis</h3>
                <p>Analyze PE, ELF, and Mach-O binaries without execution.</p>

                <h4>How to use:</h4>
                <ol>
                    <li>Go to Analysis tab</li>
                    <li>Load a binary file</li>
                    <li>Click "Run Full Static Analysis"</li>
                </ol>

                <h4>What it does:</h4>
                <ul>
                    <li>Extracts headers and sections</li>
                    <li>Identifies imports and exports</li>
                    <li>Calculates entropy</li>
                    <li>Detects packers and compilers</li>
                </ul>
            """,
            "Control Flow Graph": """
                <h3>Control Flow Graph (CFG)</h3>
                <p>Visualize program execution paths and basic blocks.</p>

                <h4>How to use:</h4>
                <ol>
                    <li>Load a binary in Analysis tab</li>
                    <li>Click "View/Analyze CFG"</li>
                    <li>Use the graph viewer to explore</li>
                </ol>

                <h4>Features:</h4>
                <ul>
                    <li>Interactive graph navigation</li>
                    <li>Basic block analysis</li>
                    <li>Path highlighting</li>
                    <li>Export to various formats</li>
                </ul>
            """,
            # Add more feature documentation...
        }

        doc = feature_docs.get(feature, f"<h3>{feature}</h3><p>Documentation coming soon...</p>")
        self.feature_details.setHtml(doc)

    def on_tutorial_selected(self, item: QListWidgetItem):
        """Handle tutorial selection."""
        tutorial_name = item.text()
        self.load_tutorial_content(tutorial_name)

    def load_tutorial_content(self, tutorial_name: str):
        """Load tutorial content."""
        # Tutorial content mapping
        tutorials = {
            "1. First Time Setup": """
                <h3>First Time Setup</h3>

                <h4>Step 1: Install Dependencies</h4>
                <p>Run the dependency installer:</p>
                <pre>dependencies\\install_dependencies.bat</pre>

                <h4>Step 2: Configure Settings</h4>
                <p>Go to Settings tab and configure:</p>
                <ul>
                    <li>Binary analysis paths</li>
                    <li>Tool locations (Ghidra, radare2)</li>
                    <li>AI model settings</li>
                </ul>

                <h4>Step 3: Verify Installation</h4>
                <p>Check that all components are working:</p>
                <ul>
                    <li>Green checkmarks in dashboard</li>
                    <li>No errors in logs tab</li>
                </ul>
            """,
            # Add more tutorials...
        }

        content = tutorials.get(tutorial_name, "<p>Tutorial content loading...</p>")
        self.tutorial_viewer.setHtml(content)

    def on_issue_selected(self, item: QTreeWidgetItem, column: int):
        """Handle troubleshooting issue selection."""
        # Note: column parameter is required by Qt signal but not used
        _ = column  # Acknowledge unused parameter
        if item.parent():
            issue = item.text(0)
            self.load_solution(issue)

    def load_solution(self, issue: str):
        """Load solution for an issue."""
        solutions = {
            "Dependencies not installing": """
                <h3>Dependencies Not Installing</h3>

                <h4>Common Causes:</h4>
                <ul>
                    <li>Missing Visual C++ redistributables</li>
                    <li>Python version mismatch</li>
                    <li>Network/firewall issues</li>
                </ul>

                <h4>Solutions:</h4>
                <ol>
                    <li>Install Visual C++ 2019 redistributable</li>
                    <li>Ensure Python 3.8+ is installed</li>
                    <li>Run as administrator</li>
                    <li>Check firewall settings</li>
                    <li>Try manual pip install for failed packages</li>
                </ol>
            """,
            "GPU not detected": """
                <h3>GPU Not Detected</h3>

                <h4>Common Causes:</h4>
                <ul>
                    <li>CUDA not installed</li>
                    <li>Incompatible GPU</li>
                    <li>Driver issues</li>
                </ul>

                <h4>Solutions:</h4>
                <ol>
                    <li>Install CUDA Toolkit 11.0+</li>
                    <li>Update GPU drivers</li>
                    <li>Check GPU compatibility</li>
                    <li>GPU is optional - CPU fallback works</li>
                </ol>
            """,
            # Add more solutions...
        }

        solution = solutions.get(issue, "<p>Solution documentation coming soon...</p>")
        self.solution_viewer.setHtml(solution)

    def load_documentation_content(self, category: str, topic: str):
        """Load documentation content based on category and topic."""
        # Documentation content mapping
        content_map = {
            ("Overview", "Welcome"): self.load_welcome_content,
            ("Overview", "Getting Started"): lambda: self.doc_browser.setHtml("""
                <h1>Getting Started with Intellicrack</h1>

                <h2>Quick Start Guide</h2>
                <ol>
                    <li><b>Install Intellicrack</b>
                        <ul>
                            <li>Run install_dependencies.bat</li>
                            <li>Launch with RUN_INTELLICRACK.bat</li>
                        </ul>
                    </li>
                    <li><b>Load a Binary</b>
                        <ul>
                            <li>Click "Load Binary" in Analysis tab</li>
                            <li>Select your target executable</li>
                        </ul>
                    </li>
                    <li><b>Run Analysis</b>
                        <ul>
                            <li>Choose analysis type (static/dynamic)</li>
                            <li>Click "Analyze" button</li>
                            <li>Review results in output panel</li>
                        </ul>
                    </li>
                    <li><b>Apply Patches</b>
                        <ul>
                            <li>Go to Patching tab</li>
                            <li>Select patch type</li>
                            <li>Apply and test</li>
                        </ul>
                    </li>
                </ol>

                <h2>Recommended Workflow</h2>
                <p>For best results, follow this workflow:</p>
                <ol>
                    <li>Static analysis first</li>
                    <li>Protection detection</li>
                    <li>Dynamic analysis if needed</li>
                    <li>Plan patches based on findings</li>
                    <li>Test patches thoroughly</li>
                </ol>
            """),
            # Add more content mappings...
        }

        # Get the content loader function
        loader = content_map.get((category, topic))
        if loader:
            loader()
        else:
            # Default content
            self.doc_browser.setHtml(f"""
                <h1>{topic}</h1>
                <p>Category: {category}</p>
                <p>Documentation for this topic is being prepared...</p>
            """)

    def on_search_changed(self, text: str):
        """Handle search text change."""
        if not text:
            # Show all items
            self.show_all_tree_items(self.nav_tree)
            self.show_all_tree_items(self.features_tree)
            self.show_all_tree_items(self.issues_tree)

    def perform_search(self):
        """Perform search across all documentation."""
        search_text = self.search_edit.text().lower()
        if not search_text:
            return

        # Search in navigation tree
        self.search_tree(self.nav_tree, search_text)

        # Search in features tree
        self.search_tree(self.features_tree, search_text)

        # Search in troubleshooting tree
        self.search_tree(self.issues_tree, search_text)

        # Show search results in documentation browser
        results_html = f"""
        <h2>Search Results for "{search_text}"</h2>
        <p>Matching items are highlighted in the navigation trees.</p>
        <p>Click on any item to view its documentation.</p>
        """
        self.doc_browser.setHtml(results_html)

    def search_tree(self, tree: QTreeWidget, search_text: str):
        """Search and highlight items in a tree widget."""
        # First hide all items
        self.hide_all_tree_items(tree)

        # Then show matching items
        for _i in range(tree.topLevelItemCount()):
            item = tree.topLevelItem(_i)
            if self.search_tree_item(item, search_text):
                item.setHidden(False)
                item.setExpanded(True)

    def search_tree_item(self, item: QTreeWidgetItem, search_text: str) -> bool:
        """Recursively search tree items."""
        # Check if this item matches
        matches = False
        for _col in range(item.columnCount()):
            if search_text in item.text(_col).lower():
                matches = True
                item.setBackground(_col, Qt.yellow)
            else:
                item.setBackground(_col, Qt.transparent)

        # Check children
        child_matches = False
        for _i in range(item.childCount()):
            child = item.child(_i)
            if self.search_tree_item(child, search_text):
                child_matches = True
                child.setHidden(False)
            else:
                child.setHidden(True)

        # Show item if it or its children match
        if matches or child_matches:
            item.setHidden(False)
            return True
        else:
            item.setHidden(True)
            return False

    def hide_all_tree_items(self, tree: QTreeWidget):
        """Hide all items in a tree."""
        for _i in range(tree.topLevelItemCount()):
            self.hide_tree_item(tree.topLevelItem(_i))

    def hide_tree_item(self, item: QTreeWidgetItem):
        """Recursively hide tree items."""
        item.setHidden(True)
        for _i in range(item.childCount()):
            self.hide_tree_item(item.child(_i))

    def show_all_tree_items(self, tree: QTreeWidget):
        """Show all items in a tree."""
        for _i in range(tree.topLevelItemCount()):
            self.show_tree_item(tree.topLevelItem(_i))

    def show_tree_item(self, item: QTreeWidgetItem):
        """Recursively show tree items and clear highlights."""
        item.setHidden(False)
        for _col in range(item.columnCount()):
            item.setBackground(_col, Qt.transparent)
        for _i in range(item.childCount()):
            self.show_tree_item(item.child(_i))
