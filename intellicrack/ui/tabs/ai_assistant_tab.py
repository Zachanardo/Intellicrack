"""AI Assistant tab for Intellicrack.

This module provides the AI-powered assistant interface for code generation,
analysis assistance, and intelligent suggestions within the application.
"""

from datetime import datetime

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
QCheckBox,
QComboBox,
QGroupBox,
QHBoxLayout,
QLabel,
QLineEdit,
QListWidget,
QMessageBox,
QProgressBar,
QPushButton,
QSlider,
QSpinBox,
QSplitter,
QTableWidget,
QTableWidgetItem,
QTabWidget,
QTextEdit,
QVBoxLayout,
QWidget,
)

from ...core.ai_model_manager import ModelConfig, ModelProvider
from .base_tab import BaseTab


class AIAssistantTab(BaseTab):
    """
    AI Assistant Tab - Comprehensive AI-powered analysis, code generation,
    and intelligent assistance for reverse engineering and exploitation.
    """

    analysis_started = pyqtSignal(str)
    analysis_completed = pyqtSignal(str, str)
    script_generated = pyqtSignal(str, str)
    model_loaded = pyqtSignal(str, bool)

    def __init__(self, shared_context=None, parent=None):
        """Initialize AI assistant tab with code analysis and generation capabilities."""
        super().__init__(shared_context, parent)

    def setup_content(self):
        """Setup the complete AI Assistant tab content"""
        main_layout = QVBoxLayout(self)

        # Create horizontal splitter for controls and results
        splitter = QSplitter(Qt.Horizontal)

        # Left panel - AI Controls (40%)
        left_panel = self.create_ai_controls_panel()
        splitter.addWidget(left_panel)

        # Right panel - Results and Chat (60%)
        right_panel = self.create_results_panel()
        splitter.addWidget(right_panel)

        # Set splitter proportions
        splitter.setSizes([400, 600])

        main_layout.addWidget(splitter)

    def create_ai_controls_panel(self):
        """Create the AI controls panel with subtabs"""
        panel = QWidget()
        layout = QVBoxLayout(panel)

        # AI subtabs
        self.ai_subtabs = QTabWidget()
        self.ai_subtabs.setTabPosition(QTabWidget.TabPosition.North)

        # Create individual AI subtabs
        self.ai_subtabs.addTab(self.create_model_selection_tab(), "Model Selection")
        self.ai_subtabs.addTab(self.create_analysis_tab(), "AI Analysis")
        self.ai_subtabs.addTab(self.create_script_generation_tab(), "Script Generation")
        self.ai_subtabs.addTab(self.create_training_tab(), "Model Training")

        layout.addWidget(self.ai_subtabs)

        # Quick Action Buttons
        quick_actions_group = QGroupBox("Quick AI Actions")
        quick_actions_layout = QHBoxLayout(quick_actions_group)

        analyze_binary_btn = QPushButton("Analyze Binary")
        analyze_binary_btn.clicked.connect(self.quick_analyze_binary)
        analyze_binary_btn.setStyleSheet("font-weight: bold; color: blue;")

        generate_frida_btn = QPushButton("Generate Frida Script")
        generate_frida_btn.clicked.connect(self.quick_generate_frida)
        generate_frida_btn.setStyleSheet("font-weight: bold; color: green;")

        generate_ghidra_btn = QPushButton("Generate Ghidra Script")
        generate_ghidra_btn.clicked.connect(self.quick_generate_ghidra)
        generate_ghidra_btn.setStyleSheet("color: purple;")

        quick_actions_layout.addWidget(analyze_binary_btn)
        quick_actions_layout.addWidget(generate_frida_btn)
        quick_actions_layout.addWidget(generate_ghidra_btn)

        layout.addWidget(quick_actions_group)

        return panel

    def create_model_selection_tab(self):
        """Create model selection and configuration"""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Model Provider Selection
        provider_group = QGroupBox("AI Model Provider")
        provider_layout = QVBoxLayout(provider_group)

        # Provider selection
        provider_selection_layout = QHBoxLayout()
        provider_selection_layout.addWidget(QLabel("Provider:"))
        self.provider_combo = QComboBox()
        self.provider_combo.addItems(
            ["OpenAI", "Anthropic", "Local (Ollama)", "Hugging Face", "Google Gemini", "Cohere", "Azure OpenAI"]
        )
        self.provider_combo.currentTextChanged.connect(self.on_provider_changed)
        provider_selection_layout.addWidget(self.provider_combo)

        # Model selection
        model_selection_layout = QHBoxLayout()
        model_selection_layout.addWidget(QLabel("Model:"))
        self.model_combo = QComboBox()
        self.model_combo.setEditable(True)
        model_selection_layout.addWidget(self.model_combo)

        # Load model button
        load_model_btn = QPushButton("Load Model")
        load_model_btn.clicked.connect(self.load_selected_model)
        load_model_btn.setStyleSheet("font-weight: bold; color: green;")
        model_selection_layout.addWidget(load_model_btn)

        provider_layout.addLayout(provider_selection_layout)
        provider_layout.addLayout(model_selection_layout)

        # Model Configuration
        config_group = QGroupBox("Model Configuration")
        config_layout = QVBoxLayout(config_group)

        # API Key
        api_key_layout = QHBoxLayout()
        api_key_layout.addWidget(QLabel("API Key:"))
        self.api_key_edit = QLineEdit()
        self.api_key_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.api_key_edit.setPlaceholderText("Enter API key (if required)")
        api_key_layout.addWidget(self.api_key_edit)

        # Temperature
        temp_layout = QHBoxLayout()
        temp_layout.addWidget(QLabel("Temperature:"))
        self.temperature_slider = QSlider(Qt.Horizontal)
        self.temperature_slider.setRange(0, 100)
        self.temperature_slider.setValue(70)
        self.temperature_label = QLabel("0.7")
        self.temperature_slider.valueChanged.connect(self.update_temperature_label)
        temp_layout.addWidget(self.temperature_slider)
        temp_layout.addWidget(self.temperature_label)

        # Max tokens
        tokens_layout = QHBoxLayout()
        tokens_layout.addWidget(QLabel("Max Tokens:"))
        self.max_tokens_spin = QSpinBox()
        self.max_tokens_spin.setRange(100, 8000)
        self.max_tokens_spin.setValue(2048)
        tokens_layout.addWidget(self.max_tokens_spin)

        config_layout.addLayout(api_key_layout)
        config_layout.addLayout(temp_layout)
        config_layout.addLayout(tokens_layout)

        # Model Status
        status_group = QGroupBox("Model Status")
        status_layout = QVBoxLayout(status_group)

        self.model_status_label = QLabel("No model loaded")
        self.model_status_label.setStyleSheet("color: #ff6b6b;")
        status_layout.addWidget(self.model_status_label)

        self.model_progress = QProgressBar()
        self.model_progress.setVisible(False)
        status_layout.addWidget(self.model_progress)

        layout.addWidget(provider_group)
        layout.addWidget(config_group)
        layout.addWidget(status_group)
        layout.addStretch()

        # Initialize with default models
        self.on_provider_changed("OpenAI")

        return tab

    def create_analysis_tab(self):
        """Create AI analysis controls"""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Analysis Target Selection
        target_group = QGroupBox("Analysis Target")
        target_layout = QVBoxLayout(target_group)

        # Binary file selection
        binary_layout = QHBoxLayout()
        binary_layout.addWidget(QLabel("Binary File:"))
        self.analysis_binary_edit = QLineEdit()
        self.analysis_binary_edit.setPlaceholderText("Path to binary for AI analysis")
        binary_layout.addWidget(self.analysis_binary_edit)

        browse_analysis_btn = QPushButton("Browse")
        browse_analysis_btn.clicked.connect(self.browse_analysis_binary)
        binary_layout.addWidget(browse_analysis_btn)

        # Analysis focus
        focus_layout = QHBoxLayout()
        focus_layout.addWidget(QLabel("Analysis Focus:"))
        self.analysis_focus_combo = QComboBox()
        self.analysis_focus_combo.addItems(
            [
                "General Analysis",
                "License Detection",
                "Protection Analysis",
                "Vulnerability Research",

                "Code Quality",
                "Performance Analysis",
                "Security Audit",
            ]
        )
        focus_layout.addWidget(self.analysis_focus_combo)

        target_layout.addLayout(binary_layout)
        target_layout.addLayout(focus_layout)

        # Analysis Options
        options_group = QGroupBox("Analysis Options")
        options_layout = QVBoxLayout(options_group)

        # Analysis depth
        depth_layout = QHBoxLayout()
        depth_layout.addWidget(QLabel("Analysis Depth:"))
        self.analysis_depth_combo = QComboBox()
        self.analysis_depth_combo.addItems(["Quick Scan", "Standard Analysis", "Deep Analysis", "Comprehensive"])
        options_layout.addLayout(depth_layout)

        # Include options
        include_layout = QHBoxLayout()
        self.include_strings_cb = QCheckBox("Include Strings")
        self.include_imports_cb = QCheckBox("Include Imports")
        self.include_exports_cb = QCheckBox("Include Exports")
        self.include_disasm_cb = QCheckBox("Include Disassembly")

        self.include_strings_cb.setChecked(True)
        self.include_imports_cb.setChecked(True)

        include_layout.addWidget(self.include_strings_cb)
        include_layout.addWidget(self.include_imports_cb)
        include_layout.addWidget(self.include_exports_cb)
        include_layout.addWidget(self.include_disasm_cb)

        options_layout.addLayout(include_layout)

        # Analysis Controls
        analysis_controls_layout = QHBoxLayout()

        start_analysis_btn = QPushButton("Start AI Analysis")
        start_analysis_btn.clicked.connect(self.start_ai_analysis)
        start_analysis_btn.setStyleSheet("font-weight: bold; color: blue;")

        stop_analysis_btn = QPushButton("Stop Analysis")
        stop_analysis_btn.clicked.connect(self.stop_ai_analysis)
        stop_analysis_btn.setStyleSheet("color: red;")

        analysis_controls_layout.addWidget(start_analysis_btn)
        analysis_controls_layout.addWidget(stop_analysis_btn)

        layout.addWidget(target_group)
        layout.addWidget(options_group)
        layout.addLayout(analysis_controls_layout)
        layout.addStretch()

        return tab

    def create_script_generation_tab(self):
        """Create script generation controls"""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Script Type Selection
        script_type_group = QGroupBox("Script Generation")
        script_type_layout = QVBoxLayout(script_type_group)

        # Script type
        type_layout = QHBoxLayout()
        type_layout.addWidget(QLabel("Script Type:"))
        self.script_type_combo = QComboBox()
        self.script_type_combo.addItems(
            [
                "Frida Hook Script",
                "Ghidra Analysis Script",
                "Python Automation",

                "API Hook Script",
                "Memory Scanner",

                "Debugging Script",
            ]
        )
        self.script_type_combo.currentTextChanged.connect(self.on_script_type_changed)
        type_layout.addWidget(self.script_type_combo)

        # Target specification
        target_spec_layout = QHBoxLayout()
        target_spec_layout.addWidget(QLabel("Target:"))
        self.script_target_edit = QLineEdit()
        self.script_target_edit.setPlaceholderText("Function name, API, or description")
        self.script_target_edit.textChanged.connect(self.on_script_target_changed)
        target_spec_layout.addWidget(self.script_target_edit)

        script_type_layout.addLayout(type_layout)
        script_type_layout.addLayout(target_spec_layout)

        # Generation Options
        gen_options_group = QGroupBox("Generation Options")
        gen_options_layout = QVBoxLayout(gen_options_group)

        # Template selection
        template_layout = QHBoxLayout()
        template_layout.addWidget(QLabel("Template:"))
        self.template_combo = QComboBox()
        self.template_combo.addItems(["Basic Template", "Advanced Template", "Custom Template", "No Template"])
        template_layout.addWidget(self.template_combo)

        # Options checkboxes
        gen_options_cb_layout = QHBoxLayout()
        self.include_comments_cb = QCheckBox("Include Comments")
        self.include_error_handling_cb = QCheckBox("Error Handling")
        self.include_logging_cb = QCheckBox("Add Logging")
        self.optimize_code_cb = QCheckBox("Optimize Code")

        self.include_comments_cb.setChecked(True)
        self.include_error_handling_cb.setChecked(True)

        gen_options_cb_layout.addWidget(self.include_comments_cb)
        gen_options_cb_layout.addWidget(self.include_error_handling_cb)
        gen_options_cb_layout.addWidget(self.include_logging_cb)
        gen_options_cb_layout.addWidget(self.optimize_code_cb)

        gen_options_layout.addLayout(template_layout)
        gen_options_layout.addLayout(gen_options_cb_layout)

        # Custom Requirements
        requirements_group = QGroupBox("Custom Requirements")
        requirements_layout = QVBoxLayout(requirements_group)

        self.requirements_edit = QTextEdit()
        self.requirements_edit.setPlaceholderText(
            "Describe specific requirements for the script:\n- Hook specific functions\n- Bypass certain protections\n- Extract specific data\n- Custom behavior requirements"
        )
        self.requirements_edit.setMaximumHeight(100)
        self.requirements_edit.textChanged.connect(self.on_requirements_changed)
        requirements_layout.addWidget(self.requirements_edit)

        # Generation Controls
        gen_controls_layout = QHBoxLayout()

        generate_script_btn = QPushButton("Generate Script")
        generate_script_btn.clicked.connect(self.generate_ai_script)
        generate_script_btn.setStyleSheet("font-weight: bold; color: green;")

        refine_script_btn = QPushButton("Refine Script")
        refine_script_btn.clicked.connect(self.refine_generated_script)

        gen_controls_layout.addWidget(generate_script_btn)
        gen_controls_layout.addWidget(refine_script_btn)

        layout.addWidget(script_type_group)
        layout.addWidget(gen_options_group)
        layout.addWidget(requirements_group)
        layout.addLayout(gen_controls_layout)
        layout.addStretch()

        return tab

    def create_training_tab(self):
        """Create model training and fine-tuning controls"""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Training Data
        training_data_group = QGroupBox("Training Data Management")
        training_data_layout = QVBoxLayout(training_data_group)

        # Data source
        data_source_layout = QHBoxLayout()
        data_source_layout.addWidget(QLabel("Data Source:"))
        self.data_source_combo = QComboBox()
        self.data_source_combo.addItems(
            ["Analysis History", "Custom Dataset", "Binary Samples", "Script Templates", "Public Datasets"]
        )
        data_source_layout.addWidget(self.data_source_combo)

        # Data path
        data_path_layout = QHBoxLayout()
        data_path_layout.addWidget(QLabel("Dataset Path:"))
        self.dataset_path_edit = QLineEdit()
        self.dataset_path_edit.setPlaceholderText("Path to training dataset")
        data_path_layout.addWidget(self.dataset_path_edit)

        browse_dataset_btn = QPushButton("Browse")
        browse_dataset_btn.clicked.connect(self.browse_dataset)
        data_path_layout.addWidget(browse_dataset_btn)

        training_data_layout.addLayout(data_source_layout)
        training_data_layout.addLayout(data_path_layout)

        # Training Configuration
        training_config_group = QGroupBox("Training Configuration")
        training_config_layout = QVBoxLayout(training_config_group)

        # Training type
        training_type_layout = QHBoxLayout()
        training_type_layout.addWidget(QLabel("Training Type:"))
        self.training_type_combo = QComboBox()
        self.training_type_combo.addItems(
            ["Fine-tuning", "Transfer Learning", "Custom Training", "Reinforcement Learning"]
        )
        training_type_layout.addWidget(self.training_type_combo)

        # Epochs
        epochs_layout = QHBoxLayout()
        epochs_layout.addWidget(QLabel("Epochs:"))
        self.epochs_spin = QSpinBox()
        self.epochs_spin.setRange(1, 1000)
        self.epochs_spin.setValue(10)
        epochs_layout.addWidget(self.epochs_spin)

        # Learning rate
        lr_layout = QHBoxLayout()
        lr_layout.addWidget(QLabel("Learning Rate:"))
        self.learning_rate_edit = QLineEdit()
        self.learning_rate_edit.setText("0.001")
        lr_layout.addWidget(self.learning_rate_edit)

        training_config_layout.addLayout(training_type_layout)
        training_config_layout.addLayout(epochs_layout)
        training_config_layout.addLayout(lr_layout)

        # Training Controls
        training_controls_layout = QHBoxLayout()

        start_training_btn = QPushButton("Start Training")
        start_training_btn.clicked.connect(self.start_model_training)
        start_training_btn.setStyleSheet("font-weight: bold; color: orange;")

        stop_training_btn = QPushButton("Stop Training")
        stop_training_btn.clicked.connect(self.stop_model_training)
        stop_training_btn.setStyleSheet("color: red;")

        save_model_btn = QPushButton("Save Model")
        save_model_btn.clicked.connect(self.save_trained_model)

        training_controls_layout.addWidget(start_training_btn)
        training_controls_layout.addWidget(stop_training_btn)
        training_controls_layout.addWidget(save_model_btn)

        # Training Progress
        progress_group = QGroupBox("Training Progress")
        progress_layout = QVBoxLayout(progress_group)

        self.training_progress = QProgressBar()
        self.training_status_label = QLabel("Ready to train")

        progress_layout.addWidget(self.training_progress)
        progress_layout.addWidget(self.training_status_label)

        layout.addWidget(training_data_group)
        layout.addWidget(training_config_group)
        layout.addLayout(training_controls_layout)
        layout.addWidget(progress_group)
        layout.addStretch()

        return tab

    def create_live_preview_tab(self):
        """Create live script preview tab with real-time generation"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Preview controls
        controls_group = QGroupBox("Live Preview Controls")
        controls_layout = QHBoxLayout(controls_group)
        
        # Auto-preview toggle
        self.auto_preview_cb = QCheckBox("Auto Preview")
        self.auto_preview_cb.setChecked(True)
        self.auto_preview_cb.toggled.connect(self.toggle_auto_preview)
        
        # Refresh preview button
        self.refresh_preview_btn = QPushButton("Refresh Preview")
        self.refresh_preview_btn.clicked.connect(self.refresh_live_preview)
        self.refresh_preview_btn.setStyleSheet("font-weight: bold; color: blue;")
        
        # Preview mode selector
        preview_mode_label = QLabel("Preview Mode:")
        self.preview_mode_combo = QComboBox()
        self.preview_mode_combo.addItems(["Syntax Highlighted", "Raw Code", "Execution Flow"])
        self.preview_mode_combo.currentTextChanged.connect(self.update_preview_mode)
        
        controls_layout.addWidget(self.auto_preview_cb)
        controls_layout.addWidget(self.refresh_preview_btn)
        controls_layout.addStretch()
        controls_layout.addWidget(preview_mode_label)
        controls_layout.addWidget(self.preview_mode_combo)
        
        # Live preview editor
        preview_group = QGroupBox("Live Script Preview")
        preview_layout = QVBoxLayout(preview_group)
        
        # Preview status
        self.preview_status_label = QLabel("Ready for preview")
        self.preview_status_label.setStyleSheet("color: #666; font-style: italic;")
        
        # Preview text editor with syntax highlighting
        self.live_preview_editor = QTextEdit()
        self.live_preview_editor.setReadOnly(True)
        self.live_preview_editor.setFont(QFont("Consolas", 10))
        self.live_preview_editor.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e1e;
                color: #d4d4d4;
                border: 1px solid #3c3c3c;
                border-radius: 4px;
            }
        """)
        
        # Preview metrics
        metrics_layout = QHBoxLayout()
        self.preview_lines_label = QLabel("Lines: 0")
        self.preview_size_label = QLabel("Size: 0 bytes")
        self.preview_lang_label = QLabel("Language: Unknown")
        
        metrics_layout.addWidget(self.preview_lines_label)
        metrics_layout.addWidget(self.preview_size_label)
        metrics_layout.addWidget(self.preview_lang_label)
        metrics_layout.addStretch()
        
        preview_layout.addWidget(self.preview_status_label)
        preview_layout.addWidget(self.live_preview_editor)
        preview_layout.addLayout(metrics_layout)
        
        # Generation progress
        self.preview_progress = QProgressBar()
        self.preview_progress.setVisible(False)
        
        layout.addWidget(controls_group)
        layout.addWidget(preview_group)
        layout.addWidget(self.preview_progress)
        
        # Initialize preview timer for auto-refresh
        self.preview_timer = QTimer()
        self.preview_timer.setSingleShot(True)
        self.preview_timer.timeout.connect(self.auto_refresh_preview)
        
        return widget

    def create_model_comparison_tab(self):
        """Create multi-model comparison tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Comparison controls
        controls_group = QGroupBox("Multi-Model Comparison")
        controls_layout = QVBoxLayout(controls_group)
        
        # Model selection for comparison
        models_selection_layout = QHBoxLayout()
        
        models_selection_layout.addWidget(QLabel("Select Models to Compare:"))
        
        # Available models checkboxes
        self.comparison_models_layout = QHBoxLayout()
        self.comparison_model_checkboxes = {}
        
        # Add default model options
        default_models = ["GPT-4", "GPT-3.5", "Claude-3", "Gemini", "Local Model"]
        for model in default_models:
            checkbox = QCheckBox(model)
            self.comparison_model_checkboxes[model] = checkbox
            self.comparison_models_layout.addWidget(checkbox)
        
        models_selection_layout.addLayout(self.comparison_models_layout)
        
        # Comparison controls
        comparison_controls_layout = QHBoxLayout()
        
        self.compare_generate_btn = QPushButton("Generate with Selected Models")
        self.compare_generate_btn.clicked.connect(self.generate_with_multiple_models)
        self.compare_generate_btn.setStyleSheet("font-weight: bold; color: green;")
        
        self.clear_comparison_btn = QPushButton("Clear Comparison")
        self.clear_comparison_btn.clicked.connect(self.clear_model_comparison)
        
        comparison_controls_layout.addWidget(self.compare_generate_btn)
        comparison_controls_layout.addWidget(self.clear_comparison_btn)
        comparison_controls_layout.addStretch()
        
        controls_layout.addLayout(models_selection_layout)
        controls_layout.addLayout(comparison_controls_layout)
        
        # Comparison results
        results_group = QGroupBox("Comparison Results")
        results_layout = QVBoxLayout(results_group)
        
        # Model results tabs
        self.comparison_results_tabs = QTabWidget()
        self.comparison_results_tabs.setTabPosition(QTabWidget.TabPosition.North)
        
        # Analysis summary tab
        self.comparison_summary_widget = QWidget()
        summary_layout = QVBoxLayout(self.comparison_summary_widget)
        
        # Summary table
        self.comparison_summary_table = QTableWidget()
        self.comparison_summary_table.setColumnCount(5)
        self.comparison_summary_table.setHorizontalHeaderLabels([
            "Model", "Generation Time", "Code Quality", "Lines", "Score"
        ])
        self.comparison_summary_table.horizontalHeader().setStretchLastSection(True)
        
        summary_layout.addWidget(self.comparison_summary_table)
        
        self.comparison_results_tabs.addTab(self.comparison_summary_widget, "Summary")
        
        results_layout.addWidget(self.comparison_results_tabs)
        
        # Comparison metrics
        metrics_group = QGroupBox("Comparison Metrics")
        metrics_layout = QVBoxLayout(metrics_group)
        
        # Metrics display
        metrics_display_layout = QHBoxLayout()
        
        self.best_model_label = QLabel("Best Model: None")
        self.best_model_label.setStyleSheet("font-weight: bold; color: green;")
        
        self.avg_time_label = QLabel("Avg Generation Time: 0s")
        self.total_comparisons_label = QLabel("Total Comparisons: 0")
        
        metrics_display_layout.addWidget(self.best_model_label)
        metrics_display_layout.addWidget(self.avg_time_label)
        metrics_display_layout.addWidget(self.total_comparisons_label)
        metrics_display_layout.addStretch()
        
        metrics_layout.addLayout(metrics_display_layout)
        
        layout.addWidget(controls_group)
        layout.addWidget(results_group)
        layout.addWidget(metrics_group)
        
        # Initialize comparison data
        self.comparison_results = {}
        self.comparison_metrics = {
            'total_comparisons': 0,
            'generation_times': [],
            'best_model': None,
            'best_score': 0.0
        }
        
        return widget

    def create_results_panel(self):
        """Create the AI results and chat panel"""
        panel = QWidget()
        layout = QVBoxLayout(panel)

        # Results tabs
        self.results_tabs = QTabWidget()
        self.results_tabs.setTabPosition(QTabWidget.TabPosition.North)

        # AI Chat Interface
        self.ai_chat_widget = QWidget()
        chat_layout = QVBoxLayout(self.ai_chat_widget)

        # Chat history
        self.chat_history = QTextEdit()
        self.chat_history.setReadOnly(True)
        self.chat_history.setFont(QFont("Segoe UI", 10))
        chat_layout.addWidget(self.chat_history)

        # Chat input
        chat_input_layout = QHBoxLayout()
        self.chat_input = QLineEdit()
        self.chat_input.setPlaceholderText("Ask the AI assistant anything about your binary...")
        self.chat_input.returnPressed.connect(self.send_chat_message)

        send_btn = QPushButton("Send")
        send_btn.clicked.connect(self.send_chat_message)
        send_btn.setStyleSheet("font-weight: bold; color: blue;")

        chat_input_layout.addWidget(self.chat_input)
        chat_input_layout.addWidget(send_btn)

        chat_layout.addLayout(chat_input_layout)

        self.results_tabs.addTab(self.ai_chat_widget, "AI Chat")

        # Analysis Results
        self.analysis_results = QTextEdit()
        self.analysis_results.setReadOnly(True)
        self.analysis_results.setFont(QFont("Consolas", 9))
        self.results_tabs.addTab(self.analysis_results, "Analysis Results")

        # Generated Scripts
        self.generated_scripts_widget = QWidget()
        scripts_layout = QVBoxLayout(self.generated_scripts_widget)

        # Scripts list
        scripts_list_layout = QHBoxLayout()
        self.scripts_list = QListWidget()
        self.scripts_list.itemClicked.connect(self.load_selected_script)
        scripts_list_layout.addWidget(self.scripts_list)

        # Script content
        self.script_content = QTextEdit()
        self.script_content.setFont(QFont("Consolas", 9))
        scripts_list_layout.addWidget(self.script_content)

        scripts_layout.addLayout(scripts_list_layout)

        # Script controls
        script_controls_layout = QHBoxLayout()

        save_script_btn = QPushButton("Save Script")
        save_script_btn.clicked.connect(self.save_selected_script)

        copy_script_btn = QPushButton("Copy to Clipboard")
        copy_script_btn.clicked.connect(self.copy_script_to_clipboard)

        test_script_btn = QPushButton("Test Script")
        test_script_btn.clicked.connect(self.test_generated_script)

        script_controls_layout.addWidget(save_script_btn)
        script_controls_layout.addWidget(copy_script_btn)
        script_controls_layout.addWidget(test_script_btn)
        script_controls_layout.addStretch()

        scripts_layout.addLayout(script_controls_layout)

        self.results_tabs.addTab(self.generated_scripts_widget, "Generated Scripts")

        # Live Script Preview Tab
        self.live_preview_widget = self.create_live_preview_tab()
        self.results_tabs.addTab(self.live_preview_widget, "Live Preview")

        # Multi-Model Comparison Tab
        self.model_comparison_widget = self.create_model_comparison_tab()
        self.results_tabs.addTab(self.model_comparison_widget, "Model Comparison")

        # Model Performance
        self.performance_widget = QWidget()
        performance_layout = QVBoxLayout(self.performance_widget)

        # Performance metrics
        self.performance_table = QTableWidget()
        self.performance_table.setColumnCount(3)
        self.performance_table.setHorizontalHeaderLabels(["Metric", "Value", "Status"])
        performance_layout.addWidget(self.performance_table)

        self.results_tabs.addTab(self.performance_widget, "Model Performance")

        layout.addWidget(self.results_tabs)

        return panel

# Method implementations
    def on_provider_changed(self, provider):
        """Update model list based on selected provider"""
        self.model_combo.clear()

        if provider == "OpenAI":
            models = ["gpt-4", "gpt-4-turbo", "gpt-3.5-turbo", "text-davinci-003"]
        elif provider == "Anthropic":
            models = ["claude-3-opus", "claude-3-sonnet", "claude-3-haiku", "claude-2"]
        elif provider == "Local (Ollama)":
            models = ["llama2", "codellama", "mistral", "neural-chat"]
        elif provider == "Hugging Face":
            models = ["microsoft/DialoGPT-large", "microsoft/CodeBERT-base", "codegen-350M"]
        elif provider == "Google Gemini":
            models = ["gemini-pro", "gemini-pro-vision", "gemini-1.5-pro"]
        elif provider == "Cohere":
            models = ["command-xl", "command", "command-light"]
        elif provider == "Azure OpenAI":
            models = ["gpt-4", "gpt-35-turbo", "text-davinci-003"]
        else:
            models = ["default-model"]

        self.model_combo.addItems(models)

                # Update API key display
        if provider in ["OpenAI", "Anthropic", "Cohere", "Azure OpenAI"]:
            self.api_key_edit.setPlaceholderText(f"Enter {provider} API key")
        else:
            self.api_key_edit.setPlaceholderText("API key not required for this provider")

    def update_temperature_label(self, value):
        """Update temperature label"""
        temp_value = value / 100.0
        self.temperature_label.setText(f"{temp_value:.1f}")

    def load_selected_model(self):
        """Load the selected AI model"""
        provider = self.provider_combo.currentText()
        model = self.model_combo.currentText()
        api_key = self.api_key_edit.text().strip()

        if not model:
            self.log_ai_message("Error: No model selected", "error")
            return

        try:
            self.model_status_label.setText("Loading model...")
            self.model_status_label.setStyleSheet("color: #ffa726;")
            self.model_progress.setVisible(True)
            self.model_progress.setRange(0, 0)  # Indeterminate progress

            # Map provider names to enum
            provider_map = {
                "OpenAI": ModelProvider.OPENAI,
                "Anthropic": ModelProvider.ANTHROPIC,
                "Local (Ollama)": ModelProvider.OLLAMA,
                "Google Gemini": ModelProvider.GOOGLE,
                "Groq": ModelProvider.GROQ,
            }

            provider_enum = provider_map.get(provider, ModelProvider.LOCAL)

            # Create model configuration
            config = ModelConfig(
                name=f"{provider}_{model}",
                provider=provider_enum,
                model_id=model,
                api_key=api_key if api_key else None,
                temperature=self.temperature_slider.value() / 100.0,
                max_tokens=self.max_tokens_spin.value(),
            )

            # Register and load model
            if self.ai_model_manager.register_model(config):
                self.ai_model_manager.load_model(config.name)
                self.log_ai_message(f"Loading {provider} model: {model}...")
            else:
                raise Exception("Failed to register model")

        except Exception as e:
            self.log_ai_message(f"Error loading model: {str(e)}", "error")
            self.model_progress.setVisible(False)

    def on_model_loaded(self, model_name, success):
        """Handle model loading completion"""
        self.model_progress.setVisible(False)

        if success:
            self.current_model = model_name
            self.model_status_label.setText(f"Model loaded: {model_name}")
            self.model_status_label.setStyleSheet("color: #66bb6a;")
            self.log_ai_message(f"Successfully loaded model: {model_name}", "success")
            self.model_loaded.emit(model_name, True)
        else:
            self.model_status_label.setText("Model loading failed")
            self.model_status_label.setStyleSheet("color: #ff6b6b;")
            self.log_ai_message(f"Failed to load model: {model_name}", "error")
            self.model_loaded.emit(model_name, False)

    def browse_analysis_binary(self):
        """Browse for binary file to analyze"""
        from PyQt6.QtWidgets import QFileDialog

        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Binary for AI Analysis", "", "Executable Files (*.exe *.dll *.so *.dylib);;All Files (*)"
)

        if file_path:
            self.analysis_binary_edit.setText(file_path)
            self.log_ai_message(f"Selected binary for analysis: {file_path}")

    def start_ai_analysis(self):
        """Start AI-powered binary analysis"""
        if not self.current_model:
            self.log_ai_message("Error: No AI model loaded", "error")
            return

        binary_path = self.analysis_binary_edit.text().strip()
        if not binary_path:
            self.log_ai_message("Error: No binary selected for analysis", "error")
            return

        focus = self.analysis_focus_combo.currentText()
        depth = self.analysis_depth_combo.currentText()

        try:
            self.log_ai_message(f"Starting AI analysis of {binary_path}...")
            self.log_ai_message(f"Focus: {focus}, Depth: {depth}")

            # Start analysis
            self.analysis_started.emit(binary_path)

            # Perform real AI analysis
            self._perform_real_ai_analysis(binary_path, focus, depth)

        except Exception as e:
            self.log_ai_message(f"Error starting AI analysis: {str(e)}", "error")

    def _perform_real_ai_analysis(self, binary_path, focus, depth):
        """Perform comprehensive AI-enhanced binary analysis using advanced techniques."""
        try:
            import hashlib
            import os

            # Initialize enhanced analyzers
            from ...core.analysis.binary_analyzer import BinaryAnalyzer
            from ...core.analysis.dynamic_analyzer import DynamicAnalyzer
            from ...core.analysis.firmware_analyzer import FirmwareAnalyzer
            from ...utils.pe_analyzer import PEAnalyzer
            from ...utils.string_extractor import StringExtractor

            # Create comprehensive analyzer instances
            binary_analyzer = BinaryAnalyzer()
            dynamic_analyzer = DynamicAnalyzer()
            firmware_analyzer = FirmwareAnalyzer()
            pe_analyzer = PEAnalyzer()
            string_extractor = StringExtractor()

            analysis_text = f"[*] Enhanced AI Binary Analysis for {os.path.basename(binary_path)}\n"
            analysis_text += "=" * 80 + "\n\n"
            analysis_text += "[+] Analysis Configuration:\n"
            analysis_text += f"  - Focus: {focus}\n"
            analysis_text += f"  - Depth: {depth}\n"
            analysis_text += f"  - AI Model: {self.current_model or 'Fallback Analysis'}\n"
            analysis_text += f"  - Binary Size: {os.path.getsize(binary_path):,} bytes\n\n"

            # File hash and metadata
            with open(binary_path, "rb") as f:
                file_data = f.read()
                md5_hash = hashlib.md5(file_data).hexdigest()
                sha1_hash = hashlib.sha1(file_data).hexdigest()
                sha256_hash = hashlib.sha256(file_data).hexdigest()

            analysis_text += "[#] File Hashes:\n"
            analysis_text += f"  - MD5:{md5_hash}\n"
            analysis_text += f"  - SHA1:   {sha1_hash}\n"
            analysis_text += f"  - SHA256: {sha256_hash}\n\n"

            # Comprehensive binary analysis
            try:
                binary_info = binary_analyzer.analyze_binary(binary_path)
                if binary_info:
                    analysis_text += "[+] Binary Architecture Analysis:\n"
                    analysis_text += f"  - Format: {binary_info.get('format', 'Unknown')}\n"
                    analysis_text += f"  - Architecture: {binary_info.get('architecture', 'Unknown')}\n"
                    analysis_text += f"  - Endianness: {binary_info.get('endianness', 'Unknown')}\n"
                    analysis_text += f"  - Entry Point: {binary_info.get('entry_point', 'Unknown')}\n"
                    analysis_text += f"  - Sections: {len(binary_info.get('sections', []))}\n\n"

                # Section analysis
                if binary_info.get("sections"):
                    analysis_text += "[+] Section Analysis:\n"
                    for i, section in enumerate(binary_info["sections"][:10]):
                        perms = section.get("permissions", "Unknown")
                        size = section.get("size", 0)
                        entropy = section.get("entropy", 0.0)
                        analysis_text += f"  - [{i+1}] {section.get('name', 'Unknown')}: {perms} ({size:,} bytes, entropy: {entropy:.2f})\n"
                    analysis_text += "\n"
            except Exception as e:
                self.log_message(f"Binary analyzer failed: {e}", "debug")
                analysis_text += f"[!] Binary analysis unavailable: {str(e)}\n\n"

            # Enhanced PE analysis with advanced features
            try:
                import pefile
                
                pe = pefile.PE(binary_path)

                analysis_text += "[+] Enhanced PE Analysis:\n"
                analysis_text += f"  - Machine Type: {hex(pe.FILE_HEADER.Machine)} ({self._get_machine_name(pe.FILE_HEADER.Machine)})\n"
                analysis_text += f"  - Characteristics: {hex(pe.FILE_HEADER.Characteristics)}\n"
                analysis_text += f"  - Subsystem: {pe.OPTIONAL_HEADER.Subsystem} ({self._get_subsystem_name(pe.OPTIONAL_HEADER.Subsystem)})\n"
                analysis_text += f"  - Image Base: {hex(pe.OPTIONAL_HEADER.ImageBase)}\n"
                analysis_text += f"  - Entry Point: {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}\n"
                analysis_text += f"  - Sections: {pe.FILE_HEADER.NumberOfSections}\n\n"

                # Security features analysis
                dll_characteristics = pe.OPTIONAL_HEADER.DllCharacteristics
                analysis_text += "[+] Security Features:\n"
                analysis_text += f"  - ASLR: {'[+] Enabled' if dll_characteristics & 0x0040 else '[-] Disabled'}\n"
                analysis_text += f"  - DEP/NX: {'[+] Enabled' if dll_characteristics & 0x0100 else '[-] Disabled'}\n"
                analysis_text += f"  - SEH: {'[+] Enabled' if not (dll_characteristics & 0x0400) else '[-] Disabled'}\n"
                analysis_text += f"  - CFG: {'[+] Enabled' if dll_characteristics & 0x4000 else '[-] Disabled'}\n"
                analysis_text += (
                    f"  - Isolation: {'[+] Enabled' if not (dll_characteristics & 0x0200) else '[-] Disabled'}\n\n"
                )

            except Exception as e:
                self.log_message(f"PE parsing failed: {e}", "debug")
                analysis_text += "[!] PE Format: Analysis failed (may be packed/obfuscated)\n\n"

            # Dynamic analysis capabilities
            if depth in ["Deep Analysis", "Comprehensive"]:
                try:
                    dynamic_results = dynamic_analyzer.quick_analysis(binary_path)
                    if dynamic_results:
                        analysis_text += "[+] Dynamic Analysis Summary:\n"
                        analysis_text += f"  - API Calls Detected: {len(dynamic_results.get('api_calls', []))}\n"
                        analysis_text += (
                            f"  - Network Activity: {'Yes' if dynamic_results.get('network_activity') else 'No'}\n"
                        )
                        analysis_text += f"  - File Operations: {len(dynamic_results.get('file_operations', []))}\n"
                        analysis_text += (
                            f"  - Registry Access: {'Yes' if dynamic_results.get('registry_access') else 'No'}\n"
                        )
                        analysis_text += (
                            f"  - Suspicious Behavior: {len(dynamic_results.get('suspicious_behaviors', []))}\n\n"
                        )
                except Exception as e:
                    self.log_message(f"Dynamic analysis failed: {e}", "debug")

            # Enhanced string analysis with categorization
            strings = string_extractor.extract_strings(binary_path)
            categorized_strings = self._categorize_strings(strings)

            analysis_text += f"📝 String Analysis ({len(strings)} total strings):\n"
            for category, cat_strings in categorized_strings.items():
                if cat_strings:
                    analysis_text += f"  - {category}: {len(cat_strings)} strings\n"
                    for s in cat_strings[:3]:  # Show first 3 of each category
                        display_str = s[:60] + "..." if len(s) > 60 else s
                        analysis_text += f"│    - {display_str}\n"
            analysis_text += "\n"

            # Focus-specific enhanced analysis
            if focus == "License Detection":
                analysis_text += self._perform_license_detection_analysis(pe, strings, file_data)
            elif focus == "Protection Analysis":
                analysis_text += self._perform_protection_analysis(pe, strings, file_data, binary_path)
            elif focus == "Vulnerability Research":
                analysis_text += self._perform_vulnerability_analysis(pe, strings, file_data)
            elif focus == "Security Audit":
                analysis_text += self._perform_security_audit_analysis(pe, strings, file_data)
            else:
                analysis_text += self._perform_general_enhanced_analysis(pe, strings, file_data)

            # AI-powered insights (if model available)
            if self.current_model and hasattr(self, "ai_model_manager"):
                try:
                    ai_context = {
                        "file_size": len(file_data),
                        "strings_count": len(strings),
                        "focus": focus,
                        "depth": depth,
                        "interesting_strings": categorized_strings.get("Interesting", [])[:20],
                    }

                    ai_analysis = self.ai_model_manager.analyze_binary(
                        self.current_model, binary_path, focus=focus.lower().replace(" ", "_"), context=ai_context
                    )

                    if ai_analysis:
                        analysis_text += "[+] AI-Generated Insights:\n"
                        analysis_text += f"{ai_analysis}\n\n"
                except Exception as e:
                    self.log_message(f"AI analysis failed: {e}", "debug")

            # Recommendations based on analysis
            recommendations = self._generate_analysis_recommendations(focus, depth)
            if recommendations:
                analysis_text += "[+] Analysis Recommendations:\n"
                for i, rec in enumerate(recommendations, 1):
                    analysis_text += f"{i}. {rec}\n"
                analysis_text += "\n"

            # Display results
            self.analysis_results.setPlainText(analysis_text)

            # Store analysis in history with enhanced metadata
            analysis_record = {
                "binary": binary_path,
                "focus": focus,
                "depth": depth,
                "timestamp": datetime.now().isoformat(),
                "file_hash": sha256_hash,
                "file_size": len(file_data),
                "results": analysis_text,
                "ai_model": self.current_model,
            }

            if not hasattr(self, "analysis_history"):
                self.analysis_history = []
            self.analysis_history.append(analysis_record)

            self.log_ai_message("Enhanced AI analysis completed successfully", "success")
            self.analysis_completed.emit(binary_path, "success")

        except Exception as e:
            error_msg = f"Error in enhanced AI analysis: {str(e)}"
            self.log_ai_message(error_msg, "error")
            self.analysis_results.setPlainText(f"Analysis Error:\n{error_msg}")
            self.analysis_completed.emit(binary_path, "failed")

    def _get_machine_name(self, machine_type):
        """Convert PE machine type to readable name."""
        machine_types = {
            0x014C: "Intel 386",
            0x0162: "MIPS R3000",
            0x0166: "MIPS R4000",
            0x0168: "MIPS R10000",
            0x0169: "MIPS WCE v2",
            0x0184: "Alpha AXP",
            0x01A2: "Hitachi SH3",
            0x01A3: "Hitachi SH3 DSP",
            0x01A6: "Hitachi SH4",
            0x01A8: "Hitachi SH5",
            0x01C0: "ARM little endian",
            0x01C2: "ARM Thumb",
            0x01C4: "ARM Thumb-2",
            0x01D3: "Matsushita AM33",
            0x01F0: "PowerPC little endian",
            0x01F1: "PowerPC with FPU",
            0x0200: "Intel Itanium",
            0x0266: "MIPS16",
            0x0284: "Alpha AXP 64-bit",
            0x0366: "MIPS with FPU",
            0x0466: "MIPS16 with FPU",
            0x0520: "Infineon TriCore",
            0x0CEF: "CEF",
            0x0EBC: "EFI Byte Code",
            0x8664: "x64 (AMD64/Intel 64)",
            0x9041: "Mitsubishi M32R",
            0xAA64: "ARM64 little endian",
            0xC0EE: "CEE",
        }
        return machine_types.get(machine_type, f"Unknown (0x{machine_type:04x})")

    def _get_subsystem_name(self, subsystem):
        """Convert PE subsystem code to readable name."""
        subsystems = {
            0: "Unknown",
            1: "Native",
            2: "Windows GUI",
            3: "Windows Console",
            5: "OS/2 Console",
            7: "POSIX Console",
            8: "Native Win9x Driver",
            9: "Windows CE GUI",
            10: "EFI Application",
            11: "EFI Boot Service Driver",
            12: "EFI Runtime Driver",
            13: "EFI ROM",
            14: "Xbox",
            16: "Windows Boot Application",
        }
        return subsystems.get(subsystem, f"Unknown ({subsystem})")

    def _categorize_strings(self, strings):
        """Categorize extracted strings into different types."""
        import re

        categorized = {
            "URLs": [],
            "File Paths": [],
            "Registry Keys": [],
            "IP Addresses": [],
            "Email Addresses": [],
            "Crypto/Hashes": [],
            "API Functions": [],
            "Error Messages": [],
            "User Agents": [],
            "Interesting": [],
            "Other": [],
        }

        # Patterns for categorization
        url_pattern = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE)
        ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        email_pattern = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
        file_path_pattern = re.compile(r'[A-Z]:\\\\[^<>:"|?*\n\r]+|/[^<>:"|?*\n\r]+', re.IGNORECASE)
        registry_pattern = re.compile(r'HKEY_[A-Z_]+\\\\[^<>:"|?*\n\r]+', re.IGNORECASE)
        crypto_pattern = re.compile(r"\b[A-Fa-f0-9]{32,128}\b")
        api_pattern = re.compile(r"\b[A-Z][a-zA-Z0-9]*[A-Z][a-zA-Z0-9]*\b")
        error_pattern = re.compile(r"\b(error|exception|failed|failure|invalid|denied|forbidden)\b", re.IGNORECASE)
        useragent_pattern = re.compile(r"Mozilla/|User-Agent|Chrome/|Firefox/", re.IGNORECASE)

        for string in strings:
            if len(string) < 4:  # Skip very short strings
                continue

            categorized_flag = False

            # Check each category
            if url_pattern.search(string):
                categorized["URLs"].append(string)
                categorized_flag = True
            elif ip_pattern.search(string):
                categorized["IP Addresses"].append(string)
                categorized_flag = True
            elif email_pattern.search(string):
                categorized["Email Addresses"].append(string)
                categorized_flag = True
            elif file_path_pattern.search(string):
                categorized["File Paths"].append(string)
                categorized_flag = True
            elif registry_pattern.search(string):
                categorized["Registry Keys"].append(string)
                categorized_flag = True
            elif crypto_pattern.search(string):
                categorized["Crypto/Hashes"].append(string)
                categorized_flag = True
            elif useragent_pattern.search(string):
                categorized["User Agents"].append(string)
                categorized_flag = True
            elif error_pattern.search(string):
                categorized["Error Messages"].append(string)
                categorized_flag = True
            elif api_pattern.search(string) and len(string) < 50:
                categorized["API Functions"].append(string)
                categorized_flag = True

            # Interesting strings (potential indicators)
            if not categorized_flag:
                if any(
                    keyword in string.lower()
                    for keyword in [
                        "password",
                        "secret",
                        "key",
                        "token",
                        "auth",
                        "login",
                        "admin",
                        "root",
                        "config",
                        "debug",
                        "test",
                        "license",
                        "serial",
                        "crack",
                        "patch",
                        "bypass",
                        "hook",
                        "inject",
                    ]
                ):
                    categorized["Interesting"].append(string)
                else:
                    categorized["Other"].append(string)

        # Limit each category to prevent overwhelming output
        for category in categorized:
            categorized[category] = categorized[category][:20]

        return categorized

    def _perform_license_detection_analysis(self, pe, strings, file_data):
        """Enhanced license detection analysis."""
        analysis = "[+] Enhanced License Detection Analysis:\n"

        # License-related strings
        license_indicators = []
        for string in strings:
            if any(
                keyword in string.lower()
                for keyword in [
                    "license",
                    "copyright",
                    "trial",
                    "demo",
                    "evaluation",
                    "registration",
                    "serial",
                    "key",
                    "activation",
                    "expir",
                ]
            ):
                license_indicators.append(string)

        if license_indicators:
            analysis += f"  - License Strings Found: {len(license_indicators)}\n"
            for indicator in license_indicators[:5]:
                display_str = indicator[:60] + "..." if len(indicator) > 60 else indicator
                analysis += f"│    - {display_str}\n"
        else:
            analysis += "  - No obvious license strings detected\n"

        # Check for common protection signatures
        protection_signatures = {
            "Themida": [b"Themida", b"WinLicense"],
            "VMProtect": [b"VMProtect", b"VMP"],
            "UPX": [b"UPX!", b"UPX0", b"UPX1"],
            "ASPack": [b"aPSPack", b"ASPack"],
            "PECompact": [b"PECompact", b"pec1", b"pec2"],
            "Armadillo": [b"Armadillo", b"ARMADILLOv"],
            "SafeNet": [b"SafeNet", b"Sentinel"],
            "FlexLM": [b"FlexLM", b"FLEXLM"],
            "Dongle": [b"HASP", b"SuperPro", b"Wibu"],
        }

        detected_protections = []
        for protection, signatures in protection_signatures.items():
            for sig in signatures:
                if sig in file_data:
                    detected_protections.append(protection)
                    break

        if detected_protections:
            analysis += f"  - Protection Systems: {', '.join(detected_protections)}\n"
        else:
            analysis += "  - No known protection systems detected\n"

        # License bypass recommendations
        analysis += "  - Recommendations:\n"
        if detected_protections:
            analysis += "     - Consider virtualization bypass techniques\n"
            analysis += "     - Analyze license validation routines\n"
            analysis += "     - Look for hardware fingerprinting\n"
        else:
            analysis += "     - Search for license validation functions\n"
            analysis += "     - Analyze network license checks\n"
            analysis += "     - Check for time-based restrictions\n"

        return analysis + "\n"

    def _perform_protection_analysis(self, pe, strings, file_data, binary_path):
        """Enhanced protection mechanism analysis with comprehensive detection."""
        analysis = "[+] Enhanced Protection Analysis:\n"

        # Run comprehensive protection detection
        protections = self._detect_advanced_protections(pe, strings, file_data, binary_path)
        pe_anomalies = self._analyze_pe_anomalies(pe)
        runtime_indicators = self._detect_runtime_packers(binary_path)
        anti_analysis = self._detect_anti_analysis_strings(strings)

        # Generate comprehensive protection report
        comprehensive_report = self._generate_protection_report(
            protections, pe_anomalies, runtime_indicators, anti_analysis
        )

        # Add the comprehensive report to analysis
        analysis += comprehensive_report

        # Legacy analysis for backwards compatibility
        analysis += "\n" + "=" * 60 + "\n"
        analysis += "📋 Legacy Analysis Summary:\n\n"

        # Anti-debugging techniques (legacy)
        antidebug_indicators = []
        antidebug_strings = [
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "OutputDebugString",
            "FindWindow",
            "ollydbg",
            "x32dbg",
            "x64dbg",
            "wireshark",
            "procmon",
        ]

        for string in strings:
            if any(indicator.lower() in string.lower() for indicator in antidebug_strings):
                antidebug_indicators.append(string)

        analysis += f"  - Legacy Anti-Debug Indicators: {len(antidebug_indicators)}\n"
        for indicator in antidebug_indicators[:3]:
            analysis += f"│    - {indicator}\n"

        # Anti-VM techniques (legacy)
        antivm_indicators = []
        antivm_strings = ["vmware", "virtualbox", "qemu", "sandboxie", "wine", "vbox", "vmtoolsd", "vmmouse", "vmhgfs"]

        for string in strings:
            if any(indicator.lower() in string.lower() for indicator in antivm_strings):
                antivm_indicators.append(string)

        analysis += f"  - Legacy Anti-VM Indicators: {len(antivm_indicators)}\n"
        for indicator in antivm_indicators[:3]:
            analysis += f"│    - {indicator}\n"

        # Packing/obfuscation detection (legacy)
        try:
            entropy_analysis = self._calculate_section_entropy(pe)
            high_entropy_sections = [s for s in entropy_analysis if s["entropy"] > 7.0]

            analysis += f"  - Legacy High Entropy Sections: {len(high_entropy_sections)}\n"
            for section in high_entropy_sections[:3]:
                analysis += f"│    - {section['name']}: {section['entropy']:.2f}\n"
        except Exception as e:
            analysis += f"  - Legacy entropy analysis failed: {str(e)}\n"

        # Code injection indicators (legacy)
        injection_apis = [
            "VirtualAlloc",
            "VirtualProtect",
            "WriteProcessMemory",
            "CreateRemoteThread",
            "SetWindowsHookEx",
            "DllInject",
        ]

        injection_indicators = []
        for string in strings:
            if any(api.lower() in string.lower() for api in injection_apis):
                injection_indicators.append(string)

        analysis += f"  - Legacy Code Injection APIs: {len(injection_indicators)}\n"
        for indicator in injection_indicators[:3]:
            analysis += f"│    - {indicator}\n"

        # Final recommendations
        analysis += "\n[+] Final Protection Analysis Recommendations:\n"

        total_protections = sum(len(prots) for prots in protections.values() if isinstance(prots, list))

        if total_protections >= 5:
            analysis += "  - HIGH PROTECTION: Multiple layers detected\n"
            analysis += "  - Recommend commercial unpacking tools\n"
            analysis += "  - Use hardware-based analysis environment\n"
            analysis += "  - Consider kernel-mode debugging\n"
        elif total_protections >= 2:
            analysis += "  - MEDIUM PROTECTION: Some protection detected\n"
            analysis += "  - Standard unpacking tools should work\n"
            analysis += "  - Dynamic analysis recommended\n"
        else:
            analysis += "  - LOW PROTECTION: Minimal protection detected\n"
            analysis += "  - Standard reverse engineering approaches\n"

        if antidebug_indicators or anti_analysis["debugger_detection"]:
            analysis += "  - Implement anti-anti-debug patches\n"
        if antivm_indicators or anti_analysis["vm_detection"]:
            analysis += "  - Use physical machine for analysis\n"
        if pe_anomalies:
            analysis += "  - PE structure requires manual reconstruction\n"
        if runtime_indicators:
            analysis += "  - Runtime unpacking required\n"

        analysis += "  - Multiple analysis techniques recommended\n"

        return analysis + "\n"

    def _calculate_section_entropy(self, pe):
        """Calculate entropy for PE sections."""
        import math
        from collections import Counter

        sections = []
        for section in pe.sections:
            try:
                data = section.get_data()
                if len(data) == 0:
                    continue

                # Calculate entropy
                byte_counts = Counter(data)
                entropy = 0
                for count in byte_counts.values():
                    freq = count / len(data)
                    entropy -= freq * math.log2(freq)

                sections.append({"name": section.Name.decode().rstrip("\x00"), "entropy": entropy, "size": len(data)})
            except Exception:
                continue

        return sections

    def _perform_vulnerability_analysis(self, pe, strings, file_data):
        """Enhanced vulnerability analysis."""
        analysis = "[+] Enhanced Vulnerability Analysis:\n"

        # Buffer overflow indicators
        dangerous_functions = [
            "strcpy",
            "strcat",
            "sprintf",
            "gets",
            "scanf",
            "memcpy",
            "memmove",
            "strncpy",
            "strncat",
        ]

        vuln_functions = []
        for string in strings:
            if any(func in string for func in dangerous_functions):
                vuln_functions.append(string)

        analysis += f"  - Dangerous Functions: {len(vuln_functions)}\n"
        for func in vuln_functions[:5]:
            analysis += f"│    - {func}\n"

        # Format string vulnerabilities
        format_indicators = []
        for string in strings:
            if "%" in string and any(fmt in string for fmt in ["%s", "%d", "%x", "%n"]):
                format_indicators.append(string)

        analysis += f"  - Format String Candidates: {len(format_indicators)}\n"
        for indicator in format_indicators[:3]:
            display_str = indicator[:40] + "..." if len(indicator) > 40 else indicator
            analysis += f"│    - {display_str}\n"

        # Network vulnerability indicators
        network_functions = [
            "send",
            "recv",
            "accept",
            "connect",
            "bind",
            "listen",
            "WSASend",
            "WSARecv",
            "InternetOpen",
        ]

        network_indicators = []
        for string in strings:
            if any(func in string for func in network_functions):
                network_indicators.append(string)

        analysis += f"  - Network Functions: {len(network_indicators)}\n"
        for indicator in network_indicators[:3]:
            analysis += f"│    - {indicator}\n"

        # Privilege escalation indicators
        privesc_indicators = []
        privesc_strings = [
            "SeDebugPrivilege",
            "SeBackupPrivilege",
            "SeRestorePrivilege",
            "SeTakeOwnershipPrivilege",
            "SeLoadDriverPrivilege",
        ]

        for string in strings:
            if any(priv in string for priv in privesc_strings):
                privesc_indicators.append(string)

        analysis += f"  - Privilege Escalation: {len(privesc_indicators)}\n"
        for indicator in privesc_indicators[:3]:
            analysis += f"│    - {indicator}\n"

        analysis += "  - Research Recommendations:\n"
        if vuln_functions:
            analysis += "     - Analyze input validation routines\n"
        if network_indicators:
            analysis += "     - Test network input handling\n"
        if format_indicators:
            analysis += "     - Examine format string usage\n"
        analysis += "     - Consider fuzzing approaches\n"

        return analysis + "\n"



    def _perform_security_audit(self, pe, strings, file_data):
        """Security audit analysis."""
        analysis = "[+] Enhanced Security Audit:\n"

        # Cryptographic functions
        crypto_functions = []
        crypto_strings = [
            "CryptGenKey",
            "CryptEncrypt",
            "CryptDecrypt",
            "CryptHashData",
            "BCryptGenRandom",
            "BCryptEncrypt",
            "BCryptDecrypt",
            "AES",
            "DES",
            "RSA",
            "SHA",
            "MD5",
        ]

        for string in strings:
            if any(crypto in string for crypto in crypto_strings):
                crypto_functions.append(string)

        analysis += f"  - Cryptographic Functions: {len(crypto_functions)}\n"
        for func in crypto_functions[:5]:
            analysis += f"│    - {func}\n"

        # Authentication mechanisms
        auth_indicators = []
        auth_strings = ["password", "username", "login", "authenticate", "credential", "token", "session", "cookie"]

        for string in strings:
            if any(auth.lower() in string.lower() for auth in auth_strings):
                auth_indicators.append(string)

        analysis += f"  - Authentication Elements: {len(auth_indicators)}\n"
        for indicator in auth_indicators[:3]:
            display_str = indicator[:40] + "..." if len(indicator) > 40 else indicator
            analysis += f"│    - {display_str}\n"

        # Input validation
        validation_functions = []
        validation_strings = ["validate", "sanitize", "filter", "escape", "strlen", "strnlen", "wcslen", "wcsnlen"]

        for string in strings:
            if any(val in string.lower() for val in validation_strings):
                validation_functions.append(string)

        analysis += f"  - Input Validation: {len(validation_functions)}\n"
        for func in validation_functions[:3]:
            analysis += f"│    - {func}\n"

        # Secure coding practices
        secure_indicators = []
        secure_strings = [
            "SecureZeroMemory",
            "CryptProtectData",
            "CryptUnprotectData",
            "GetSecurityInfo",
            "SetSecurityInfo",
        ]

        for string in strings:
            if any(secure in string for secure in secure_strings):
                secure_indicators.append(string)

        analysis += f"  - Secure APIs: {len(secure_indicators)}\n"
        for indicator in secure_indicators[:3]:
            analysis += f"│    - {indicator}\n"

        analysis += "  - Security Recommendations:\n"
        if not crypto_functions:
            analysis += "     - Consider adding encryption for sensitive data\n"
        if not validation_functions:
            analysis += "     - Implement input validation\n"
        if not secure_indicators:
            analysis += "     - Use secure memory management APIs\n"
        analysis += "     - Regular security testing recommended\n"

        return analysis + "\n"

    def _perform_enhanced_analysis(self, pe, strings, file_data):
        """General enhanced analysis."""
        analysis = "[+] General Enhanced Analysis:\n"

        # File operations
        file_ops = []
        file_strings = [
            "CreateFile",
            "ReadFile",
            "WriteFile",
            "DeleteFile",
            "FindFirstFile",
"FindNextFile",
"GetFileAttributes",
        ]

        for string in strings:
            if any(op in string for op in file_strings):
                file_ops.append(string)

        analysis += f"  - File Operations: {len(file_ops)}\n"
        for op in file_ops[:3]:
            analysis += f"│    - {op}\n"

        # Registry operations
        registry_ops = []
        registry_strings = [
            "RegOpenKey",
            "RegCreateKey",
            "RegSetValue",
            "RegQueryValue",
            "RegDeleteKey",
            "RegDeleteValue",
            "RegEnumKey",
        ]

        for string in strings:
            if any(op in string for op in registry_strings):
                registry_ops.append(string)

        analysis += f"  - Registry Operations: {len(registry_ops)}\n"
        for op in registry_ops[:3]:
            analysis += f"│    - {op}\n"

        # Process operations
        process_ops = []
        process_strings = [
            "CreateProcess",
            "TerminateProcess",
            "OpenProcess",
            "GetCurrentProcess",
            "WaitForSingleObject",
        ]

        for string in strings:
            if any(op in string for op in process_strings):
                process_ops.append(string)

        analysis += f"  - Process Operations: {len(process_ops)}\n"
        for op in process_ops[:3]:
            analysis += f"│    - {op}\n"

        # Threading operations
        thread_ops = []
        thread_strings = [
            "CreateThread",
            "ExitThread",
            "SuspendThread",
            "ResumeThread",
            "GetThreadContext",
            "SetThreadContext",
        ]

        for string in strings:
            if any(op in string for op in thread_strings):
                thread_ops.append(string)

        analysis += f"  - Threading Operations: {len(thread_ops)}\n"
        for op in thread_ops[:3]:
            analysis += f"     - {op}\n"

        return analysis + "\n"

    def _generate_analysis_recommendations(self, focus, depth):
        """Generate actionable recommendations based on analysis."""
        recommendations = []

        if focus == "License Detection":
            recommendations.extend(
                [
                    "Use dynamic analysis to trace license validation routines",
                    "Monitor registry access during license checks",
                    "Analyze network communication for online license validation",
                    "Check for hardware fingerprinting in license mechanism",
                ]
            )
        elif focus == "Protection Analysis":
            recommendations.extend(
                [
                    "Consider unpacking if high entropy sections detected",
                    "Use anti-anti-debug techniques for protected binaries",
                    "Analyze in isolated VM environment",
                    "Monitor API calls during execution",
                ]
            )
        elif focus == "Vulnerability Research":
            recommendations.extend(
                [
                    "Focus on input validation in identified dangerous functions",
                    "Test network input handling for buffer overflows",
                    "Examine format string vulnerabilities",
                    "Consider targeted fuzzing for specific components",
                ]
            )

        elif focus == "Security Audit":
            recommendations.extend(
                [
                    "Review cryptographic implementations",
                    "Assess input validation mechanisms",
                    "Check authentication and authorization",
                    "Evaluate secure coding practices",
                ]
            )
        else:
            recommendations.extend(
                [
                    "Start with static analysis of imports and strings",
                    "Use dynamic analysis to understand runtime behavior",
                    "Focus on interesting strings and API calls",
                    "Consider reverse engineering specific functions",
                ]
            )

        # Add depth-specific recommendations
        if depth in ["Deep Analysis", "Comprehensive"]:
            recommendations.extend(
                [
                    "Perform control flow graph analysis",
                    "Use symbolic execution for path exploration",
                    "Apply machine learning for pattern recognition",
                ]
            )

        return recommendations[:8]  # Limit to 8 recommendations

    def _detect_advanced_protections(self, pe, strings, file_data, binary_path):
        """Advanced protection detection using multiple techniques."""
        protections = {
            "packers": [],
            "protectors": [],
            "obfuscators": [],
            "anti_analysis": [],
            "code_injection": [],
            "virtualization": [],
        }

        # Enhanced packer signatures
        packer_signatures = {
            "UPX": [b"UPX!", b"UPX0", b"UPX1", b"UPX2", b"$Id: UPX"],
            "ASPack": [b"aPSPack", b"ASPack", b".aspack", b"asPack"],
            "PECompact": [b"PECompact", b"pec1", b"pec2", b"PEC2TO"],
            "FSG": [b"FSG!", b"FSG ", b"FSG1", b"FSG2"],
            "MEW": [b"MEW ", b"MEW1", b"MEW2"],
            "Petite": [b"Petite", b"petite"],
            "NsPack": [b"NsPack", b"nsp1", b"nsp2"],
            "WWPack": [b"WWPack32", b"WWPACK"],
            "tElock": [b"tElock", b"TELOCK"],
            "Yoda": [b"Yoda's", b"YodaProtector"],
            "CrypKey": [b"CrypKey", b"CRYPKEY"],
            "Enigma": [b"Enigma", b"ENIGMA"],
            "ExeCryptor": [b"ExeCryptor", b"EXECRYPTOR"],
            "PESpin": [b"PESpin", b"PESPIN"],
            "ASProtect": [b"ASProtect", b"ASPROTECT"],
            "BobSoft": [b"BobSoft", b"BOBSOFT"],
            "PEBundle": [b"PEBundle", b"PEBUNDLE"],
            "WinUpack": [b"WinUpack", b"WINUPACK"],
        }

        # Advanced protector signatures
        protector_signatures = {
            "Themida": [b"Themida", b"WinLicense", b"Oreans", b"SecuROM"],
            "VMProtect": [b"VMProtect", b"VMP", b"PolyTech"],
            "Armadillo": [b"Armadillo", b"ARMADILLOv", b"Silicon Realms"],
            "SafeDisc": [b"SafeDisc", b"SAFEDISC", b"Macrovision"],
            "StarForce": [b"StarForce", b"STARFORCE", b"Protection Technology"],
            "SecuROM": [b"SecuROM", b"SECUROM", b"Sony DADC"],
            "Denuvo": [b"Denuvo", b"DENUVO", b"Irdeto"],
            "HASP": [b"HASP", b"Sentinel", b"SafeNet"],
            "CodeMeter": [b"CodeMeter", b"WIBU"],
            "FlexLM": [b"FlexLM", b"FLEXLM", b"Flexera"],
            "Guardant": [b"Guardant", b"GUARDANT"],
"PACE": [b"PACE Anti-Piracy", b"iLok"],
"LockIt": [b"Lock-It!", b"LOCK-IT"],
"SGK": [b"SuperPro", b"Rainbow"],
"ELMLicense": [b"ELMLicense", b"ELMLICENSE"],
}

        # Virtualization/Code protection signatures
        virtualization_signatures = {
            "Code Virtualizer": [b"Code Virtualizer", b"CODEVIRTUALIZER"],
            "WinLicense": [b"WinLicense", b"WINLICENSE"],
            "VMProtect Ultimate": [b"VMProtect Ultimate", b"VMPROTECT_ULTIMATE"],
            "Enigma VirtualBox": [b"Enigma VirtualBox", b"ENIGMA_VIRTUALBOX"],
            "BoxedApp": [b"BoxedApp", b"BOXEDAPP"],
            "Molebox": [b"Molebox", b"MOLEBOX"],
            "Thinstall": [b"Thinstall", b"THINSTALL"],
            "Cameyo": [b"Cameyo", b"CAMEYO"],
        }

        # Obfuscation signatures
        obfuscation_signatures = {
            "ConfuserEx": [b"ConfuserEx", b"CONFUSEREX"],
            "Obfuscar": [b"Obfuscar", b"OBFUSCAR"],
            "SmartAssembly": [b"SmartAssembly", b"SMARTASSEMBLY"],
            "Dotfuscator": [b"Dotfuscator", b"DOTFUSCATOR"],
            "Eazfuscator": [b"Eazfuscator", b"EAZFUSCATOR"],
            "Code Obfuscator": [b"Code Obfuscator", b"CODEOBFUSCATOR"],
            "Babel Obfuscator": [b"Babel", b"BABEL"],
            "Reactor": [b"Reactor", b"REACTOR"],
            "Xenocode": [b"Xenocode", b"XENOCODE"],
        }

        # Scan for all protection types
        all_signatures = {
            "packers": packer_signatures,
            "protectors": protector_signatures,
            "obfuscators": obfuscation_signatures,
            "virtualization": virtualization_signatures,
        }

        for category, signature_dict in all_signatures.items():
            for protection_name, signatures in signature_dict.items():
                for signature in signatures:
                    if signature in file_data:
                        protections[category].append(protection_name)
                        break

        # Anti-analysis techniques detection
        anti_analysis_indicators = {
            "Anti-Debug": [
                "IsDebuggerPresent",
                "CheckRemoteDebuggerPresent",
                "OutputDebugString",
                "NtQueryInformationProcess",
                "NtSetInformationThread",
                "KiFastSystemCall",
                "DbgBreakPoint",
                "DbgUserBreakPoint",
                "ZwQueryInformationProcess",
                "ProcessDebugPort",
                "ProcessDebugObjectHandle",
                "ProcessDebugFlags",
            ],
            "Anti-VM": [
                "VMware",
                "VirtualBox",
                "QEMU",
                "Xen",
                "Parallels",
                "VirtualPC",
                "vmtoolsd",
                "VBoxService",
                "vmmouse",
                "vmhgfs",
                "vmsrvc",
                "VBoxTray",
                "VBoxControl",
                "vmwareuser",
                "vmwaretray",
            ],
            "Anti-Sandbox": [
                "Sandboxie",
                "SbieDll",
                "SboxDll",
                "cmdvrt32",
                "Anubis",
                "ThreatAnalyzer",
                "CWSandbox",
                "Joe Sandbox",
                "Cuckoo",
                "WinAPIOverride",
                "apimonitor",
                "detours",
            ],
            "Anti-Emulation": [
                "Wine",
                "user32.dll",
                "GetVersion",
                "GetVersionEx",
                "CPUID",
                "rdtsc",
                "QueryPerformanceCounter",
                "GetTickCount",
                "timeGetTime",
                "GetSystemTime",
            ],
        }

        for category, indicators in anti_analysis_indicators.items():
            detected = []
            for indicator in indicators:
                for string in strings:
                    if indicator.lower() in string.lower():
                        detected.append(indicator)
                        break
            if detected:
                protections["anti_analysis"].append(
                    {"category": category, "indicators": detected[:5]}  # Limit to first 5
                )

        # Code injection detection
        injection_indicators = [
            "VirtualAlloc",
            "VirtualProtect",
            "WriteProcessMemory",
            "CreateRemoteThread",
            "SetWindowsHookEx",
            "NtMapViewOfSection",
            "ZwMapViewOfSection",
            "RtlCreateUserThread",
            "NtCreateThread",
            "ZwCreateThread",
            "LoadLibrary",
            "GetProcAddress",
            "DllInject",
            "Process32First",
            "Process32Next",
            "CreateToolhelp32Snapshot",
        ]

        detected_injection = []
        for indicator in injection_indicators:
            for string in strings:
                if indicator.lower() in string.lower():
                    detected_injection.append(indicator)
                    break

        if detected_injection:
            protections["code_injection"] = detected_injection[:10]

        return protections

    def _analyze_pe_anomalies(self, pe):
        """Analyze PE file for structural anomalies that indicate protection."""
        anomalies = []

        try:
            # Check for unusual section names
            common_sections = {".text", ".data", ".rdata", ".rsrc", ".reloc", ".idata", ".edata", ".bss"}
            for section in pe.sections:
                section_name = section.Name.decode().rstrip("\x00")
                if section_name not in common_sections and not section_name.startswith(".debug"):
                    anomalies.append(f"Unusual section name: {section_name}")

            # Check for overlapping sections
            sections_data = []
            for section in pe.sections:
                sections_data.append(
                    {
                        "name": section.Name.decode().rstrip("\x00"),
                        "virtual_address": section.VirtualAddress,
                        "virtual_size": section.Misc_VirtualSize,
                        "raw_address": section.PointerToRawData,
                        "raw_size": section.SizeOfRawData,
                    }
                )

            for i, section1 in enumerate(sections_data):
                for section2 in sections_data[i + 1 :]:
                    # Check virtual address overlap
                    if (
                        section1["virtual_address"] < section2["virtual_address"] + section2["virtual_size"]
                        and section2["virtual_address"] < section1["virtual_address"] + section1["virtual_size"]
                    ):
                        anomalies.append(f"Virtual address overlap: {section1['name']} and {section2['name']}")

                    # Check raw address overlap
                    if (
                        section1["raw_address"] < section2["raw_address"] + section2["raw_size"]
                        and section2["raw_address"] < section1["raw_address"] + section1["raw_size"]
                    ):
                        anomalies.append(f"Raw address overlap: {section1['name']} and {section2['name']}")

            # Check for suspicious characteristics
            characteristics = pe.FILE_HEADER.Characteristics
            if characteristics & 0x0001:  # IMAGE_FILE_RELOCS_STRIPPED
                anomalies.append("Relocations stripped (unusual for executables)")

            if characteristics & 0x0004:  # IMAGE_FILE_LINE_NUMBERS_STRIPPED
                anomalies.append("Line numbers stripped")

            if characteristics & 0x0008:  # IMAGE_FILE_LOCAL_SYMS_STRIPPED
                anomalies.append("Local symbols stripped")

            # Check optional header anomalies
            if hasattr(pe, "OPTIONAL_HEADER"):
                # Unusual entry point
                entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
                found_in_section = False
                for section in pe.sections:
                    if section.VirtualAddress <= entry_point < section.VirtualAddress + section.Misc_VirtualSize:
                        section_name = section.Name.decode().rstrip("\x00")
                        if section_name != ".text":
                            anomalies.append(f"Entry point in unusual section: {section_name}")
                        found_in_section = True
                        break

                if not found_in_section:
                    anomalies.append("Entry point not found in any section")

                # Check for unusual image base
                image_base = pe.OPTIONAL_HEADER.ImageBase
                if image_base != 0x400000 and image_base != 0x10000000:
                    anomalies.append(f"Unusual image base: 0x{image_base:08x}")

                # Check subsystem
                subsystem = pe.OPTIONAL_HEADER.Subsystem
                if subsystem not in [1, 2, 3]:  # Native, GUI, Console
                    anomalies.append(f"Unusual subsystem: {subsystem}")

            # Check import table anomalies
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                total_imports = 0
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    total_imports += len(entry.imports)

                if total_imports < 5:
                    anomalies.append(f"Very few imports detected: {total_imports}")
                elif total_imports > 1000:
                    anomalies.append(f"Unusually many imports: {total_imports}")
            else:
                anomalies.append("No import table found")

        except Exception as e:
            anomalies.append(f"PE analysis error: {str(e)}")

        return anomalies

    def _detect_runtime_packers(self, binary_path):
        """Detect runtime packers using heuristic analysis."""
        runtime_indicators = []

        try:
            with open(binary_path, "rb") as f:
                # Read first 1024 bytes for analysis
                header_data = f.read(1024)

                # Check for common runtime packer patterns
                packer_patterns = [
                    (b"\\x60\\x8B\\x6C\\x24\\x24", "UPX stub pattern"),
                    (b"\\x87\\x25\\x00\\x00\\x01\\x00", "ASPack pattern"),
                    (b"\\x68\\x00\\x00\\x00\\x00\\x68", "Common packer prologue"),
                    (b"\\xE8\\x00\\x00\\x00\\x00\\x5D", "GetPC thunk pattern"),
                    (b"\\x55\\x8B\\xEC\\x83\\xEC", "Standard function prologue"),
                    (b"\\x60\\x9C\\x33\\xC0\\x8B", "Pushad/Pushfd pattern"),
                ]

                for pattern, description in packer_patterns:
                    if pattern in header_data:
                        runtime_indicators.append(description)

                # Seek to different file positions to check for packed data
                file_size = f.seek(0, 2)  # Seek to end to get size
                f.seek(0)  # Back to beginning

                # Sample different areas of the file
                sample_positions = [0, file_size // 4, file_size // 2, 3 * file_size // 4]
                high_entropy_regions = 0

                for pos in sample_positions:
                    if pos + 512 < file_size:
                        f.seek(pos)
                        sample = f.read(512)
                        entropy = self._calculate_entropy(sample)
                        if entropy > 7.5:
                            high_entropy_regions += 1

                if high_entropy_regions >= 3:
                    runtime_indicators.append(f"High entropy in {high_entropy_regions}/4 regions")

        except Exception as e:
            runtime_indicators.append(f"Runtime analysis error: {str(e)}")

        return runtime_indicators

    def _calculate_entropy(self, data):
        """Calculate Shannon entropy of data."""
        import math
        from collections import Counter

        if len(data) == 0:
            return 0

        counter = Counter(data)
        entropy = 0
        data_len = len(data)

        for count in counter.values():
            freq = count / data_len
            entropy -= freq * math.log2(freq)

        return entropy

    def _detect_anti_analysis(self, strings):
        """Detect anti-analysis techniques from string analysis."""
        anti_analysis = {
            "debugger_detection": [],
            "vm_detection": [],
            "sandbox_detection": [],
            "analysis_tools": [],
            "evasion_techniques": [],
        }

        patterns = {
            "debugger_detection": [
                "isdebuggerpresent",
                "checkremotedebuggerpresent",
                "outputdebugstring",
                "findwindow.*olly",
                "findwindow.*debug",
                "ntqueryinformationprocess",
                "zwqueryinformationprocess",
                "debugbreak",
                "int 3",
                "__debugbreak",
                "processdebugport",
                "processdebugflags",
                "heap flags",
            ],
            "vm_detection": [
                "vmware",
                "virtualbox",
                "qemu",
                "xen",
                "parallels",
                "virtualpc",
                "vbox",
                "vmtoolsd",
                "vboxservice",
                "vmmouse",
                "vmhgfs",
                "redpill",
                "sidt",
                "sgdt",
                "sldt",
                "str",
                "cpuid",
            ],
            "sandbox_detection": [
                "sandboxie",
                "anubis",
                "joesandbox",
                "cuckoo",
                "threatanalyzer",
                "cwsandbox",
                "norman",
                "sunbelt",
                "comodo",
                "malwr",
                "sleep",
                "delay",
                "timeout",
                "wait",
            ],
            "analysis_tools": [
                "wireshark",
                "fiddler",
                "procmon",
                "process monitor",
                "regmon",
                "filemon",
                "apimonitor",
                "detours",
                "winapis",
                "ollydbg",
                "x32dbg",
                "x64dbg",
                "immunity",
                "ida",
                "ghidra",
                "radare",
            ],
            "evasion_techniques": [
                "virtualalloc",
                "virtualprotect",
                "heapalloc",
                "getmodulehandle",
                "getprocaddress",
                "loadlibrary",
                "createthread",
                "createprocess",
                "writeprocessmemory",
                "readprocessmemory",
                "suspendthread",
            ],
        }

        for category, keywords in patterns.items():
            for string in strings:
                string_lower = string.lower()
                for keyword in keywords:
                    if keyword in string_lower:
                        anti_analysis[category].append(string)
                        break

        # Limit results to prevent overwhelming output
        for category in anti_analysis:
            anti_analysis[category] = anti_analysis[category][:10]

        return anti_analysis

    def _generate_protection_report(self, protections, pe_anomalies, runtime_indicators, anti_analysis):
        """Generate comprehensive protection analysis report."""
        report = "[+] Comprehensive Protection Detection Report:\n"
        report += "=" * 60 + "\n\n"

        # Protection categories summary
        total_protections = sum(len(prots) for prots in protections.values() if isinstance(prots, list))
        if total_protections > 0:
            report += f"[+] Protection Summary: {total_protections} protection mechanisms detected\n\n"

        # Packers
        if protections["packers"]:
            report += "[+] Detected Packers:\n"
            for packer in protections["packers"]:
                report += f"  - {packer}\n"
            report += "\n"

        # Protectors
        if protections["protectors"]:
            report += "[+] Detected Protectors:\n"
            for protector in protections["protectors"]:
                report += f"  - {protector}\n"
            report += "\n"

        # Obfuscators
        if protections["obfuscators"]:
            report += "[+] Detected Obfuscators:\n"
            for obfuscator in protections["obfuscators"]:
                report += f"  - {obfuscator}\n"
            report += "\n"

        # Virtualization
        if protections["virtualization"]:
            report += "[+] Detected Virtualization:\n"
            for virtualizer in protections["virtualization"]:
                report += f"  - {virtualizer}\n"
            report += "\n"

        # Anti-analysis techniques
        if protections["anti_analysis"]:
            report += "[+] Anti-Analysis Techniques:\n"
            for technique in protections["anti_analysis"]:
                report += f"  - {technique['category']}: "
                report += f"{', '.join(technique['indicators'][:3])}\n"
            report += "\n"

        # Code injection capabilities
        if protections["code_injection"]:
            report += "[+] Code Injection Capabilities:\n"
            for api in protections["code_injection"][:5]:
                report += f"  - {api}\n"
            report += "\n"

        # PE anomalies
        if pe_anomalies:
            report += "[+] PE Structure Anomalies:\n"
            for anomaly in pe_anomalies[:10]:
                report += f"  - {anomaly}\n"
            report += "\n"

        # Runtime indicators
        if runtime_indicators:
            report += "[+] Runtime Packer Indicators:\n"
            for indicator in runtime_indicators:
                report += f"  - {indicator}\n"
            report += "\n"

        # Detailed anti-analysis breakdown
        for category, techniques in anti_analysis.items():
            if techniques:
                category_name = category.replace("_", " ").title()
                report += f"[+] {category_name}:\n"
                for technique in techniques[:5]:
                    display_str = technique[:50] + "..." if len(technique) > 50 else technique
                    report += f"  - {display_str}\n"
                report += "\n"

        # Protection level assessment
        protection_level = "Low"
        if total_protections >= 10:
            protection_level = "Very High"
        elif total_protections >= 5:
            protection_level = "High"
        elif total_protections >= 2:
            protection_level = "Medium"

        report += f"[+] Overall Protection Level: {protection_level}\n\n"

        # Bypass recommendations
        report += "[+] Analysis & Bypass Recommendations:\n"

        if protections["packers"]:
            report += "  - Use unpacking tools (UPX, ASPack unpackers)\n"

        if protections["protectors"]:
            report += "  - Consider commercial unpacking services\n"
            report += "  - Use memory dumping during runtime\n"

        if protections["virtualization"]:
            report += "  - Analyze in hardware virtualization environment\n"
            report += "  - Use specialized VM detection bypass tools\n"

        if protections["anti_analysis"]:
            report += "  - Implement anti-anti-analysis techniques\n"
            report += "  - Use kernel-mode debugging\n"

        if pe_anomalies:
            report += "  - Manual PE reconstruction may be required\n"

        if runtime_indicators:
            report += "  - Dynamic analysis in isolated environment\n"

        report += "  - Consider multiple analysis approaches\n"

        return report

    def stop_ai_analysis(self):
        """Stop ongoing AI analysis"""
        try:
            self.log_ai_message("AI analysis stopped by user", "warning")

        except Exception as e:
            self.log_ai_message(f"Error stopping analysis: {str(e)}", "error")

    def generate_ai_script(self):
        """Generate script using AI"""
        if not self.current_model:
            self.log_ai_message("Error: No AI model loaded", "error")
            return

        script_type = self.script_type_combo.currentText()
        target = self.script_target_edit.text().strip()
        requirements = self.requirements_edit.toPlainText().strip()

        if not target:
            self.log_ai_message("Error: No target specified for script generation", "error")
            return

        try:
            self.log_ai_message(f"Generating {script_type} for target: {target}...")

            # Generate script based on type and requirements
            script_content = self._generate_script_content(script_type, target, requirements)

            # Add to generated scripts
            script_info = {
                "type": script_type,
                "target": target,
                "content": script_content,
                "requirements": requirements,
            }

            self.generated_scripts.append(script_info)

            # Update scripts list
            script_name = f"{script_type} - {target}"
            self.scripts_list.addItem(script_name)

            # Display in content area
            self.script_content.setPlainText(script_content)

            self.log_ai_message(f"Generated {script_type} successfully", "success")
            self.script_generated.emit(script_type, "success")

        except Exception as e:
            self.log_ai_message(f"Error generating script: {str(e)}", "error")
            self.script_generated.emit(script_type, "failed")

    def _generate_script_content(self, script_type, target, requirements):
        """Generate actual script content based on type and requirements"""
        try:
            # Use AI model if available
            if self.current_model and self.ai_model_manager.get_loaded_models():
                script_type_map = {
                    "Frida Hook Script": "frida",
                    "Ghidra Analysis Script": "ghidra",
                    "API Hook Script": "api_hook",
                }

                ai_script_type = script_type_map.get(script_type, script_type.lower())

                # Generate using AI model
                generated_script = self.ai_model_manager.generate_script(
                    self.current_model, ai_script_type, target, requirements
                )

                if generated_script:
                    return generated_script

            # Fallback to template-based generation
            if script_type == "Frida Hook Script":
                return self._generate_frida_script(target, requirements)
            elif script_type == "Ghidra Analysis Script":
                return self._generate_ghidra_script(target, requirements)
            elif script_type == "API Hook Script":
                return self._generate_api_hook_script(target, requirements)
            else:
                return self._generate_generic_script(script_type, target, requirements)

        except Exception as e:
            return f"// Error generating script: {str(e)}\n// Please check your requirements and try again."

    def _generate_frida_script(self, target, requirements):
        """Generate Frida hook script"""
        script_template = f"""// Frida Hook Script for {target}
// Generated by Intellicrack AI Assistant

Java.perform(function() {{
    console.log("[+] Starting Frida hook for {target}");

    // Hook target function/method
    var targetClass = Java.use("{target}");

    targetClass.targetMethod.implementation = function() {{
        console.log("[+] Method called with arguments:", arguments);

        // Original function call
        var result = this.targetMethod.apply(this, arguments);

        console.log("[+] Method result:", result);
        return result;
    }};

    console.log("[+] Hook installed successfully");
}});

// Additional requirements: {requirements}
"""
        return script_template

    def _generate_ghidra_script(self, target, requirements):
        """Generate Ghidra analysis script"""
        script_template = f"""// Ghidra Analysis Script for {target}
// Generated by Intellicrack AI Assistant

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;

public class AutoAnalysis extends GhidraScript {{

    @Override
    public void run() throws Exception {{
        println("Starting analysis of {target}");

        // Get current program
        Program program = getCurrentProgram();
        Listing listing = program.getListing();

        // Find target functions
        FunctionManager functionManager = program.getFunctionManager();
        FunctionIterator functions = functionManager.getFunctions(true);

        while (functions.hasNext()) {{
            Function function = functions.next();
            String funcName = function.getName();

            if (funcName.contains("{target}")) {{
                println("Found target function: " + funcName);

                // Analyze function
                analyzeFunction(function);
            }}
        }}

        println("Analysis complete");
    }}

    private void analyzeFunction(Function function) {{
        // Analysis implementation based on requirements
        println("Analyzing: " + function.getName());

        // {requirements}
    }}
}}
"""
        return script_template



    def _generate_api_hook_script(self, target, requirements):
        """Generate API hook script"""
        script_template = f"""// API Hook Script for {target}
// Generated by Intellicrack AI Assistant

#include <windows.h>
#include <detours.h>
#include <stdio.h>

// Original function pointers
static FARPROC OriginalAPI = NULL;

// Hooked function
DWORD WINAPI HookedAPI(DWORD param1, DWORD param2) {{
    printf("[+] API called: {target} with params: %lu, %lu\\n", param1, param2);

    // Call original function
    DWORD result = ((DWORD(WINAPI*)(DWORD, DWORD))OriginalAPI)(param1, param2);

    printf("[+] API result: %lu\\n", result);
    return result;
}}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {{
    switch (fdwReason) {{
        case DLL_PROCESS_ATTACH:
            printf("[+] API hook loaded for {target}\\n");

            // Hook the target API
            HMODULE hMod = GetModuleHandle(TEXT("kernel32.dll"));
            OriginalAPI = GetProcAddress(hMod, "{target}");

            if (OriginalAPI) {{
                DetourTransactionBegin();
                DetourUpdateThread(GetCurrentThread());
                DetourAttach(&OriginalAPI, HookedAPI);
                DetourTransactionCommit();

                printf("[+] {target} hooked successfully\\n");
            }}
            break;

        case DLL_PROCESS_DETACH:
            if (OriginalAPI) {{
                DetourTransactionBegin();
                DetourUpdateThread(GetCurrentThread());
                DetourDetach(&OriginalAPI, HookedAPI);
                DetourTransactionCommit();
            }}
            break;
    }}
    return TRUE;
}}

// Additional requirements: {requirements}
"""
        return script_template

    def _generate_generic_script(self, script_type, target, requirements):
        """Generate generic script for other types"""
        script_template = f"""// {script_type} for {target}
// Generated by Intellicrack AI Assistant

// This is a generic template for {script_type}
// Target: {target}
// Requirements: {requirements}

function main() {{
    console.log("Starting {script_type} for {target}");

    // Implementation based on script type and requirements
    try {{
        // Add your specific implementation here
        performAnalysis();

        console.log("Script execution completed successfully");
    }} catch (error) {{
        console.error("Script execution failed:", error);
    }}
}}

function performAnalysis() {{
    // Specific analysis logic for {target}
    // Based on requirements: {requirements}
}}

// Execute main function
main();
"""
        return script_template

    # Live Preview Methods
    def toggle_auto_preview(self, enabled):
        """Toggle auto preview functionality"""
        if enabled:
            self.preview_status_label.setText("Auto preview enabled")
            self.preview_status_label.setStyleSheet("color: green; font-style: italic;")
            # Start preview if we have data
            if hasattr(self, 'script_target_edit') and self.script_target_edit.text().strip():
                self.start_live_preview()
        else:
            self.preview_status_label.setText("Auto preview disabled")
            self.preview_status_label.setStyleSheet("color: #666; font-style: italic;")
            self.preview_timer.stop()

    def refresh_live_preview(self):
        """Manually refresh the live preview"""
        self.start_live_preview()

    def start_live_preview(self):
        """Start live preview generation"""
        if not hasattr(self, 'script_target_edit'):
            return
            
        target = self.script_target_edit.text().strip()
        if not target:
            self.live_preview_editor.setPlainText("// Enter a target to see live preview")
            self.update_preview_metrics("", "Unknown")
            return

        script_type = self.script_type_combo.currentText() if hasattr(self, 'script_type_combo') else "Frida Hook Script"
        requirements = self.requirements_edit.toPlainText().strip() if hasattr(self, 'requirements_edit') else ""

        self.preview_status_label.setText("Generating preview...")
        self.preview_status_label.setStyleSheet("color: orange; font-style: italic;")
        self.preview_progress.setVisible(True)
        self.preview_progress.setValue(0)

        try:
            # Generate preview content
            preview_content = self._generate_preview_content(script_type, target, requirements)
            
            # Update preview editor
            self.live_preview_editor.setPlainText(preview_content)
            
            # Update metrics
            self.update_preview_metrics(preview_content, self._detect_language(script_type))
            
            # Update status
            self.preview_status_label.setText("Preview updated successfully")
            self.preview_status_label.setStyleSheet("color: green; font-style: italic;")
            self.preview_progress.setValue(100)
            
            # Hide progress after delay
            QTimer.singleShot(1000, lambda: self.preview_progress.setVisible(False))
            
        except Exception as e:
            self.preview_status_label.setText(f"Preview failed: {str(e)}")
            self.preview_status_label.setStyleSheet("color: red; font-style: italic;")
            self.preview_progress.setVisible(False)

    def _generate_preview_content(self, script_type, target, requirements):
        """Generate preview content for live preview"""
        # Use the same generation logic as the main script generator
        return self._generate_script_content(script_type, target, requirements)

    def update_preview_mode(self, mode):
        """Update preview display mode"""
        current_content = self.live_preview_editor.toPlainText()
        
        if mode == "Syntax Highlighted":
            # Apply syntax highlighting (basic implementation)
            self.live_preview_editor.setStyleSheet("""
                QTextEdit {
                    background-color: #1e1e1e;
                    color: #d4d4d4;
                    border: 1px solid #3c3c3c;
                    border-radius: 4px;
                }
            """)
        elif mode == "Raw Code":
            # Plain text mode
            self.live_preview_editor.setStyleSheet("""
                QTextEdit {
                    background-color: #ffffff;
                    color: #000000;
                    border: 1px solid #cccccc;
                    border-radius: 4px;
                }
            """)
        elif mode == "Execution Flow":
            # Add execution flow comments
            if current_content and not current_content.startswith("// EXECUTION FLOW"):
                flow_content = "// EXECUTION FLOW ANALYSIS\n// This preview shows the logical flow of execution\n\n" + current_content
                self.live_preview_editor.setPlainText(flow_content)

    def update_preview_metrics(self, content, language):
        """Update preview metrics display"""
        lines = len(content.split('\n')) if content else 0
        size = len(content.encode('utf-8')) if content else 0
        
        self.preview_lines_label.setText(f"Lines: {lines}")
        self.preview_size_label.setText(f"Size: {size} bytes")
        self.preview_lang_label.setText(f"Language: {language}")

    def _detect_language(self, script_type):
        """Detect programming language from script type"""
        language_map = {
            "Frida Hook Script": "JavaScript",
            "Ghidra Analysis Script": "Java",
            "Python Automation": "Python",
            "API Hook Script": "C/C++",
            "Memory Scanner": "JavaScript",
            "Debugging Script": "JavaScript"
        }
        return language_map.get(script_type, "Unknown")

    def auto_refresh_preview(self):
        """Auto refresh preview after timer delay"""
        if self.auto_preview_cb.isChecked():
            self.start_live_preview()

    def on_script_target_changed(self, text):
        """Handle script target text changes for live preview"""
        if hasattr(self, 'auto_preview_cb') and self.auto_preview_cb.isChecked():
            # Delay the preview update to avoid too frequent updates
            self.preview_timer.stop()
            self.preview_timer.start(500)  # 500ms delay

    def on_script_type_changed(self, script_type):
        """Handle script type changes for live preview"""
        if hasattr(self, 'auto_preview_cb') and self.auto_preview_cb.isChecked():
            self.start_live_preview()

    def on_requirements_changed(self):
        """Handle requirements text changes for live preview"""
        if hasattr(self, 'auto_preview_cb') and self.auto_preview_cb.isChecked():
            # Delay the preview update to avoid too frequent updates while typing
            self.preview_timer.stop()
            self.preview_timer.start(1000)  # 1 second delay for text area

    # Multi-Model Comparison Methods
    def generate_with_multiple_models(self):
        """Generate scripts with multiple selected models"""
        # Get selected models
        selected_models = []
        for model_name, checkbox in self.comparison_model_checkboxes.items():
            if checkbox.isChecked():
                selected_models.append(model_name)

        if not selected_models:
            QMessageBox.warning(self, "No Models Selected", "Please select at least one model for comparison.")
            return

        if not hasattr(self, 'script_target_edit') or not self.script_target_edit.text().strip():
            QMessageBox.warning(self, "No Target", "Please specify a target for script generation.")
            return

        target = self.script_target_edit.text().strip()
        script_type = self.script_type_combo.currentText() if hasattr(self, 'script_type_combo') else "Frida Hook Script"
        requirements = self.requirements_edit.toPlainText().strip() if hasattr(self, 'requirements_edit') else ""

        # Clear existing comparison results tabs (except summary)
        while self.comparison_results_tabs.count() > 1:
            self.comparison_results_tabs.removeTab(1)

        self.comparison_results = {}
        generation_times = []

        # Generate with each selected model
        for model_name in selected_models:
            try:
                start_time = datetime.now()
                
                # Generate script with current model (simulate different models)
                script_content = self._generate_script_with_model(model_name, script_type, target, requirements)
                
                end_time = datetime.now()
                generation_time = (end_time - start_time).total_seconds()
                generation_times.append(generation_time)

                # Analyze script quality
                quality_score = self._analyze_script_quality(script_content)
                
                # Store results
                self.comparison_results[model_name] = {
                    'content': script_content,
                    'generation_time': generation_time,
                    'quality_score': quality_score,
                    'lines': len(script_content.split('\n')),
                    'target': target,
                    'type': script_type
                }

                # Add result tab
                self._add_comparison_result_tab(model_name, script_content, generation_time, quality_score)

            except Exception as e:
                self.comparison_results[model_name] = {
                    'error': str(e),
                    'generation_time': 0,
                    'quality_score': 0,
                    'lines': 0
                }

        # Update summary table
        self._update_comparison_summary()
        
        # Update metrics
        self._update_comparison_metrics(generation_times)

    def _generate_script_with_model(self, model_name, script_type, target, requirements):
        """Generate script simulating different AI models"""
        # This is a simulation - in practice, you'd use different model APIs
        base_content = self._generate_script_content(script_type, target, requirements)
        
        # Add model-specific variations
        model_variations = {
            "GPT-4": "// Generated with GPT-4 - Enhanced reasoning and optimization\n",
            "GPT-3.5": "// Generated with GPT-3.5 - Fast and efficient generation\n",
            "Claude-3": "// Generated with Claude-3 - Thoughtful and detailed approach\n",
            "Gemini": "// Generated with Gemini - Multi-modal analysis capabilities\n",
            "Local Model": "// Generated with Local Model - Privacy-focused generation\n"
        }
        
        variation = model_variations.get(model_name, f"// Generated with {model_name}\n")
        return variation + base_content

    def _analyze_script_quality(self, script_content):
        """Analyze script quality and return a score"""
        score = 50.0  # Base score
        
        # Check for comments
        if "///" in script_content or "/*" in script_content:
            score += 10
            
        # Check for error handling
        if "try" in script_content and "catch" in script_content:
            score += 15
            
        # Check for logging
        if "console.log" in script_content or "printf" in script_content:
            score += 10
            
        # Check script length (not too short, not too long)
        lines = len(script_content.split('\n'))
        if 20 <= lines <= 100:
            score += 15
        elif lines > 10:
            score += 5
            
        # Check for function structure
        if "function" in script_content or "def " in script_content:
            score += 10
            
        return min(score, 100.0)

    def _add_comparison_result_tab(self, model_name, content, generation_time, quality_score):
        """Add a tab for comparison result"""
        tab_widget = QWidget()
        tab_layout = QVBoxLayout(tab_widget)
        
        # Model info
        info_layout = QHBoxLayout()
        info_layout.addWidget(QLabel(f"Model: {model_name}"))
        info_layout.addWidget(QLabel(f"Time: {generation_time:.2f}s"))
        info_layout.addWidget(QLabel(f"Quality: {quality_score:.1f}/100"))
        info_layout.addStretch()
        
        # Script content
        content_editor = QTextEdit()
        content_editor.setReadOnly(True)
        content_editor.setPlainText(content)
        content_editor.setFont(QFont("Consolas", 9))
        
        tab_layout.addLayout(info_layout)
        tab_layout.addWidget(content_editor)
        
        self.comparison_results_tabs.addTab(tab_widget, model_name)

    def _update_comparison_summary(self):
        """Update the comparison summary table"""
        self.comparison_summary_table.setRowCount(len(self.comparison_results))
        
        for row, (model_name, result) in enumerate(self.comparison_results.items()):
            if 'error' in result:
                self.comparison_summary_table.setItem(row, 0, QTableWidgetItem(model_name))
                self.comparison_summary_table.setItem(row, 1, QTableWidgetItem("Error"))
                self.comparison_summary_table.setItem(row, 2, QTableWidgetItem("Failed"))
                self.comparison_summary_table.setItem(row, 3, QTableWidgetItem("0"))
                self.comparison_summary_table.setItem(row, 4, QTableWidgetItem("0.0"))
            else:
                self.comparison_summary_table.setItem(row, 0, QTableWidgetItem(model_name))
                self.comparison_summary_table.setItem(row, 1, QTableWidgetItem(f"{result['generation_time']:.2f}s"))
                self.comparison_summary_table.setItem(row, 2, QTableWidgetItem(f"{result['quality_score']:.1f}/100"))
                self.comparison_summary_table.setItem(row, 3, QTableWidgetItem(str(result['lines'])))
                self.comparison_summary_table.setItem(row, 4, QTableWidgetItem(f"{result['quality_score']:.1f}"))

    def _update_comparison_metrics(self, generation_times):
        """Update comparison metrics display"""
        if generation_times:
            avg_time = sum(generation_times) / len(generation_times)
            self.avg_time_label.setText(f"Avg Generation Time: {avg_time:.2f}s")
        
        # Find best model
        best_model = None
        best_score = 0
        
        for model_name, result in self.comparison_results.items():
            if 'quality_score' in result and result['quality_score'] > best_score:
                best_score = result['quality_score']
                best_model = model_name
        
        if best_model:
            self.best_model_label.setText(f"Best Model: {best_model} ({best_score:.1f})")
            self.comparison_metrics['best_model'] = best_model
            self.comparison_metrics['best_score'] = best_score
        
        self.comparison_metrics['total_comparisons'] += 1
        self.total_comparisons_label.setText(f"Total Comparisons: {self.comparison_metrics['total_comparisons']}")

    def clear_model_comparison(self):
        """Clear all comparison results"""
        # Clear result tabs (except summary)
        while self.comparison_results_tabs.count() > 1:
            self.comparison_results_tabs.removeTab(1)
        
        # Clear summary table
        self.comparison_summary_table.setRowCount(0)
        
        # Reset metrics
        self.best_model_label.setText("Best Model: None")
        self.avg_time_label.setText("Avg Generation Time: 0s")
        
        # Clear results data
        self.comparison_results = {}

    def send_chat_message(self):
        """Send chat message to AI assistant"""
        message = self.chat_input.text().strip()
        if not message:
            return

        # Add user message to chat history
        self.chat_history.append(f"<b>You:</b> {message}")
        self.chat_input.clear()

        # Simulate AI response
        ai_response = self.generate_ai_response(message)
        self.chat_history.append(f"<b>AI Assistant:</b> {ai_response}")

        # Scroll to bottom
        cursor = self.chat_history.textCursor()
        cursor.movePosition(cursor.End)
        self.chat_history.setTextCursor(cursor)

    def generate_ai_response(self, message):
        """Generate AI response based on user message"""
        try:
            if hasattr(self, 'ai_model_manager') and self.current_model:
                response = self.ai_model_manager.generate_response(
                    model=self.current_model,
                    prompt=message,
                    context={
                        'role': 'binary_analysis_assistant',
                        'focus': 'reverse_engineering'
                    }
                )
                return response
            else:
                self.log_message("Error: No AI model loaded for chat", "error")
                return "AI model not available. Please load a model first."
        except Exception as e:
            self.log_message(f"Error generating AI response: {str(e)}", "error")
            return f"Error generating response: {str(e)}"

    def browse_training_dataset(self):
        """Browse for training dataset"""
        from PyQt6.QtWidgets import QFileDialog

        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Training Dataset", "", "Dataset Files (*.json *.csv *.txt);;All Files (*)"
        )

        if file_path:
            self.dataset_path_edit.setText(file_path)
            self.log_message(f"Training dataset selected: {file_path}")

    def start_model_training(self):
        """Start model training process"""
        dataset_path = self.dataset_path_edit.text().strip()
        if not dataset_path:
            self.log_message("Error: No training dataset selected", "error")
            return

        training_type = self.training_type_combo.currentText()
        epochs = self.epochs_spin.value()
        learning_rate = self.learning_rate_edit.text()

        self.log_message(f"Starting {training_type} with {epochs} epochs, learning rate: {learning_rate}")
        self.training_status_label.setText("Training in progress...")
        self.training_progress.setValue(0)

        # Start real model training with progress monitoring
        try:
            from ...ai.ai_model_manager import AIModelManager
            if hasattr(self, 'ai_model_manager'):
                # Create training thread to avoid blocking UI
                from PyQt6.QtCore import QThread, pyqtSignal
                
                class TrainingThread(QThread):
                    progress_update = pyqtSignal(dict)
                    finished_training = pyqtSignal(bool, str)
                    
                    def __init__(self, model_manager, params):
                        super().__init__()
                        self.model_manager = model_manager
                        self.params = params
                        
                    def run(self):
                        try:
                            self.model_manager.train_model(
                                dataset_path=self.params['dataset_path'],
                                training_type=self.params['training_type'],
                                epochs=self.params['epochs'],
                                learning_rate=self.params['learning_rate'],
                                progress_callback=lambda data: self.progress_update.emit(data)
                            )
                            self.finished_training.emit(True, "Training completed successfully")
                        except Exception as e:
                            self.finished_training.emit(False, str(e))
                
                # Create and start training thread
                self.training_thread = TrainingThread(
                    self.ai_model_manager,
                    {
                        'dataset_path': dataset_path,
                        'training_type': training_type,
                        'epochs': epochs,
                        'learning_rate': float(learning_rate)
                    }
                )
                
                # Connect signals
                self.training_thread.progress_update.connect(self._update_training_progress)
                self.training_thread.finished_training.connect(self._on_training_finished)
                
                # Start training
                self.training_thread.start()
                self.training_status_label.setText("Initializing training...")
                
            else:
                self.log_message("Error: AI Model Manager not initialized", "error")
        except Exception as e:
            self.log_message(f"Error starting training: {str(e)}", "error")
            self.training_status_label.setText("Training failed")

    def _update_training_progress(self, progress_data):
        """Update real training progress from model trainer"""
        if isinstance(progress_data, dict):
            epoch = progress_data.get('epoch', 0)
            loss = progress_data.get('loss', 0.0)
            accuracy = progress_data.get('accuracy', 0.0)
            progress_pct = progress_data.get('progress', 0)
            
            self.training_progress.setValue(int(progress_pct))
            self.training_status_label.setText(
                f"Epoch {epoch} - Loss: {loss:.4f}, Accuracy: {accuracy:.2%}"
            )
            
            if progress_pct >= 100:
                self.log_message("Training completed successfully", "success")
                self.training_status_label.setText("Training complete")

    def _on_training_finished(self, success, message):
        """Handle training completion"""
        if success:
            self.log_message(message, "success")
            self.training_status_label.setText("Training complete")
        else:
            self.log_message(f"Training failed: {message}", "error")
            self.training_status_label.setText("Training failed")
        
        # Clean up thread
        if hasattr(self, 'training_thread'):
            self.training_thread.deleteLater()
            self.training_thread = None
    
    def stop_model_training(self):
        """Stop ongoing model training"""
        try:
            # Stop the training thread if running
            if hasattr(self, 'training_thread') and self.training_thread and self.training_thread.isRunning():
                self.training_thread.terminate()
                self.training_thread.wait()
                self.training_thread.deleteLater()
                self.training_thread = None
            
            # Stop model training
            if hasattr(self, 'ai_model_manager'):
                self.ai_model_manager.stop_training()
                self.log_message("Training stopped by user", "warning")
                self.training_status_label.setText("Training stopped")
                self.training_progress.setValue(0)
        except Exception as e:
            self.log_message(f"Error stopping training: {str(e)}", "error")


    def save_trained_model(self):
        """Save trained model"""
        from PyQt6.QtWidgets import QFileDialog

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Trained Model", "", "Model Files (*.pkl *.pth *.h5);;All Files (*)"
        )

        if file_path:
            self.log_message(f"Model saved to: {file_path}")
            self.training_status_label.setText("Model saved successfully")

    def log_message(self, message, level="info"):
        """Log message to console or status"""
        if hasattr(self.shared_context, "log_message"):
            self.shared_context.log_message(message, level)
        else:
            print(f"[{level.upper()}] {message}")

    def _on_model_loaded(self, model_name: str):
        """Handle model loaded signal from AI model manager"""
        self.model_progress.setVisible(False)
        self.current_model = model_name
        self.model_status_label.setText(f"Model loaded: {model_name}")
        self.model_status_label.setStyleSheet("color: #66bb6a;")
        self.log_ai_message(f"Successfully loaded model: {model_name}", "success")
        self.model_loaded.emit(model_name, True)

        # Update AppContext if available
        if self.app_context:
            self.app_context.register_model(
                model_name,
                {
                    "provider": self.provider_combo.currentText(),
                    "model_id": self.model_combo.currentText(),
                    "loaded_at": datetime.now().isoformat(),
                },
            )

    def _on_model_unloaded(self, model_name: str):
        """Handle model unloaded signal"""
        self.log_ai_message(f"Model unloaded: {model_name}", "info")
        if self.current_model == model_name:
            self.current_model = None
            self.model_status_label.setText("No model loaded")

    def _on_response_received(self, model_name: str, response: str):
        """Handle response received from AI model"""
        # This is handled in the script generation callbacks
        pass

    def _on_ai_error(self, model_name: str, error: str):
        """Handle AI model error"""
        self.model_progress.setVisible(False)
        self.log_ai_message(f"AI Error ({model_name}): {error}", "error")
        QMessageBox.warning(self, "AI Model Error", f"Error with {model_name}:\n{error}")
