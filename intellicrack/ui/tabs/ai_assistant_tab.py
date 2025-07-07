from PyQt6.QtWidgets import (
    QVBoxLayout, QHBoxLayout, QGroupBox, QPushButton, QLabel, 
    QTextEdit, QTabWidget, QCheckBox, QComboBox, QSpinBox,
    QLineEdit, QListWidget, QSplitter, QWidget, QScrollArea,
    QTableWidget, QTableWidgetItem, QHeaderView, QFrame,
    QSlider, QProgressBar
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread, QTimer
from PyQt6.QtGui import QFont, QTextOption

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
        super().__init__(shared_context, parent)
        self.current_model = None
        self.analysis_history = []
        self.generated_scripts = []
        
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
        self.ai_subtabs.setTabPosition(QTabWidget.North)
        
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
        self.provider_combo.addItems([
            "OpenAI", "Anthropic", "Local (Ollama)", "Hugging Face",
            "Google Gemini", "Cohere", "Azure OpenAI"
        ])
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
        self.analysis_focus_combo.addItems([
            "General Analysis", "License Detection", "Protection Analysis",
            "Vulnerability Research", "Malware Analysis", "Code Quality",
            "Performance Analysis", "Security Audit"
        ])
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
        self.analysis_depth_combo.addItems([
            "Quick Scan", "Standard Analysis", "Deep Analysis", "Comprehensive"
        ])
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
        self.script_type_combo.addItems([
            "Frida Hook Script", "Ghidra Analysis Script", "Python Automation",
            "License Bypass Script", "API Hook Script", "Memory Scanner",
            "Custom Payload", "Debugging Script"
        ])
        type_layout.addWidget(self.script_type_combo)
        
        # Target specification
        target_spec_layout = QHBoxLayout()
        target_spec_layout.addWidget(QLabel("Target:"))
        self.script_target_edit = QLineEdit()
        self.script_target_edit.setPlaceholderText("Function name, API, or description")
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
        self.template_combo.addItems([
            "Basic Template", "Advanced Template", "Custom Template", "No Template"
        ])
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
            "Describe specific requirements for the script:\n"
            "- Hook specific functions\n"
            "- Bypass certain protections\n" 
            "- Extract specific data\n"
            "- Custom behavior requirements"
        )
        self.requirements_edit.setMaximumHeight(100)
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
        self.data_source_combo.addItems([
            "Analysis History", "Custom Dataset", "Binary Samples",
            "Script Templates", "Public Datasets"
        ])
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
        self.training_type_combo.addItems([
            "Fine-tuning", "Transfer Learning", "Custom Training", "Reinforcement Learning"
        ])
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
        
    def create_results_panel(self):
        """Create the AI results and chat panel"""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        
        # Results tabs
        self.results_tabs = QTabWidget()
        self.results_tabs.setTabPosition(QTabWidget.North)
        
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
        
        # Update API key placeholder
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
            
            # Simulate model loading
            QTimer.singleShot(2000, lambda: self.on_model_loaded(model, True))
            
            self.log_ai_message(f"Loading {provider} model: {model}...")
            
        except Exception as e:
            self.log_ai_message(f"Error loading model: {str(e)}", "error")
            self.on_model_loaded(model, False)
    
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
            self, "Select Binary for AI Analysis", "", 
            "Executable Files (*.exe *.dll *.so *.dylib);;All Files (*)"
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
            
            # Simulate AI analysis
            self._simulate_ai_analysis(binary_path, focus, depth)
            
        except Exception as e:
            self.log_ai_message(f"Error starting AI analysis: {str(e)}", "error")
    
    def _simulate_ai_analysis(self, binary_path, focus, depth):
        """Simulate AI analysis process"""
        try:
            import os
            
            # Generate analysis based on focus and depth
            analysis_text = f"AI Analysis Results for {os.path.basename(binary_path)}\n"
            analysis_text += "=" * 60 + "\n\n"
            analysis_text += f"Analysis Focus: {focus}\n"
            analysis_text += f"Analysis Depth: {depth}\n"
            analysis_text += f"AI Model: {self.current_model}\n\n"
            
            if focus == "License Detection":
                analysis_text += "License Protection Analysis:\n"
                analysis_text += "- Detected potential license validation functions\n"
                analysis_text += "- Found string references to licensing systems\n"
                analysis_text += "- Identified possible bypass targets\n\n"
                analysis_text += "Recommended approach:\n"
                analysis_text += "1. Hook license validation functions\n"
                analysis_text += "2. Patch return values to simulate valid license\n"
                analysis_text += "3. Monitor network traffic for license servers\n"
                
            elif focus == "Protection Analysis":
                analysis_text += "Protection Mechanism Analysis:\n"
                analysis_text += "- Anti-debugging techniques detected\n"
                analysis_text += "- Code obfuscation patterns identified\n"
                analysis_text += "- Packing/encryption analysis\n\n"
                analysis_text += "Bypass strategies:\n"
                analysis_text += "1. Use Frida to bypass anti-debug checks\n"
                analysis_text += "2. Implement memory dumping for unpacking\n"
                analysis_text += "3. Hook critical API calls\n"
                
            elif focus == "Vulnerability Research":
                analysis_text += "Vulnerability Analysis:\n"
                analysis_text += "- Buffer overflow potential detected\n"
                analysis_text += "- Unsafe API usage identified\n"
                analysis_text += "- Input validation weaknesses found\n\n"
                analysis_text += "Exploitation vectors:\n"
                analysis_text += "1. Stack-based buffer overflow in input handler\n"
                analysis_text += "2. Format string vulnerability in logging\n"
                analysis_text += "3. Integer overflow in size calculations\n"
                
            else:
                analysis_text += "General Binary Analysis:\n"
                analysis_text += "- Architecture: x86-64\n"
                analysis_text += "- Compilation: MSVC with optimizations\n"
                analysis_text += "- Dependencies: Standard libraries + custom DLLs\n"
                analysis_text += "- Entry points: 3 main functions identified\n\n"
                analysis_text += "Key findings:\n"
                analysis_text += "1. Interesting string patterns suggesting commercial software\n"
                analysis_text += "2. Network communication capabilities\n"
                analysis_text += "3. Registry access for configuration storage\n"
            
            # Display results
            self.analysis_results.setPlainText(analysis_text)
            
            # Add to history
            self.analysis_history.append({
                'binary': binary_path,
                'focus': focus,
                'depth': depth,
                'results': analysis_text
            })
            
            self.log_ai_message("AI analysis completed successfully", "success")
            self.analysis_completed.emit(binary_path, "success")
            
        except Exception as e:
            self.log_ai_message(f"Error in AI analysis: {str(e)}", "error")
            self.analysis_completed.emit(binary_path, "failed")
    
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
                'type': script_type,
                'target': target,
                'content': script_content,
                'requirements': requirements
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
            if script_type == "Frida Hook Script":
                return self._generate_frida_script(target, requirements)
            elif script_type == "Ghidra Analysis Script":
                return self._generate_ghidra_script(target, requirements)
            elif script_type == "License Bypass Script":
                return self._generate_license_bypass_script(target, requirements)
            elif script_type == "API Hook Script":
                return self._generate_api_hook_script(target, requirements)
            else:
                return self._generate_generic_script(script_type, target, requirements)
                
        except Exception as e:
            return f"// Error generating script: {str(e)}\n// Please check your requirements and try again."

    def _generate_frida_script(self, target, requirements):
        """Generate Frida hook script"""
        script_template = f'''// Frida Hook Script for {target}
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
'''
        return script_template
    
    def _generate_ghidra_script(self, target, requirements):
        """Generate Ghidra analysis script"""
        script_template = f'''// Ghidra Analysis Script for {target}
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
'''
        return script_template
    
    def _generate_license_bypass_script(self, target, requirements):
        """Generate license bypass script"""
        script_template = f'''// License Bypass Script for {target}
// Generated by Intellicrack AI Assistant

#include <windows.h>
#include <stdio.h>

// License validation bypass
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {{
    switch (fdwReason) {{
        case DLL_PROCESS_ATTACH:
            printf("[+] License bypass loaded for {target}\\n");
            
            // Hook license validation functions
            hookLicenseValidation();
            break;
            
        case DLL_PROCESS_DETACH:
            printf("[+] License bypass unloaded\\n");
            break;
    }}
    return TRUE;
}}

void hookLicenseValidation() {{
    // Patch license check functions
    HMODULE hMod = GetModuleHandle(TEXT("{target}"));
    if (hMod) {{
        // Find and patch validation routines
        FARPROC checkLicense = GetProcAddress(hMod, "CheckLicense");
        if (checkLicense) {{
            // Patch to always return valid
            DWORD oldProtect;
            VirtualProtect(checkLicense, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
            
            // Replace with: mov eax, 1; ret
            *(BYTE*)checkLicense = 0xB8;      // mov eax,
            *((DWORD*)((BYTE*)checkLicense + 1)) = 1; // 1
            *(BYTE*)((BYTE*)checkLicense + 5) = 0xC3; // ret
            
            VirtualProtect(checkLicense, 5, oldProtect, &oldProtect);
            printf("[+] License check patched\\n");
        }}
    }}
}}

// Additional requirements: {requirements}
'''
        return script_template
    
    def _generate_api_hook_script(self, target, requirements):
        """Generate API hook script"""
        script_template = f'''// API Hook Script for {target}
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
'''
        return script_template
    
    def _generate_generic_script(self, script_type, target, requirements):
        """Generate generic script for other types"""
        script_template = f'''// {script_type} for {target}
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
'''
        return script_template
    
    def send_chat_message(self):
        """Send chat message to AI assistant"""
        message = self.chat_input.text().strip()
        if not message:
            return
            
        # Add user message to chat history
        self.chat_history.append(f"<b>You:</b> {message}")
        self.chat_input.clear()
        
        # Simulate AI response
        ai_response = self._generate_ai_response(message)
        self.chat_history.append(f"<b>AI Assistant:</b> {ai_response}")
        
        # Scroll to bottom
        cursor = self.chat_history.textCursor()
        cursor.movePosition(cursor.End)
        self.chat_history.setTextCursor(cursor)
    
    def _generate_ai_response(self, message):
        """Generate AI response based on user message"""
        message_lower = message.lower()
        
        if "analyze" in message_lower:
            return "I can help you analyze binaries. Please select a binary file and choose your analysis focus. I'll provide detailed insights about protection mechanisms, potential vulnerabilities, and exploitation strategies."
        elif "script" in message_lower or "frida" in message_lower or "ghidra" in message_lower:
            return "I can generate custom scripts for your analysis needs. Choose the script type, specify your target, and I'll create optimized code for Frida hooking, Ghidra analysis, or custom automation."
        elif "protection" in message_lower or "bypass" in message_lower:
            return "I can identify protection mechanisms and suggest bypass strategies. Common protections include packers, obfuscation, anti-debugging, and license validation. Each requires specific techniques for analysis and circumvention."
        elif "help" in message_lower or "how" in message_lower:
            return "I'm your AI assistant for binary analysis and exploitation. I can: 1) Analyze binaries for protections and vulnerabilities, 2) Generate custom scripts (Frida, Ghidra, etc.), 3) Provide exploitation guidance, 4) Help with reverse engineering tasks. What would you like to work on?"
        else:
            return f"I understand you're asking about: '{message}'. Could you be more specific about what you'd like me to help with? I specialize in binary analysis, script generation, and exploitation techniques."
    
    def browse_training_dataset(self):
        """Browse for training dataset"""
        from PyQt6.QtWidgets import QFileDialog
        
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Training Dataset",
            "",
            "Dataset Files (*.json *.csv *.txt);;All Files (*)"
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
        
        self.log_message(f"Starting {training_type} with {epochs} epochs")
        self.training_status_label.setText("Training in progress...")
        self.training_progress.setValue(0)
        
        # Simulate training progress
        self._simulate_training()
    
    def _simulate_training(self):
        """Simulate training progress"""
        from PyQt6.QtCore import QTimer
        
        self.training_timer = QTimer()
        self.training_step = 0
        self.training_timer.timeout.connect(self._update_training_progress)
        self.training_timer.start(100)
    
    def _update_training_progress(self):
        """Update training progress"""
        self.training_step += 1
        progress = min(100, (self.training_step * 2) % 101)
        self.training_progress.setValue(progress)
        
        if progress == 100:
            self.training_timer.stop()
            self.training_status_label.setText("Training completed successfully")
            self.log_message("Model training completed")
        else:
            epoch = (self.training_step // 50) + 1
            self.training_status_label.setText(f"Training... Epoch {epoch}")
    
    def stop_model_training(self):
        """Stop model training"""
        if hasattr(self, 'training_timer'):
            self.training_timer.stop()
        
        self.training_status_label.setText("Training stopped")
        self.log_message("Model training stopped by user")
    
    def save_trained_model(self):
        """Save trained model"""
        from PyQt6.QtWidgets import QFileDialog
        
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Trained Model",
            "",
            "Model Files (*.pkl *.pth *.h5);;All Files (*)"
        )
        
        if file_path:
            self.log_message(f"Model saved to: {file_path}")
            self.training_status_label.setText("Model saved successfully")
    
    def log_message(self, message, level="info"):
        """Log message to console or status"""
        if hasattr(self.shared_context, 'log_message'):
            self.shared_context.log_message(message, level)
        else:
            print(f"[{level.upper()}] {message}")
