from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel
from PyQt6.QtCore import QTimer, Qt
from PyQt6.QtGui import QFont

class BaseTab(QWidget):
    """
    Base class for all main application tabs.
    Provides common functionality including loading states, shared context, and consistent styling.
    """
    
    def __init__(self, shared_context=None, parent=None):
        super().__init__(parent)
        self.shared_context = shared_context
        self.is_loaded = False
        self.setup_loading_ui()
        
    def setup_loading_ui(self):
        """Setup initial loading state UI"""
        layout = QVBoxLayout(self)
        
        loading_label = QLabel("Loading...")
        loading_label.setAlignment(Qt.AlignCenter)
        font = QFont()
        font.setPointSize(14)
        loading_label.setFont(font)
        
        layout.addWidget(loading_label)
        
    def lazy_load_content(self):
        """
        Override this method in subclasses to implement lazy loading.
        This method should create and setup the actual tab content.
        """
        if not self.is_loaded:
            self.clear_layout()
            self.setup_content()
            self.is_loaded = True
            
    def setup_content(self):
        """Override this method to setup the actual tab content"""
        pass
        
    def clear_layout(self):
        """Clear all widgets from the current layout"""
        layout = self.layout()
        if layout:
            while layout.count():
                child = layout.takeAt(0)
                if child.widget():
                    child.widget().deleteLater()
                    
    def log_activity(self, message):
        """Log activity to shared context if available"""
        if self.shared_context and hasattr(self.shared_context, 'log_activity'):
            self.shared_context.log_activity(message)