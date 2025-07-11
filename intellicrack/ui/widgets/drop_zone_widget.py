from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel
from PyQt6.QtCore import Qt, pyqtSignal, QMimeData
from PyQt6.QtGui import QPainter, QPen, QColor, QDragEnterEvent, QDropEvent, QFont
import os


class DropZoneWidget(QWidget):
    """A widget that provides a visual drop zone for files"""
    
    files_dropped = pyqtSignal(list)  # List of file paths
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.is_dragging = False
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Icon and text
        self.label = QLabel("Drop files here for analysis")
        self.label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        font = QFont()
        font.setPointSize(12)
        self.label.setFont(font)
        
        self.info_label = QLabel("Supported: .exe, .dll, .so, .elf, .apk, etc.")
        self.info_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.info_label.setStyleSheet("color: #666;")
        
        layout.addStretch()
        layout.addWidget(self.label)
        layout.addWidget(self.info_label)
        layout.addStretch()
        
        # Style
        self.setMinimumHeight(150)
        self.update_style()
        
    def update_style(self):
        """Update widget style based on state"""
        if self.is_dragging:
            self.setStyleSheet("""
                DropZoneWidget {
                    background-color: #e3f2fd;
                    border: 3px dashed #2196f3;
                    border-radius: 10px;
                }
            """)
            self.label.setText("Release to load files")
        else:
            self.setStyleSheet("""
                DropZoneWidget {
                    background-color: #f5f5f5;
                    border: 2px dashed #ccc;
                    border-radius: 10px;
                }
                DropZoneWidget:hover {
                    background-color: #eeeeee;
                    border-color: #999;
                }
            """)
            self.label.setText("Drop files here for analysis")
            
    def paintEvent(self, event):
        """Custom paint event"""
        super().paintEvent(event)
        
        # Draw additional visual elements if needed
        if self.is_dragging:
            painter = QPainter(self)
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            
            # Draw highlight
            pen = QPen(QColor(33, 150, 243, 50))
            pen.setWidth(10)
            painter.setPen(pen)
            painter.drawRoundedRect(self.rect().adjusted(5, 5, -5, -5), 10, 10)
            
    def dragEnterEvent(self, event: QDragEnterEvent):
        """Handle drag enter"""
        if event.mimeData().hasUrls():
            # Check if any files are supported
            for url in event.mimeData().urls():
                if url.isLocalFile() and self._is_supported_file(url.toLocalFile()):
                    event.acceptProposedAction()
                    self.is_dragging = True
                    self.update_style()
                    return
        event.ignore()
        
    def dragLeaveEvent(self, event):
        """Handle drag leave"""
        self.is_dragging = False
        self.update_style()
        
    def dropEvent(self, event: QDropEvent):
        """Handle drop"""
        self.is_dragging = False
        self.update_style()
        
        if event.mimeData().hasUrls():
            file_paths = []
            for url in event.mimeData().urls():
                if url.isLocalFile():
                    file_path = url.toLocalFile()
                    if self._is_supported_file(file_path):
                        file_paths.append(file_path)
                        
            if file_paths:
                self.files_dropped.emit(file_paths)
                event.acceptProposedAction()
                return
                
        event.ignore()
        
    def _is_supported_file(self, file_path: str) -> bool:
        """Check if file is supported"""
        if not os.path.exists(file_path):
            return False
            
        # Supported extensions
        supported_exts = [
            '.exe', '.dll', '.so', '.dylib', '.elf', '.bin',
            '.sys', '.drv', '.ocx', '.app', '.apk', '.ipa',
            '.dex', '.jar', '.class', '.pyc', '.pyd', '.msi',
            '.rpm', '.deb', '.dmg', '.pkg'
        ]
        
        ext = os.path.splitext(file_path)[1].lower()
        return ext in supported_exts