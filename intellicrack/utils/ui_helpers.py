"""Common UI helper functions to reduce code duplication."""

def check_binary_path_and_warn(app_instance):
    """Check if binary path exists and show warning if not.
    
    Args:
        app_instance: Application instance with binary_path and QMessageBox access
        
    Returns:
        bool: True if binary path exists, False if missing
    """
    if not hasattr(app_instance, 'binary_path') or not app_instance.binary_path:
        try:
            from PyQt5.QtWidgets import QMessageBox
            QMessageBox.warning(app_instance, "No File Selected",
                              "Please select a program first.")
        except ImportError:
            pass
        return False
    return True

def emit_log_message(app_instance, message):
    """Emit log message if app instance supports it.
    
    Args:
        app_instance: Application instance
        message: Message to log
    """
    if hasattr(app_instance, 'update_output') and hasattr(app_instance.update_output, 'emit'):
        try:
            from ..utils.logger import log_message
            app_instance.update_output.emit(log_message(message))
        except ImportError:
            app_instance.update_output.emit(message)
    elif hasattr(app_instance, 'update_output'):
        app_instance.update_output.emit(message)

def show_file_dialog(parent, title, file_filter="HTML Files (*.html);;All Files (*)"):
    """Show file save dialog and return filename.
    
    Args:
        parent: Parent widget
        title: Dialog title
        file_filter: File filter string
        
    Returns:
        str: Selected filename or empty string if cancelled
    """
    try:
        from PyQt5.QtWidgets import QFileDialog
        filename, _ = QFileDialog.getSaveFileName(parent, title, "", file_filter)
        return filename if filename else ""
    except ImportError:
        return ""

def ask_yes_no_question(parent, title, question):
    """Show yes/no question dialog.
    
    Args:
        parent: Parent widget
        title: Dialog title
        question: Question text
        
    Returns:
        bool: True if Yes clicked, False otherwise
    """
    try:
        from PyQt5.QtWidgets import QMessageBox
        return QMessageBox.question(
            parent, title, question,
            QMessageBox.Yes | QMessageBox.No
        ) == QMessageBox.Yes
    except ImportError:
        return False