import sys
import os
sys.path.insert(0, 'C:\\Intellicrack')

print("Testing imports...")
try:
    print("Importing main_app...")
    from intellicrack.ui import main_app
    print("Successfully imported main_app")
    
    print("Importing QApplication...")
    from PyQt6.QtWidgets import QApplication
    print("Successfully imported QApplication")
    
    print("Creating app...")
    app = QApplication(sys.argv)
    
    print("Creating main window...")
    window = main_app.MainWindow()
    
    print("Success!")
    
except Exception as e:
    print(f"\nError occurred: {type(e).__name__}: {e}")
    import traceback
    traceback.print_exc()