"""Perform Analysis Plugin Template.

Basic template for straightforward binary analysis tasks.
"""

class SimpleAnalysisPlugin:
    """Perform simple binary analysis tasks."""

    def __init__(self):
        """Initialize the simple analysis plugin."""
        self.name = "Simple Analysis Plugin"
        self.version = "1.0.0"
        self.description = "Template for simple binary analysis tasks"

    def analyze(self, binary_path):
        """Analyze binary file and return basic information."""
        results = []
        results.append(f"Analyzing: {binary_path}")

        # Your analysis code here
        import os
        file_size = os.path.getsize(binary_path)
        results.append(f"File size: {file_size:,} bytes")

        return results

def register():
    """Register and instantiate the simple analysis plugin."""
    return SimpleAnalysisPlugin()
