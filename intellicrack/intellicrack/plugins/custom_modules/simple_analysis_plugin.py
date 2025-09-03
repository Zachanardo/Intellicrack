"""Simple Analysis Plugin Template
Basic template for straightforward binary analysis tasks.
"""


class SimpleAnalysisPlugin:
    """Simple plugin template for straightforward binary analysis tasks."""

    def __init__(self):
        """Initialize simple analysis plugin with basic metadata."""
        self.name = "Simple Analysis Plugin"
        self.version = "1.0.0"
        self.description = "Template for simple binary analysis tasks"

    def analyze(self, binary_path):
        """Simple analysis implementation."""
        results = []
        results.append(f"Analyzing: {binary_path}")

        # Your analysis code here
        import os

        file_size = os.path.getsize(binary_path)
        results.append(f"File size: {file_size:,} bytes")

        return results


def register():
    """Register and return SimpleAnalysisPlugin instance."""
    return SimpleAnalysisPlugin()
