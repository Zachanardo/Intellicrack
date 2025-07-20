import sys
print("Testing qiling import...")

try:
    import typing_extensions
    import importlib.metadata
    te_version = importlib.metadata.version('typing-extensions')
    print(f"typing-extensions version: {te_version}")
except ImportError:
    print("typing-extensions not found")

try:
    import qiling
    print("✓ qiling imported successfully")
except ImportError as e:
    print(f"✗ qiling import failed: {e}")
    
try:
    # Test basic qiling functionality
    from qiling import Qiling
    print("✓ Qiling class imported successfully")
except Exception as e:
    print(f"✗ Qiling class import failed: {e}")

# Check if python-fx is installed
try:
    import importlib.metadata
    try:
        version = importlib.metadata.version('python-fx')
        print(f"python-fx version: {version}")
    except:
        print("python-fx not installed")
except:
    pass