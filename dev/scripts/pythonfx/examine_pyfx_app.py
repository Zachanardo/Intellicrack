import pyfx.app
import inspect

print("=== pyfx.app module examination ===")
print(f"Module location: {pyfx.app.__file__}")
print(f"\nAttributes in pyfx.app:")
for name in dir(pyfx.app):
    if not name.startswith('_'):
        obj = getattr(pyfx.app, name)
        obj_type = type(obj).__name__
        print(f"  {name}: {obj_type}")
        if inspect.isclass(obj):
            print(f"    Methods: {[m for m in dir(obj) if not m.startswith('_')][:5]}...")

# Check if there's a main app class
if hasattr(pyfx.app, 'App'):
    print("\nFound App class")
elif hasattr(pyfx.app, 'PyfxApp'):
    print("\nFound PyfxApp class")
elif hasattr(pyfx.app, 'Application'):
    print("\nFound Application class")
