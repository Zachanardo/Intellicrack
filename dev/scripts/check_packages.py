import subprocess
import sys

# Packages to check
packages = ['flask', 'starlette', 'ruamel-yaml', 'typing-extensions', 'click', 'capstone']

print("Python executable:", sys.executable)
print("Python path:", sys.path[0])
print("\nChecking package versions:")

for package in packages:
    try:
        result = subprocess.run([sys.executable, '-m', 'pip', 'show', package], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            name = version = location = None
            for line in lines:
                if line.startswith('Name:'):
                    name = line.split(':', 1)[1].strip()
                elif line.startswith('Version:'):
                    version = line.split(':', 1)[1].strip()
                elif line.startswith('Location:'):
                    location = line.split(':', 1)[1].strip()
            print(f"\n{name}: {version}")
            print(f"  Location: {location}")
    except Exception as e:
        print(f"Error checking {package}: {e}")