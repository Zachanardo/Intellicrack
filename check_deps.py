import subprocess
import re

# Get installed packages
result = subprocess.run(['C:\\Intellicrack\\mamba_env\\python.exe', '-m', 'pip', 'list', '--format=freeze'], 
                       capture_output=True, text=True)
installed = {}
for line in result.stdout.strip().split('\n'):
    if '==' in line:
        name, version = line.split('==')
        installed[name.lower().replace('_', '-').replace('.', '-')] = version

# Read pyproject.toml dependencies
deps = []
with open('C:\\Intellicrack\\setup\\pyproject.toml', 'r') as f:
    in_deps = False
    for line in f:
        if line.strip() == 'dependencies = [':
            in_deps = True
            continue
        if in_deps and line.strip() == ']':
            break
        if in_deps and '==' in line and not line.strip().startswith('#'):
            # Extract package name from quoted string
            match = re.search(r'"([^"]+)"', line)
            if match:
                dep = match.group(1)
                if '@' not in dep and ';' not in dep:
                    pkg_name = dep.split('==')[0].split('>=')[0].split('<=')[0].split('!=')[0].split('>')[0].split('<')[0]
                    deps.append(pkg_name.lower().replace('_', '-').replace('.', '-'))

# Check missing
missing = []
for dep in deps:
    # Handle special cases
    if dep == 'tensorflow-cpu':
        dep = 'tensorflow'
    if dep == 'psycopg2-binary':
        dep = 'psycopg2'
    if dep == 'keystone-engine':
        dep = 'keystone'
    
    if dep not in installed:
        missing.append(dep)

print("Missing dependencies:")
for dep in missing:
    print(f"  - {dep}")