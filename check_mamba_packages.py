import importlib

# Packages that should be installed via mamba according to environment.yml
mamba_packages = {
    "numpy": "numpy",
    "seaborn": "seaborn",
    "tensorflow": "tensorflow",
    "onnxruntime": "onnxruntime",
    "cryptography": "cryptography",
    "psycopg2": "psycopg2",
    "pillow": "PIL",
    "cairocffi": "cairocffi",
    "graphviz": "graphviz",
    "lief": "lief",
    "joblib": "joblib",
    "dask": "dask",
    "ray": "ray",
    "cffi": "cffi",
    "wheel": "wheel",
    "setuptools": "setuptools",
    "networkx": "networkx",
}

print("Checking mamba-installed packages from environment.yml:\n")
print("-" * 50)

working = []
broken = []

for package_name, import_name in mamba_packages.items():
    try:
        mod = importlib.import_module(import_name)
        version = getattr(mod, "__version__", "unknown")
        working.append(f"{package_name} ({import_name}): v{version}")
        print(f"✓ {package_name:20} OK (v{version})")
    except ImportError as e:
        broken.append(f"{package_name} ({import_name})")
        print(f"✗ {package_name:20} FAILED: {str(e)[:50]}...")
    except Exception as e:
        broken.append(f"{package_name} ({import_name})")
        print(f"✗ {package_name:20} ERROR: {str(e)[:50]}...")

print("\n" + "=" * 50)
print("SUMMARY:")
print(f"Working: {len(working)}/{len(mamba_packages)} packages")
print(f"Broken:  {len(broken)}/{len(mamba_packages)} packages")

if broken:
    print("\nBroken packages:")
    for pkg in broken:
        print(f"  - {pkg}")

print("\nConclusion:")
if len(working) < len(mamba_packages) // 2:
    print("❌ Most mamba packages are NOT working properly!")
    print("   The mamba environment appears to be corrupted.")
else:
    print("✓ Most mamba packages are working.")
