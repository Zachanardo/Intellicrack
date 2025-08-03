@echo off
echo Installing Manticore with pysha3 workaround...

REM Step 1: Install pycryptodomex
pip install pycryptodomex

REM Step 2: Install all other manticore dependencies first
pip install pyyaml protobuf prettytable ply rlp intervaltree wasm pyevmasm>=0.2.3 z3-solver crytic-compile==0.2.2

REM Step 3: Create fake pysha3 by directly writing Python files
python -c "import os, site; p=os.path.join(site.getsitepackages()[0], 'pysha3'); os.makedirs(p, exist_ok=True)"

REM Step 4: Write the compatibility module
python -c "import os, site; open(os.path.join(site.getsitepackages()[0], 'pysha3', '__init__.py'), 'w').write('from Cryptodome.Hash import SHA3_224, SHA3_256, SHA3_384, SHA3_512\nclass H:\n def __init__(self,h): self._h=h\n def update(self,d): self._h.update(d); return self\n def digest(self): return self._h.digest()\n def hexdigest(self): return self._h.hexdigest()\ndef keccak_224(d=None): h=H(SHA3_224.new()); return h.update(d) if d else h\ndef keccak_256(d=None): h=H(SHA3_256.new()); return h.update(d) if d else h\ndef keccak_384(d=None): h=H(SHA3_384.new()); return h.update(d) if d else h\ndef keccak_512(d=None): h=H(SHA3_512.new()); return h.update(d) if d else h\nsha3_224=keccak_224\nsha3_256=keccak_256\nsha3_384=keccak_384\nsha3_512=keccak_512\nsha3=sha3_256\n')"

REM Step 5: Install manticore without dependencies
pip install manticore --no-deps

echo.
echo Done! Manticore should now be installed.
