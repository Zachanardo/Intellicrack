@echo off
echo Installing pysha3 fix for Windows...

REM Install pycryptodomex which has SHA3 support
pip install pycryptodomex

REM Create a fake pysha3 package
mkdir "%CD%\venv_windows\Lib\site-packages\pysha3"

REM Create __init__.py with compatibility layer
echo # pysha3 compatibility layer using pycryptodomex > "%CD%\venv_windows\Lib\site-packages\pysha3\__init__.py"
echo from Cryptodome.Hash import SHA3_224, SHA3_256, SHA3_384, SHA3_512 >> "%CD%\venv_windows\Lib\site-packages\pysha3\__init__.py"
echo from Cryptodome.Hash import SHAKE128, SHAKE256 >> "%CD%\venv_windows\Lib\site-packages\pysha3\__init__.py"
echo. >> "%CD%\venv_windows\Lib\site-packages\pysha3\__init__.py"
echo class _SHA3: >> "%CD%\venv_windows\Lib\site-packages\pysha3\__init__.py"
echo     def __init__(self, hashfn): >> "%CD%\venv_windows\Lib\site-packages\pysha3\__init__.py"
echo         self._h = hashfn >> "%CD%\venv_windows\Lib\site-packages\pysha3\__init__.py"
echo     def update(self, data): >> "%CD%\venv_windows\Lib\site-packages\pysha3\__init__.py"
echo         self._h.update(data) >> "%CD%\venv_windows\Lib\site-packages\pysha3\__init__.py"
echo     def digest(self): >> "%CD%\venv_windows\Lib\site-packages\pysha3\__init__.py"
echo         return self._h.digest() >> "%CD%\venv_windows\Lib\site-packages\pysha3\__init__.py"
echo     def hexdigest(self): >> "%CD%\venv_windows\Lib\site-packages\pysha3\__init__.py"
echo         return self._h.hexdigest() >> "%CD%\venv_windows\Lib\site-packages\pysha3\__init__.py"
echo. >> "%CD%\venv_windows\Lib\site-packages\pysha3\__init__.py"
echo def keccak_224(data=None): >> "%CD%\venv_windows\Lib\site-packages\pysha3\__init__.py"
echo     h = _SHA3(SHA3_224.new()) >> "%CD%\venv_windows\Lib\site-packages\pysha3\__init__.py"
echo     if data: h.update(data) >> "%CD%\venv_windows\Lib\site-packages\pysha3\__init__.py"
echo     return h >> "%CD%\venv_windows\Lib\site-packages\pysha3\__init__.py"
echo. >> "%CD%\venv_windows\Lib\site-packages\pysha3\__init__.py"
echo def keccak_256(data=None): >> "%CD%\venv_windows\Lib\site-packages\pysha3\__init__.py"
echo     h = _SHA3(SHA3_256.new()) >> "%CD%\venv_windows\Lib\site-packages\pysha3\__init__.py"
echo     if data: h.update(data) >> "%CD%\venv_windows\Lib\site-packages\pysha3\__init__.py"
echo     return h >> "%CD%\venv_windows\Lib\site-packages\pysha3\__init__.py"
echo. >> "%CD%\venv_windows\Lib\site-packages\pysha3\__init__.py"
echo def keccak_384(data=None): >> "%CD%\venv_windows\Lib\site-packages\pysha3\__init__.py"
echo     h = _SHA3(SHA3_384.new()) >> "%CD%\venv_windows\Lib\site-packages\pysha3\__init__.py"
echo     if data: h.update(data) >> "%CD%\venv_windows\Lib\site-packages\pysha3\__init__.py"
echo     return h >> "%CD%\venv_windows\Lib\site-packages\pysha3\__init__.py"
echo. >> "%CD%\venv_windows\Lib\site-packages\pysha3\__init__.py"
echo def keccak_512(data=None): >> "%CD%\venv_windows\Lib\site-packages\pysha3\__init__.py"
echo     h = _SHA3(SHA3_512.new()) >> "%CD%\venv_windows\Lib\site-packages\pysha3\__init__.py"
echo     if data: h.update(data) >> "%CD%\venv_windows\Lib\site-packages\pysha3\__init__.py"
echo     return h >> "%CD%\venv_windows\Lib\site-packages\pysha3\__init__.py"
echo. >> "%CD%\venv_windows\Lib\site-packages\pysha3\__init__.py"
echo def sha3_224(data=None): >> "%CD%\venv_windows\Lib\site-packages\pysha3\__init__.py"
echo     return keccak_224(data) >> "%CD%\venv_windows\Lib\site-packages\pysha3\__init__.py"
echo. >> "%CD%\venv_windows\Lib\site-packages\pysha3\__init__.py"
echo def sha3_256(data=None): >> "%CD%\venv_windows\Lib\site-packages\pysha3\__init__.py"
echo     return keccak_256(data) >> "%CD%\venv_windows\Lib\site-packages\pysha3\__init__.py"
echo. >> "%CD%\venv_windows\Lib\site-packages\pysha3\__init__.py"
echo def sha3_384(data=None): >> "%CD%\venv_windows\Lib\site-packages\pysha3\__init__.py"
echo     return keccak_384(data) >> "%CD%\venv_windows\Lib\site-packages\pysha3\__init__.py"
echo. >> "%CD%\venv_windows\Lib\site-packages\pysha3\__init__.py"
echo def sha3_512(data=None): >> "%CD%\venv_windows\Lib\site-packages\pysha3\__init__.py"
echo     return keccak_512(data) >> "%CD%\venv_windows\Lib\site-packages\pysha3\__init__.py"
echo. >> "%CD%\venv_windows\Lib\site-packages\pysha3\__init__.py"
echo sha3 = sha3_256 >> "%CD%\venv_windows\Lib\site-packages\pysha3\__init__.py"

REM Create a fake dist-info to make pip think pysha3 is installed
mkdir "%CD%\venv_windows\Lib\site-packages\pysha3-1.0.2.dist-info"
echo Metadata-Version: 2.1 > "%CD%\venv_windows\Lib\site-packages\pysha3-1.0.2.dist-info\METADATA"
echo Name: pysha3 >> "%CD%\venv_windows\Lib\site-packages\pysha3-1.0.2.dist-info\METADATA"
echo Version: 1.0.2 >> "%CD%\venv_windows\Lib\site-packages\pysha3-1.0.2.dist-info\METADATA"
echo pysha3 > "%CD%\venv_windows\Lib\site-packages\pysha3-1.0.2.dist-info\top_level.txt"
echo pysha3/__init__.py,, > "%CD%\venv_windows\Lib\site-packages\pysha3-1.0.2.dist-info\RECORD"
echo pysha3-1.0.2.dist-info/METADATA,, >> "%CD%\venv_windows\Lib\site-packages\pysha3-1.0.2.dist-info\RECORD"
echo pysha3-1.0.2.dist-info/top_level.txt,, >> "%CD%\venv_windows\Lib\site-packages\pysha3-1.0.2.dist-info\RECORD"
echo pysha3-1.0.2.dist-info/RECORD,, >> "%CD%\venv_windows\Lib\site-packages\pysha3-1.0.2.dist-info\RECORD"
echo Wheel-Version: 1.0 > "%CD%\venv_windows\Lib\site-packages\pysha3-1.0.2.dist-info\WHEEL"
echo Generator: fake-pysha3-installer >> "%CD%\venv_windows\Lib\site-packages\pysha3-1.0.2.dist-info\WHEEL"
echo Root-Is-Purelib: true >> "%CD%\venv_windows\Lib\site-packages\pysha3-1.0.2.dist-info\WHEEL"
echo Tag: py3-none-any >> "%CD%\venv_windows\Lib\site-packages\pysha3-1.0.2.dist-info\WHEEL"

echo.
echo pysha3 compatibility layer installed successfully!
echo Now you can install manticore:
echo pip install manticore --no-deps