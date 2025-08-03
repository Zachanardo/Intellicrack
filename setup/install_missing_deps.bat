@echo off
echo Installing packages not available in conda-forge using uv pip...

REM Activate the mamba environment first
call mamba activate C:\Intellicrack\mamba_env

REM Install the missing packages using uv pip
uv pip install ^
    frida==17.2.4 ^
    opencv-python ^
    pdfkit==1.0.0 ^
    ray==2.47.1 ^
    torch==2.7.1 ^
    unicorn==2.0.1.post1 ^
    yara-python==4.5.4

echo.
echo Installation complete!
