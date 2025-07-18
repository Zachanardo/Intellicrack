#!/usr/bin/env python3
"""Launch Intellicrack with unbuffered output."""

import os
import sys

# Unbuffered output
os.environ['PYTHONUNBUFFERED'] = '1'

# Intel Arc B580 compatibility settings
os.environ['DISABLE_TENSORFLOW'] = '1'
os.environ['QT_OPENGL'] = 'software'
os.environ['QT_ANGLE_PLATFORM'] = 'warp'
os.environ['QT_D3D_ADAPTER_INDEX'] = '1'
os.environ['QT_QUICK_BACKEND'] = 'software'
os.environ['QT_QPA_PLATFORM'] = 'windows'

# Flush print immediately
def print_flush(*args, **kwargs):
    print(*args, **kwargs)
    sys.stdout.flush()

# Monkey patch print
import builtins
builtins.print = print_flush

# Import and run
from intellicrack.main import intellicrack_main

if __name__ == "__main__":
    sys.exit(intellicrack_main())