"""Launcher: works both as a package import and as a plain script.

Clients launch `python run.py`; the process must not assume it is installed.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.server import main

if __name__ == "__main__":
    main()
