#!/usr/bin/env python3
"""Entry point for PyInstaller one-file daemon exe. Run the Unveil daemon (no CLI install needed)."""
from unveil.daemon import main

if __name__ == "__main__":
    main()
