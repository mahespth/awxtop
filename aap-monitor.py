#!/usr/bin/env python3
"""
Wrapper entry point for the awxtop UI.

The main implementation lives in the awxtop package so it can be installed and
imported. This file remains so the UI can still be invoked directly via
`python aap-monitor.py` in a checkout.
"""

from awxtop.awxtop import main


if __name__ == "__main__":
    main()
