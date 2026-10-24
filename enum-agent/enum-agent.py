#!/usr/bin/env python3
"""enum — network enumeration. Its programs and description are in
manifest.json beside this file; shared/recon_runner.py runs it. This file is
the same for every recon agent and is never edited by hand.
"""
import sys
from pathlib import Path

import recon_runner

if __name__ == "__main__":
    sys.exit(recon_runner.main(Path(__file__).resolve().parent / "manifest.json"))
