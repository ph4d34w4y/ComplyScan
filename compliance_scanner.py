#!/usr/bin/env python3
"""Compatibility entry point for the former script name."""
from complyscan import *  # noqa: F401,F403
from complyscan import main

if __name__ == "__main__":
    raise SystemExit(main())
