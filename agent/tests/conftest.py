"""
CleanShift Test Configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Shared pytest fixtures and configuration for the test suite.
"""

import sys
from pathlib import Path

import pytest

# Ensure the project root is in the Python path for imports
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
