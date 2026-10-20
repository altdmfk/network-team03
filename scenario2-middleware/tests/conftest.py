import os
import sys
from pathlib import Path

# middleware root directory
middleware_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(middleware_root / "src"))
sys.path.insert(0, str(middleware_root / "simulators"))
sys.path.insert(0, str(middleware_root))

# Default AUTH_ENABLED to false for tests to preserve backward compatibility
# of existing test suites unless explicitly overridden by security tests.
if "AUTH_ENABLED" not in os.environ:
    os.environ["AUTH_ENABLED"] = "false"
