"""Run every Warden test.  Usage:  python tests/run_tests.py"""

import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TESTS = ["test_policy.py", "test_scanner.py", "test_intent.py", "test_lab.py", "test_gateway.py"]

failed = []
for name in TESTS:
    print(f"\n===== {name} =====", flush=True)
    if subprocess.run([sys.executable, str(HERE / name)], stderr=subprocess.DEVNULL).returncode != 0:
        failed.append(name)

print("\n" + ("ALL TEST FILES PASSED" if not failed else f"FAILED: {', '.join(failed)}"))
sys.exit(1 if failed else 0)
