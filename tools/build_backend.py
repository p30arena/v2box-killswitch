#!/usr/bin/env python3
"""Build an isolated zipapp in .build; never install, run, or change networking."""
from pathlib import Path
import tempfile
import zipapp

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / ".build" / "org.v2boxkillswitch.backend"
OUTPUT.parent.mkdir(exist_ok=True)
with tempfile.TemporaryDirectory() as temporary:
    staging = Path(temporary)
    for source in sorted((ROOT / "src").glob("*.py")):
        (staging / source.name).write_bytes(source.read_bytes())
    (staging / "__main__.py").write_text("from runtime import main\nraise SystemExit(main())\n")
    zipapp.create_archive(staging, OUTPUT, interpreter="/usr/bin/python3 -I", compressed=True)
print("Built backend only:", OUTPUT)
print("Not installed or executed. Requires reviewed root deployment and configuration.")
