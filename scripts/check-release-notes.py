"""GitHub supplies the release title; the notes file contains the body only."""
from pathlib import Path
import re
import sys


def validate(text):
    if not text.strip():
        raise ValueError("release notes must not be empty")
    if re.search(r"(?m)^ {0,3}#(?:\s|$)|^ {0,3}=+\s*$", text):
        raise ValueError("remove the level-one title from release notes; GitHub renders the release title separately")


if __name__ == "__main__":
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1] / "RELEASE_NOTES.md"
    validate(path.read_text())
    print(f"Release body validated: {path}")
