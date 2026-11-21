#!/usr/bin/env python3
"""#2767 fixed seven-file entry point; accepts no arguments, paths or profile."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from prod_front_sha_readonly import article_main


if __name__ == '__main__':
    raise SystemExit(article_main())
