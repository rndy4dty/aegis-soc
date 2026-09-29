"""Entry point untuk `python -m worker`."""

import sys

from worker.main import main

if __name__ == "__main__":
    sys.exit(main())
