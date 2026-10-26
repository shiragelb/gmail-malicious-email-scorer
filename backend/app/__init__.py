"""Malicious Email Scorer backend."""

import asyncio
import sys

# Python 3.10.0 on Windows can hang while closing the default proactor loop
# after a worker thread has run. The selector loop shuts down cleanly.
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
