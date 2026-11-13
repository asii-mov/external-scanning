"""Test suite. Tests run with no network.

The enrich stage downloads public feeds (CISA KEV, EPSS, CDN ranges) and is
on by default, so any test that drives a whole run would reach for the
internet. This switches it off for the suite; tests/test_enrich.py turns it
back on against local files.
"""

import os

os.environ.setdefault("EXTSCAN_OFFLINE", "1")
