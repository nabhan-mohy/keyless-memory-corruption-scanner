"""Integration tests that exercise the complete KMCS pipeline.

These tests are marked ``integration`` and skip cleanly when the external
tools they require (a C compiler, AFL++) are not installed.  They are the
tests that prove KMCS works end to end, not just that its individual modules
are self-consistent.

Run them with::

    pytest tests/integration -m integration -q

Run them in CI with the marker deselected if AFL++ is not available:

    pytest tests -m "not integration"
"""
