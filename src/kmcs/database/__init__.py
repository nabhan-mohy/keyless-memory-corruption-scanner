"""Persistence layer for KMCS.

Only :mod:`kmcs.database` talks to SQLite.  Higher layers use domain models from
:mod:`kmcs.core.models` and never see SQLAlchemy objects unless they explicitly
ask for them.
"""
