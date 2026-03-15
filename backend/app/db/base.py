"""
Declarative base shared by all SQLAlchemy ORM models.

All models must import Base from this module, not re-declare it, so that
Alembic's autogenerate can discover them by importing this module once.
"""

from __future__ import annotations

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass
