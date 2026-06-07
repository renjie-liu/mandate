"""Data-sensitivity ordering.

A total order over sensitivity labels, used for the ``data.max_sensitivity`` ceiling
in the capability subset rule (contract §5): a grant may only touch data at or below
the sensitivity the request asked for.
"""

from __future__ import annotations

from ..errors import MandateError

# Least → most sensitive. Index is the level.
SENSITIVITY_ORDER: tuple[str, ...] = (
    "public",
    "internal",
    "confidential",
    "restricted",
    "secret",
)


def sensitivity_level(label: str) -> int:
    """Return the integer level of a sensitivity *label* (higher = more sensitive)."""
    try:
        return SENSITIVITY_ORDER.index(label)
    except ValueError as exc:
        raise MandateError(
            f"unknown sensitivity label {label!r}; "
            f"expected one of {', '.join(SENSITIVITY_ORDER)}"
        ) from exc


def sensitivity_at_most(label: str, ceiling: str) -> bool:
    """True if *label* is no more sensitive than *ceiling* (i.e. ``label <= ceiling``)."""
    return sensitivity_level(label) <= sensitivity_level(ceiling)
