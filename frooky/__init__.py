"""Frooky package."""

try:
    from ._version import version as __version__
except ImportError:
    __version__ = "0+unknown" # Using a PEP 440 compliant local version to make it obvious this is not a real release.

__all__ = ["__version__"]
