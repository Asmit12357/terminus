"""Terminus: vulnerability intelligence and remediation recommendations."""

from importlib import metadata

try:
    __version__ = metadata.version("terminus")
except metadata.PackageNotFoundError:  # running from an uninstalled source tree
    __version__ = "0.0.0+unknown"
