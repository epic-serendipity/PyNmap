"""NetMapper: an interactive Nmap orchestration, inventory, and reporting tool."""

__all__ = ["__version__", "TOOL_NAME", "SCHEMA_VERSION"]

__version__ = "0.1.0"

#: Identifier written into every manifest so directories can be recognised.
TOOL_NAME = "netmapper"

#: Manifest / config schema version. Bump when the on-disk format changes.
SCHEMA_VERSION = 1
