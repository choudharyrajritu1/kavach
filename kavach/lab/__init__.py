"""Self-contained, deliberately-vulnerable lab fixtures for KAVACH.

These services are INTENTIONALLY INSECURE and exist only to validate that the
Exploiter agent can generate a working PoC and capture a planted flag. They bind
to loopback only and must never be exposed to a network.
"""

from .vulnerable_app import LabServer, VulnClass

__all__ = ["LabServer", "VulnClass"]
