"""KAVACH: a defensive, 5-agent AI CVE research pipeline.

The pipeline analyzes a CVE and produces an evidence-backed report with
remediation guidance. It is DEFENSIVE ONLY: it never generates weaponized
exploit code and never attacks live targets. All dynamic checks run inside a
strongly isolated sandbox using benign proof-of-concept markers.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
