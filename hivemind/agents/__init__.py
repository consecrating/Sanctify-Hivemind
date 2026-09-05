"""Specialist agents. Each plugs into the core Agent contract with a least-privilege
CapabilityGrant. Recon + Security ship in the vertical slice; SEO/Frontend/Content
follow the same pattern."""

from .recon import ReconAgent
from .security import SecurityAgent

__all__ = ["ReconAgent", "SecurityAgent"]
