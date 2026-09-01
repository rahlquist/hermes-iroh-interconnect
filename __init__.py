"""hermes-iroh-interconnect — agent interconnect over Iroh QUIC.

Registers four client tools in the ``iroh`` toolset (outbound peer calls).
The long-lived Iroh endpoint lives in a supervised Rust sidecar binary
(``sidecar/``); this plugin never owns sockets. See docs/security.md for the
trust model and plan coverage.

Zero core edits — everything goes through the public PluginContext surface.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

__all__ = ["register"]


def register(ctx) -> None:
    """Plugin entry point — called by the Hermes plugin system."""
    try:
        from .peer_tools import register_tools

        register_tools(ctx)
        logger.info("hermes-iroh-interconnect: client tools registered")
    except Exception:
        logger.warning(
            "hermes-iroh-interconnect: failed to register client tools",
            exc_info=True,
        )
