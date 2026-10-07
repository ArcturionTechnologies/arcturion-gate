"""ArcturionGate: a local, encrypted credential store for AI agents.

Agents hold references ("valet tickets"); values stay in the store and are
released only to a process or browser field, never into model context.
"""

from .broker import Broker
from .errors import GateError
from .store import Gate, GateStore

__all__ = ["Broker", "Gate", "GateStore", "GateError"]
__version__ = "0.1.0"
