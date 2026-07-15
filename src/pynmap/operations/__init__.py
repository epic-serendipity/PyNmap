"""Scan operations.

Every operation is an independent module that declares its metadata
(id, display name, description, dependencies, expected outputs, whether it
becomes stale, whether it must rerun during an update) and knows how to build
its command, validate completion, and run.

The :data:`REGISTRY` maps operation ids to instances and is the single source
of truth used by the engine and UI.
"""

from __future__ import annotations

from .base import Operation, ScanContext, OperationRunResult, resolve_dependencies
from .discovery import DiscoveryOperation
from .tcp import TcpTop1000Operation, TcpFullOperation, ServiceDetectionOperation
from .udp import UdpTop50Operation
from .os_detection import OsDetectionOperation
from .traceroute import TracerouteOperation
from .reports import InventoryOperation, HtmlReportOperation
from .mapping import NetworkMapOperation


def _build_registry() -> dict[str, Operation]:
    ops: list[Operation] = [
        DiscoveryOperation(),
        TcpTop1000Operation(),
        ServiceDetectionOperation(),
        TcpFullOperation(),
        UdpTop50Operation(),
        OsDetectionOperation(),
        TracerouteOperation(),
        InventoryOperation(),
        HtmlReportOperation(),
        NetworkMapOperation(),
    ]
    return {op.id: op for op in ops}


REGISTRY: dict[str, Operation] = _build_registry()


def get_operation(op_id: str) -> Operation:
    return REGISTRY[op_id]


def all_operations() -> list[Operation]:
    return list(REGISTRY.values())


__all__ = [
    "Operation",
    "ScanContext",
    "OperationRunResult",
    "resolve_dependencies",
    "REGISTRY",
    "get_operation",
    "all_operations",
]
