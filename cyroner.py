#!/usr/bin/env python3

"""
This is a postmortem analyzer for Cyphal network exchange dumps.
It can read the network exchange dump file of any Cyphal transport (provided that there is a suitable loader for your
transport log format, e.g., tcpdump or candump) and reconstruct the high-level network events from it,
up to the full deserialized message contents. The tool supports an arbitrary number of redundant interfaces with
deduplication mimicking ordinary Cyphal nodes.

In order to know how to map port-IDs to data types, the script accepts a list of port-ID to data type mappings
in the standard format like Yakut: <port-ID>:<data-type-name>. The data type name is case-insensitive and the
version numbers are optional -- if not specified, the latest available version will be used.

The output is presented in a very simple JSON schema, one JSON object per line;
one object corresponds to one high-level network event: a transfer, an error, or a duplicate dropped transfer.

Usage example:
    ./cyroner.py candump.log 408:uavcan.file.Read 435:uavcan.node.ExecuteCommand > output.json
"""

from __future__ import annotations
import re
import io
from pathlib import Path
from typing import Iterable, Any, Type
import time
import json
import dataclasses
import logging
from decimal import Decimal
from pycyphal.dsdl import deserialize, is_service_type, to_builtin, get_fixed_port_id, get_model
from pycyphal.transport import MessageDataSpecifier, ServiceDataSpecifier, Timestamp
from pycyphal.transport import Capture, Trace, TransferTrace, ErrorTrace, Transport
from pycyphal.transport.can.media import FrameFormat, DataFrame
from pycyphal.transport.can import CANCapture
from pycyphal.transport.redundant import RedundantTransport, RedundantCapture, RedundantDuplicateTransferTrace
from dtype_loader import load_dtype


CaptureSource = Iterable[tuple[str, Capture]]
"""
Returns the next capture event along with the name of the network interface that captured it.
The format of the interface name can be arbitrary but it shall be unique.
"""


@dataclasses.dataclass(frozen=True)
class TraceEvent:
    transport: Type[Transport]
    """The transport kind of this event: CAN, UDP, etc. Useful for heterogeneously redundant networks."""

    source_iface: str
    """
    The name of the network interface that completed this trace event.
    It may or may not be the network interface that delivered this transfer;
    remember that a transfer may have been carried over multiple interfaces simultaneously in redundant networks.
    """

    trace: Trace
    """See pycyphal.transport.Trace."""


def trace(source: CaptureSource) -> Iterable[TraceEvent]:
    """
    Takes a source of network event captures, returns high-level network events.
    This does not require loading everything into memory so it can be quite efficient for very large datasets.
    """
    tracer = RedundantTransport.make_tracer()
    iface2id: dict[tuple[type, str], int] = {}
    for iface, cap in source:
        assert isinstance(cap, Capture) and isinstance(iface, str)
        tracer_key = (cap.get_transport_type(), iface)
        iface_id = iface2id.setdefault(tracer_key, len(iface2id))
        # TODO: PyCyphal needs to make the transfer-ID modulo a static property in the Transport interface...
        tid_modulo = getattr(cap.get_transport_type(), "TRANSFER_ID_MODULO")
        rc = RedundantCapture(
            cap.timestamp,
            inferior=cap,
            iface_id=iface_id,
            transfer_id_modulo=tid_modulo,
        )
        if tr := tracer.update(rc):
            yield TraceEvent(transport=cap.get_transport_type(), source_iface=iface, trace=tr)


def merge(*capture_sources: CaptureSource) -> CaptureSource:
    """
    Given a multitude of capture sources, returns a single capture source that merges them all.
    This is done by sorting the captures produced by each capture source by timestamp.
    This may require a lot of memory.
    """
    if len(capture_sources) == 0:
        return iter(())
    if len(capture_sources) == 1:
        return capture_sources[0]
    # The current implementation is rather silly and has a huge room for improvement such that it doesn't require
    # loading everything into memory at once. Well-known algorithms exist for that, one just needs to be implemented.
    it = iter(
        sorted(
            ((iface, cap) for cs in capture_sources for iface, cap in cs),
            key=lambda x: x[1].timestamp.system_ns,
        )
    )
    return lambda: next(it)


class Deserializer:
    """
    Takes two mappings (int) -> type that map a port-ID to the DSDL type for that port-ID.
    The first mapping is for subjects, the second one is for services.
    The deserialize method returns the deserialized object if there is a known mapping and the trace is of a suitable
    kind; otherwise returns nothing.
    """

    def __init__(
        self,
        subject_types: dict[int, type],
        service_types: dict[int, type],
    ) -> None:
        self._subjects = subject_types
        self._services = service_types

    def deserialize(self, trace: Trace) -> Any | None:
        if not isinstance(trace, TransferTrace):
            return None
        ds = trace.transfer.metadata.session_specifier.data_specifier
        if isinstance(ds, MessageDataSpecifier):
            ty = self._subjects.get(ds.subject_id, None)
        elif isinstance(ds, ServiceDataSpecifier):
            ty = self._services.get(ds.service_id, None)
            if ty is not None:
                ty = {
                    ServiceDataSpecifier.Role.REQUEST: ty.Request,
                    ServiceDataSpecifier.Role.RESPONSE: ty.Response,
                }[ds.role]
        else:
            assert False, "Internal error"
        if ty is None:
            return None
        return deserialize(ty, trace.transfer.fragmented_payload)


class CandumpCaptureLoader:
    @dataclasses.dataclass(frozen=True)
    class Record:
        """This comes from pycyphal.transport.can.media.candump."""

        _RE_REC_REMOTE = re.compile(r"(?a)^\s*\((\d+\.\d+)\)\s+([\w-]+)\s+([\da-fA-F]+)#R")
        _RE_REC_DATA = re.compile(r"(?a)^\s*\((\d+\.\d+)\)\s+([\w-]+)\s+([\da-fA-F]+)#(#\d)?([\da-fA-F]*)")

        @staticmethod
        def parse(line: str) -> None | CandumpCaptureLoader.Record:
            try:
                if CandumpCaptureLoader.Record._RE_REC_REMOTE.match(line):
                    return CandumpCaptureLoader.UnsupportedRecord()
                match = CandumpCaptureLoader.Record._RE_REC_DATA.match(line)
                if not match:
                    return None
                s_ts, iface_name, s_canid, s_flags, s_data = match.groups()
                if s_flags is None:
                    s_flags = "#0"
                if s_data is None:
                    s_data = ""
                return CandumpCaptureLoader.DataFrameRecord(
                    ts=Timestamp(
                        system_ns=int(Decimal(s_ts) * Decimal("1e9")),
                        monotonic_ns=time.monotonic_ns(),
                    ),
                    iface_name=iface_name,
                    fmt=FrameFormat.EXTENDED if len(s_canid) > 3 else FrameFormat.BASE,
                    can_id=int(s_canid, 16),
                    can_payload=bytes.fromhex(s_data),
                    can_flags=int(s_flags[1:], 16),  # skip over #
                )
            except ValueError:
                return None

    @dataclasses.dataclass(frozen=True)
    class UnsupportedRecord(Record):
        pass

    @dataclasses.dataclass(frozen=True)
    class DataFrameRecord(Record):
        ts: Timestamp
        iface_name: str
        fmt: FrameFormat
        can_id: int
        can_payload: bytes
        can_flags: int

        def __str__(self) -> str:
            if self.fmt == FrameFormat.EXTENDED:
                s_id = f"{self.can_id:08x}"
            elif self.fmt == FrameFormat.BASE:
                s_id = f"{self.can_id:03x}"
            else:
                assert False
            return f"{self.ts} {self.iface_name!r} {s_id}#{self.can_payload.hex()}"

    def __init__(self, file: io.TextIOBase | str | Path):
        if isinstance(file, (str, Path)):
            self._file = open(file, "r")
        else:
            self._file = file
        self._it = iter(enumerate(self._file))

    def __iter__(self):
        return self

    def __next__(self) -> tuple[str, CANCapture]:
        """Returns CAN capture events along with the name of the CAN iface that captured them."""
        while True:
            no, line = next(self._it)
            rec = self.Record.parse(line)
            if rec is None:
                _logger.error("Failed to parse line %d: %r", no + 1, line)
            elif isinstance(rec, self.UnsupportedRecord):
                _logger.error("Unsupported record at line %d: %r", no + 1, line)
            elif isinstance(rec, self.DataFrameRecord):
                cap = CANCapture(
                    timestamp=rec.ts,
                    frame=DataFrame(
                        format=rec.fmt,
                        identifier=rec.can_id,
                        data=rec.can_payload,
                    ),
                    own=False,
                )
                return rec.iface_name, cap
            else:
                assert False, "Internal error"


def main() -> None:
    import sys

    try:
        import uavcan.node as uavcan_node
    except ImportError:
        uavcan_node = None

    logging.basicConfig(
        stream=sys.stderr,
        format="%(asctime)s %(levelname)-5.5s %(name)s: %(message)s\n",
        level=logging.INFO,
    )
    port_spec_regexp = re.compile(r"^(\d+):(.+\..+)$")
    subject_types = {}
    service_types = {}
    capture_sources = []
    if uavcan_node is not None:
        subject_types[get_fixed_port_id(uavcan_node.Heartbeat_1)] = uavcan_node.Heartbeat_1
        service_types[get_fixed_port_id(uavcan_node.GetInfo_1)] = uavcan_node.GetInfo_1
    for a in sys.argv[1:]:
        if a in ("-v", "--verbose"):
            logging.root.setLevel(logging.DEBUG)
        elif m := port_spec_regexp.match(a):
            port_id, dtype_name = m.groups()
            dtype = load_dtype(dtype_name, allow_minor_version_mismatch=True)
            if dtype is None:
                raise ValueError(f"Failed to load data type {dtype_name!r}")
            if is_service_type(dtype):
                service_types[int(port_id)] = dtype
            else:
                subject_types[int(port_id)] = dtype
        else:
            # TODO: add support for other transports and data sources here (e.g., Wireshark dumps).
            capture_sources.append(CandumpCaptureLoader(a))
    loader = merge(*capture_sources)
    des = Deserializer(subject_types, service_types)
    for event in trace(loader):
        tr = event.trace
        obj = des.deserialize(event.trace)
        meta = {
            "ts_system": float(tr.timestamp.system),
            "ts_monotonic": float(tr.timestamp.monotonic),
            "transport": {
                "kind": event.transport.__name__.lower().replace("transport", ""),
                "source_iface": event.source_iface,
            },
        }
        if isinstance(tr, TransferTrace):
            payload = b"".join(tr.transfer.fragmented_payload)
            ds = tr.transfer.metadata.session_specifier.data_specifier
            dsdl = get_model(obj) if obj is not None else None
            meta["priority"] = tr.transfer.metadata.priority.name.lower()
            meta["transfer_id"] = tr.transfer.metadata.transfer_id
            meta["source_node_id"] = tr.transfer.metadata.session_specifier.source_node_id
            meta["destination_node_id"] = tr.transfer.metadata.session_specifier.destination_node_id
            if isinstance(ds, MessageDataSpecifier):
                meta["subject_id"] = ds.subject_id
            elif isinstance(ds, ServiceDataSpecifier):
                meta["service_id"] = ds.service_id
                meta["role"] = ds.role.name.lower()
            else:
                assert False, "Internal error"
            meta["dtype"] = f"{dsdl.full_name}.{dsdl.version[0]}.{dsdl.version[1]}" if dsdl is not None else None
            meta["payload_hex"] = payload.hex()
        elif isinstance(tr, ErrorTrace):
            meta["error"] = str(tr)
        elif isinstance(tr, RedundantDuplicateTransferTrace):
            meta["duplicate"] = {}
        else:
            assert False, f"Unsupported trace: {tr}"
        model = {"_meta_": meta}
        model.update(to_builtin(obj) if obj is not None else {})
        json.dump(model, sys.stdout)
        sys.stdout.write("\n")


_logger = logging.getLogger(__name__)


if __name__ == "__main__":
    main()
