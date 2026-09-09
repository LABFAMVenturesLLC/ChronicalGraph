"""Evidence graph construction and deterministic correlation."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta
from urllib.parse import urlparse

from .models import Entity, EvidenceEvent, Relation, stable_id


ENTITY_FIELDS = {
    "host": "hostname", "user": "username", "file": "path",
    "url": "url", "hash": "sha256_hash", "process": "process_id",
}


@dataclass
class EvidenceGraph:
    events: dict[str, EvidenceEvent] = field(default_factory=dict)
    entities: dict[str, Entity] = field(default_factory=dict)
    relations: list[Relation] = field(default_factory=list)

    def add_relation(self, source_id: str, target_id: str, relation: str,
                     event: EvidenceEvent, confidence: float, explanation: str,
                     inferred: bool = False, event_ids: list[str] | None = None) -> None:
        ids = event_ids or [event.id]
        relation_id = stable_id("rel", source_id, target_id, relation, *ids)
        self.relations.append(Relation(
            id=relation_id, source_id=source_id, target_id=target_id, relation=relation,
            timestamp=event.timestamp, confidence=round(confidence, 2),
            artifact_source=event.source, parser=event.parser,
            original_event_ids=ids, explanation=explanation, inferred=inferred,
        ))


def _entity(graph: EvidenceGraph, kind: str, value: str) -> Entity:
    entity_id = stable_id(kind, value)
    if entity_id not in graph.entities:
        graph.entities[entity_id] = Entity(entity_id, kind, value)
    return graph.entities[entity_id]


def _classify_action(event: EvidenceEvent) -> str:
    text = f"{event.event_type} {event.source} {event.message}".lower()
    if any(token in text for token in ("download", "browser history", "browser_download")):
        return "download"
    if any(token in text for token in ("process start", "execution", "prefetch", "amcache", "userassist", "program run")):
        return "execution"
    if any(token in text for token in ("service install", "scheduled task", "run key", "persistence", "autorun")):
        return "persistence"
    if any(token in text for token in ("usb", "removable", "device connected")):
        return "usb"
    if any(token in text for token in ("logon", "login", "authentication")):
        return "logon"
    if any(token in text for token in ("network", "connection", "dns")):
        return "network"
    return "observed"


def build_graph(events: list[EvidenceEvent], correlation_minutes: int = 30) -> EvidenceGraph:
    graph = EvidenceGraph(events={event.id: event for event in events})
    by_file: dict[str, list[tuple[EvidenceEvent, str]]] = defaultdict(list)

    for event in events:
        event_entity = _entity(graph, "event", event.id)
        action = _classify_action(event)
        for kind, field_name in ENTITY_FIELDS.items():
            value = getattr(event, field_name)
            if not value:
                continue
            entity = _entity(graph, kind, value)
            graph.add_relation(event_entity.id, entity.id, f"EVENT_REFERENCES_{kind.upper()}", event,
                               1.0, f"The {field_name} is present in the source event.")
            if kind == "file":
                by_file[value.lower()].append((event, action))
        if event.url:
            domain = urlparse(event.url).hostname
            if domain:
                domain_entity = _entity(graph, "domain", domain)
                url_entity = _entity(graph, "url", event.url)
                graph.add_relation(url_entity.id, domain_entity.id, "URL_USES_DOMAIN", event, 1.0,
                                   "Domain was parsed directly from the URL.")

    window = timedelta(minutes=correlation_minutes)
    for path, observations in by_file.items():
        ordered = sorted(observations, key=lambda item: (item[0].timestamp is None, item[0].timestamp))
        for index, (left, left_action) in enumerate(ordered):
            if left.timestamp is None:
                continue
            for right, right_action in ordered[index + 1:]:
                if right.timestamp is None or right.timestamp - left.timestamp > window:
                    break
                relation = None
                if left_action == "download" and right_action == "execution":
                    relation = "DOWNLOAD_PRECEDED_EXECUTION"
                elif left_action == "usb" and right_action == "execution":
                    relation = "USB_ACTIVITY_PRECEDED_EXECUTION"
                elif left_action == "execution" and right_action == "persistence":
                    relation = "EXECUTION_PRECEDED_PERSISTENCE"
                if relation:
                    confidence = min(left.timestamp_confidence, right.timestamp_confidence) * 0.9
                    graph.add_relation(left.id, right.id, relation, right, confidence,
                                       f"Events reference the same path ({path}) within {correlation_minutes} minutes.",
                                       inferred=True, event_ids=[left.id, right.id])
    return graph

