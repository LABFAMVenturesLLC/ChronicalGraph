"""Explainable hypothesis and finding evaluation."""

from __future__ import annotations

from dataclasses import dataclass

from .graph import EvidenceGraph
from .models import Finding


@dataclass(frozen=True)
class Hypothesis:
    id: str
    title: str
    required_relations: tuple[str, ...]


BUILTIN_HYPOTHESES = (
    Hypothesis("browser-delivery", "An executable was downloaded and then run", ("DOWNLOAD_PRECEDED_EXECUTION",)),
    Hypothesis("usb-execution", "A file was executed following USB activity", ("USB_ACTIVITY_PRECEDED_EXECUTION",)),
    Hypothesis("execution-persistence", "Execution was followed by persistence", ("EXECUTION_PRECEDED_PERSISTENCE",)),
)


def evaluate(graph: EvidenceGraph) -> list[Finding]:
    findings: list[Finding] = []
    for hypothesis in BUILTIN_HYPOTHESES:
        matches = [relation for relation in graph.relations if relation.relation in hypothesis.required_relations]
        if not matches:
            continue
        event_ids = sorted({event_id for match in matches for event_id in match.original_event_ids})
        confidence = sum(match.confidence for match in matches) / len(matches)
        findings.append(Finding(
            rule_id=hypothesis.id, title=hypothesis.title,
            severity="high" if confidence >= 0.75 else "medium",
            confidence=round(confidence, 2),
            summary=f"Found {len(matches)} supporting evidence chain(s). This is an inference, not proof of intent.",
            event_ids=event_ids,
            supporting_facts=[match.explanation for match in matches[:10]],
        ))
    return findings

