"""Modelos de datos compartidos por todos los módulos."""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple

# Tipos de entidad soportados como entrada o como entidades derivadas
ENTITY_TYPES = ("person", "name", "email", "username", "phone", "domain",
                "subdomain", "ip", "profile", "breach", "org")


@dataclass
class Finding:
    """Un hallazgo individual producido por un módulo."""
    source: str                      # nombre del módulo
    kind: str                        # p.ej. breach, profile, dns, whois, info
    title: str                       # resumen legible
    data: Dict = field(default_factory=dict)
    url: Optional[str] = None
    confidence: float = 1.0          # 0..1 (1 = dato verificado por la fuente)
    # Entidades derivadas (tipo, valor) -> alimentan el grafo y el pivoteo
    entities: List[Tuple[str, str]] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class ScanResult:
    """Resultado agregado de un escaneo completo."""
    target: str
    ttype: str
    started: str = ""
    findings: List[Finding] = field(default_factory=list)
    errors: List[Dict] = field(default_factory=list)     # fallos / módulos omitidos
    entities: Dict[str, Tuple[str, str]] = field(default_factory=dict)
    edges: List[Tuple[str, str, str, float]] = field(default_factory=list)

    @staticmethod
    def node_id(etype: str, value: str) -> str:
        return f"{etype}:{value}"

    def add_entity(self, etype: str, value: str) -> str:
        nid = self.node_id(etype, value)
        self.entities.setdefault(nid, (etype, value))
        return nid

    def to_dict(self) -> Dict:
        return {
            "target": self.target, "type": self.ttype, "started": self.started,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
            "entities": [{"id": k, "type": v[0], "value": v[1]} for k, v in self.entities.items()],
            "edges": [{"from": a, "to": b, "label": l, "confidence": c} for a, b, l, c in self.edges],
        }
