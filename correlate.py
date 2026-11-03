"""Correlación: añade relaciones entre entidades (marcadas como heurísticas)."""
from __future__ import annotations
from collections import defaultdict
from urllib.parse import urlparse

from .models import ScanResult


def correlate(res: ScanResult) -> None:
    ents = res.entities
    # 1) email <-> username cuando la parte local coincide (confianza baja)
    usernames = {v.lower(): k for k, (t, v) in ents.items() if t == "username"}
    for k, (t, v) in list(ents.items()):
        if t == "email":
            local = v.split("@")[0].lower()
            if local in usernames:
                res.edges.append((k, usernames[local], "heurística: misma parte local", 0.4))
            # 2) email -> dominio del correo
            dom = v.split("@")[1].lower()
            if ("domain", dom) in ents.values():
                res.edges.append((k, f"domain:{dom}", "email del dominio", 0.9))

    # 3) perfiles que comparten el mismo identificador en la URL -> misma cuenta probable
    by_handle = defaultdict(list)
    for k, (t, v) in ents.items():
        if t == "profile":
            handle = urlparse(v).path.strip("/").split("/")[-1].lstrip("@~").lower()
            if handle:
                by_handle[handle].append(k)
    for handle, nodes in by_handle.items():
        if len(nodes) > 1:
            hub = res.add_entity("username", handle)
            for n in nodes:
                res.edges.append((hub, n, "mismo handle en varias plataformas", 0.6))


def profile_summary(res: ScanResult) -> dict:
    """Resumen agrupado por tipo de entidad (para el reporte)."""
    out = defaultdict(list)
    for _, (t, v) in res.entities.items():
        out[t].append(v)
    return {t: sorted(set(vs)) for t, vs in out.items()}
