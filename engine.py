"""Motor: detecta el tipo de entrada, ejecuta módulos en paralelo y pivotea."""
from __future__ import annotations
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Iterable, Optional

from .base import REGISTRY, Context
from .correlate import correlate
from .models import ScanResult

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
PHONE_RE = re.compile(r"^\+?[\d\s().-]{7,20}$")
IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,}$")

# Tipos de entidad derivada que se pueden reutilizar como nueva entrada (--depth)
PIVOT_TYPES = {"email", "username", "domain", "ip"}


def detect_type(value: str) -> str:
    """Adivina el tipo de dato. Se puede forzar con --type."""
    v = value.strip()
    if EMAIL_RE.match(v):
        return "email"
    if IP_RE.match(v):
        return "ip"
    if PHONE_RE.match(v) and sum(c.isdigit() for c in v) >= 7:
        return "phone"
    if DOMAIN_RE.match(v):
        return "domain"
    if " " in v:
        return "name"
    return "username"


class Engine:
    def __init__(self, ctx: Optional[Context] = None, modules: Optional[Iterable[str]] = None,
                 depth: int = 0, max_pivots: int = 10, workers: int = 4, log=None):
        self.ctx = ctx or Context()
        names = list(modules) if modules else list(REGISTRY)
        unknown = [n for n in names if n not in REGISTRY]
        if unknown:
            raise ValueError(f"Módulos desconocidos: {unknown}")
        self.modules = [REGISTRY[n]() for n in names]
        self.depth, self.max_pivots, self.workers = depth, max_pivots, workers
        self.log = log or (lambda msg: None)      # callback de progreso (la usa el menú)

    def _run_one(self, mod, value, ttype):
        """Ejecuta un módulo aislando sus errores (un fallo no tumba el escaneo)."""
        ok, why = mod.available(self.ctx)
        if not ok:
            return mod.name, [], {"module": mod.name, "target": value, "error": f"omitido: {why}"}
        try:
            return mod.name, mod.run(value, ttype, self.ctx), None
        except Exception as e:                                   # noqa: BLE001
            msg = f"{type(e).__name__}: {e}"
            # Las URL de error pueden incluir ?key=...: nunca dejar secretos en el reporte
            for k, val in self.ctx.env.items():
                if k.endswith(("_KEY", "_TOKEN")) and val and len(val) > 4:
                    msg = msg.replace(val, "***")
            return mod.name, [], {"module": mod.name, "target": value, "error": msg}

    def scan(self, target: str, ttype: Optional[str] = None) -> ScanResult:
        ttype = ttype or detect_type(target)
        res = ScanResult(target, ttype, started=datetime.now(timezone.utc).isoformat(timespec="seconds"))
        res.add_entity(ttype, target)
        queue = [(ttype, target, 0)]
        seen = {(ttype, target)}
        pivots = 0
        while queue:
            t, v, d = queue.pop(0)
            src_id = ScanResult.node_id(t, v)
            mods = [m for m in self.modules if t in m.accepts]
            with ThreadPoolExecutor(self.workers) as ex:
                futs = [ex.submit(self._run_one, m, v, t) for m in mods]
                for f in as_completed(futs):
                    mname, findings, err = f.result()
                    if err:
                        res.errors.append(err)
                        self.log(f"[!] {mname}: {err['error']}")
                    else:
                        self.log(f"[✓] {mname}: {len(findings)} hallazgo(s)")
                    for fd in findings:
                        res.findings.append(fd)
                        for et, ev in fd.entities:
                            dst = res.add_entity(et, ev)
                            res.edges.append((src_id, dst, fd.source, fd.confidence))
                            if (d < self.depth and et in PIVOT_TYPES and (et, ev) not in seen
                                    and pivots < self.max_pivots):
                                seen.add((et, ev)); pivots += 1
                                queue.append((et, ev, d + 1))
        correlate(res)                                           # relaciones heurísticas
        return res

    def scan_many(self, inputs, label=None) -> ScanResult:
        """Escanea varios datos de UNA misma investigación y los fusiona en un solo
        resultado, con un nodo raíz 'person' conectado a cada dato aportado."""
        label = label or inputs[0][1]
        merged = ScanResult(label, "person",
                            started=datetime.now(timezone.utc).isoformat(timespec="seconds"))
        root = merged.add_entity("person", label)
        for t, v in inputs:
            self.log(f"--- {t}: {v}")
            r = self.scan(v, t)
            merged.findings += r.findings
            merged.errors += r.errors
            for k, val in r.entities.items():
                merged.entities.setdefault(k, val)
            merged.edges += r.edges
            merged.edges.append((root, ScanResult.node_id(t, v), "dato aportado", 1.0))
        correlate(merged)                       # relaciones cruzadas entre todos los datos
        merged.edges = list(dict.fromkeys(merged.edges))     # sin duplicados
        return merged
