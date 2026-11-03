"""Interfaz de línea de comandos."""
from __future__ import annotations
import argparse
import re
import sys
from datetime import datetime
from pathlib import Path

from .base import REGISTRY, Context
from .engine import Engine, detect_type
from .modules import load_all
from .report import write_all

NOTICE = ("Esta herramienta consulta fuentes públicas. Úsala solo sobre datos propios, con consentimiento\n"
          "o con base legal/autorización (pentest, investigación, formación). Confirma con --authorized.")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="osint", description="Toolkit OSINT modular")
    ap.add_argument("target", nargs="?", help="nombre, email, username, teléfono o dominio")
    ap.add_argument("--type", choices=["name", "email", "username", "phone", "domain"],
                    help="forzar tipo (por defecto se autodetecta)")
    ap.add_argument("-m", "--modules", help="lista separada por comas (por defecto: todos los aplicables)")
    ap.add_argument("--depth", type=int, default=0, help="pivoteo: reutiliza entidades halladas (0 = off)")
    ap.add_argument("--max-pivots", type=int, default=10)
    ap.add_argument("--region", default="ES", help="región por defecto para teléfonos (ISO-2)")
    ap.add_argument("--format", default="json,html,dot,csv", help="json,html,dot,csv")
    ap.add_argument("-o", "--out", default="reports", help="directorio de salida")
    ap.add_argument("--plugins", default="plugins", help="directorio de plugins propios")
    ap.add_argument("--list-modules", action="store_true")
    ap.add_argument("--authorized", action="store_true", help="confirmo uso autorizado/ético")
    a = ap.parse_args(argv)

    load_all(a.plugins)
    if a.list_modules:
        for n, c in sorted(REGISTRY.items()):
            print(f"{n:14} {','.join(sorted(c.accepts)):22} {c.description}")
        return 0
    if not a.target:
        ap.error("falta el objetivo")
    if not a.authorized:
        print(NOTICE, file=sys.stderr)
        return 2

    ttype = a.type or detect_type(a.target)
    mods = a.modules.split(",") if a.modules else None
    eng = Engine(Context(region=a.region), mods, depth=a.depth, max_pivots=a.max_pivots)
    print(f"[*] Objetivo: {a.target} ({ttype}) · módulos: {[m.name for m in eng.modules if ttype in m.accepts]}")
    res = eng.scan(a.target, ttype)

    slug = re.sub(r"[^\w.-]", "_", a.target)[:40]
    outdir = Path(a.out) / f"{slug}_{datetime.now():%Y%m%d_%H%M%S}"
    files = write_all(res, outdir, tuple(a.format.split(",")))
    print(f"[+] {len(res.findings)} hallazgos, {len(res.entities)} entidades, {len(res.errors)} avisos/errores")
    for e in res.errors:
        print(f"    - {e['module']}: {e['error']}")
    print(f"[+] Reporte en {outdir}/ -> {', '.join(files)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
