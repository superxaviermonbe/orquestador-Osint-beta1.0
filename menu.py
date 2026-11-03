"""Menú interactivo en terminal: banner ASCII, preguntas guiadas y reporte en el navegador."""
from __future__ import annotations
import json
import os
import re
import sys
import webbrowser
from datetime import datetime
from pathlib import Path

from .base import REGISTRY, Context
from .engine import DOMAIN_RE, EMAIL_RE, PHONE_RE, Engine
from .modules import load_all
from .report import write_all

# Claves API conocidas: variable de entorno -> (servicio, dónde conseguirla)
KEYS = {
    "HIBP_API_KEY": ("HaveIBeenPwned", "haveibeenpwned.com/API/Key"),
    "HUNTER_API_KEY": ("Hunter.io", "hunter.io/api-keys"),
    "SHODAN_API_KEY": ("Shodan", "account.shodan.io"),
    "VT_API_KEY": ("VirusTotal", "virustotal.com/gui/my-apikey"),
    "GITHUB_TOKEN": ("GitHub (opcional, sube el rate-limit)", "github.com/settings/tokens"),
    "EMAILREP_KEY": ("EmailRep (opcional)", "emailrep.io/key"),
    "SERPAPI_KEY": ("SerpApi: Google real (recomendado para dorks)", "serpapi.com/manage-api-key"),
    "BRAVE_API_KEY": ("Brave Search (alternativa para dorks)", "brave.com/search/api"),
    "GOOGLE_CSE_KEY": ("Google Programmable Search: clave", "developers.google.com/custom-search"),
    "GOOGLE_CSE_CX": ("Google Programmable Search: id del buscador (cx)", "programmablesearchengine.google.com"),
    "IG_ACCESS_TOKEN": ("Instagram Graph API: token", "developers.facebook.com"),
    "IG_USER_ID": ("Instagram Graph API: tu IG user id", "developers.facebook.com"),
}
CFG = Path.home() / ".jsint.json"
R, G, Y, B, C, D, X = "\033[91m", "\033[92m", "\033[93m", "\033[94m", "\033[96m", "\033[2m", "\033[0m"

# Banner: se compone letra a letra para evitar errores de alineación
_L = {
    "J": ["     _ ", "    | |", " _  | |", "| |_| |", " \\___/ "],
    "S": [" ____  ", "/ ___| ", "\\___ \\ ", " ___) |", "|____/ "],
    "I": [" ___ ", "|_ _|", " | | ", " | | ", "|___|"],
    "N": [" _   _ ", "| \\ | |", "|  \\| |", "| |\\  |", "|_| \\_|"],
    "T": [" _____ ", "|_   _|", "  | |  ", "  | |  ", "  |_|  "],
}


def banner() -> str:
    rows = ["".join(_L[ch][i] for ch in "JSINT") for i in range(5)]
    art = "\n".join(f"{C}{r}{X}" for r in rows)
    return f"\n{art}\n{D}  OSINT toolkit · solo fuentes públicas · uso ético y autorizado{X}\n"


# ---------------------------------------------------------------- utilidades
def load_cfg() -> dict:
    try:
        return json.loads(CFG.read_text())
    except Exception:
        return {}


def save_cfg(cfg: dict) -> None:
    CFG.write_text(json.dumps(cfg))
    try:
        os.chmod(CFG, 0o600)                       # puede contener la clave de HIBP
    except OSError:
        pass


def build_env(cfg: dict) -> dict:
    """Variables de entorno + claves guardadas en la config (el entorno gana si ambos existen)."""
    keys = dict(cfg.get("keys", {}))
    if cfg.get("hibp"):                                 # compatibilidad con la versión anterior
        keys.setdefault("HIBP_API_KEY", cfg["hibp"])
    return {**keys, **os.environ}


def ask(prompt: str, validator=None, err="Valor no válido.") -> str:
    """Pide un dato; Enter = omitir. Repite hasta que sea válido."""
    while True:
        v = input(f"{B}?{X} {prompt}: ").strip()
        if not v or validator is None or validator(v):
            return v
        print(f"{R}  {err}{X}")


def yes(prompt: str, default=False) -> bool:
    d = "S/n" if default else "s/N"
    v = input(f"{B}?{X} {prompt} [{d}]: ").strip().lower()
    return default if not v else v in ("s", "si", "sí", "y", "yes")


def open_report(path: Path) -> None:
    print(f"{G}[+] Reporte: {path}{X}")
    if not webbrowser.open(path.resolve().as_uri()):
        print(f"{Y}    No pude abrir el navegador; abre el archivo manualmente.{X}")


# ---------------------------------------------------------------- acciones
def show_modules(ctx: Context) -> None:
    print(f"\n{C}Módulos disponibles{X}")
    for n, cls in sorted(REGISTRY.items()):
        ok, why = cls().available(ctx)
        mark = f"{G}●{X}" if ok else f"{Y}○{X}"
        extra = "" if ok else f" {D}({why}){X}"
        print(f" {mark} {n:13} {','.join(sorted(cls.accepts)):26} {cls.description}{extra}")
    print(f"\n{D} ● listo  ○ requiere clave/herramienta externa{X}")


def settings(cfg: dict) -> None:
    print(f"\n{C}Configuración{X}  (se guarda en {CFG})")
    keys = cfg.setdefault("keys", {})
    env = build_env(cfg)
    print(f"{D}Enter = mantener · escribe '-' para borrar una clave{X}")
    for var, (svc, where) in KEYS.items():
        state = f"{G}definida{X}" if env.get(var) else f"{Y}vacía{X}"
        v = input(f"{B}?{X} {svc} [{state}] ({where}): ").strip()
        if v == "-":
            keys.pop(var, None)
        elif v:
            keys[var] = v
    d = input(f"{B}?{X} Profundidad de pivoteo 0-2 [{cfg.get('depth', 1)}]: ").strip()
    if d.isdigit():
        cfg["depth"] = min(int(d), 2)
    r = input(f"{B}?{X} Región por defecto de teléfonos ISO-2 [{cfg.get('region', 'ES')}]: ").strip().upper()
    if len(r) == 2:
        cfg["region"] = r
    save_cfg(cfg)
    print(f"{G}[+] Guardado.{X}")


def investigate(cfg: dict) -> Path | None:
    print(f"\n{C}Nueva investigación{X}")
    print(f"{D}Úsala solo sobre datos propios, con consentimiento o autorización legítima.{X}")
    if not yes("¿Confirmas que tienes autorización/base legítima para investigar este objetivo?"):
        print(f"{Y}Cancelado.{X}")
        return None
    print(f"{D}Rellena lo que tengas; Enter para omitir un campo.{X}\n")
    name = ask("Nombre completo")
    email = ask("Correo electrónico", EMAIL_RE.match, "Formato de email inválido.")
    user = ask("Nombre de usuario / alias", lambda v: re.match(r"^[A-Za-z0-9_.\-]{1,40}$", v),
               "Solo letras, números, _ . - (máx. 40).")
    phone = ask("Teléfono (con +prefijo mejor)", lambda v: PHONE_RE.match(v), "Formato de teléfono inválido.")
    domain = ask("Dominio (ej. empresa.com)", lambda v: DOMAIN_RE.match(v), "Dominio inválido.")
    dctx = ask("Palabra de contexto para afinar Google (ciudad, empresa, profesión; opcional)") if name else ""
    inputs = [(t, v) for t, v in (("name", name), ("email", email), ("username", user),
                                  ("phone", phone), ("domain", domain.lower())) if v]
    if not inputs:
        print(f"{Y}No introdujiste ningún dato.{X}")
        return None

    print(f"\n{C}Resumen{X}")
    for t, v in inputs:
        print(f"  {t:9} {v}")
    if not yes("¿Ejecutar la investigación?", True):
        return None

    env = build_env(cfg)
    if dctx:
        env["DORK_CONTEXT"] = dctx
    ctx = Context(env=env, region=cfg.get("region", "ES"))
    eng = Engine(ctx, depth=cfg.get("depth", 1), log=lambda m: print(f"  {m}"))
    print(f"\n{C}Ejecutando...{X}  {D}(puede tardar un minuto){X}")
    res = eng.scan_many(inputs, label=name or email or user or phone or domain)

    slug = re.sub(r"[^\w.-]", "_", res.target)[:40]
    out = Path("reports") / f"{slug}_{datetime.now():%Y%m%d_%H%M%S}"
    write_all(res, out)
    print(f"\n{G}[+] {len(res.findings)} hallazgos · {len(res.entities)} entidades · "
          f"{len(res.edges)} relaciones · {len(res.errors)} avisos{X}")
    print(f"{D}    También: report.json · graph.dot · maltego_entities.csv · maltego_links.csv{X}")
    html = out / "report.html"
    open_report(html)
    return html


def main() -> int:
    os.system("")                                   # activa ANSI en Windows
    load_all()
    cfg = load_cfg()
    last = None
    while True:
        print(banner())
        print(f" {G}1{X}) Nueva investigación")
        print(f" {G}2{X}) Ver módulos y estado")
        print(f" {G}3{X}) Configuración (API keys, profundidad)")
        print(f" {G}4{X}) Abrir último reporte")
        print(f" {G}0{X}) Salir\n")
        try:
            op = input(f"{B}jsint>{X} ").strip()
            if op == "1":
                last = investigate(cfg) or last
            elif op == "2":
                show_modules(Context(env=build_env(cfg)))
            elif op == "3":
                settings(cfg)
            elif op == "4":
                if last:
                    open_report(last)
                else:
                    print(f"{Y}Aún no hay reportes en esta sesión (mira la carpeta reports/).{X}")
            elif op in ("0", "q", "salir"):
                print("¡Hasta luego!")
                return 0
            else:
                print(f"{Y}Opción no válida.{X}")
            input(f"\n{D}Enter para volver al menú...{X}")
        except (KeyboardInterrupt, EOFError):
            print("\n¡Hasta luego!")
            return 0


if __name__ == "__main__":
    sys.exit(main())
