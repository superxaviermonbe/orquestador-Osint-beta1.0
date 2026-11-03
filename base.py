"""Clase base de módulos, contexto compartido y registro de módulos."""
from __future__ import annotations
import os
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Tuple, Type

import requests

from .models import Finding

UA = "osintkit/0.1 (+educational OSINT toolkit)"


@dataclass
class Context:
    """Configuración y utilidades que reciben todos los módulos."""
    timeout: int = 12
    region: str = "ES"                 # región por defecto para teléfonos
    env: Dict[str, str] = field(default_factory=lambda: dict(os.environ))
    session: requests.Session = field(default_factory=requests.Session)

    def __post_init__(self):
        self.session.headers.update({"User-Agent": UA})

    def get(self, url: str, **kw) -> requests.Response:
        """GET con timeout por defecto (los módulos no deben colgarse)."""
        kw.setdefault("timeout", self.timeout)
        return self.session.get(url, **kw)


class BaseModule:
    """Interfaz que debe implementar todo módulo (incluidos los plugins)."""
    name: str = "base"
    description: str = ""
    accepts: FrozenSet[str] = frozenset()   # tipos de entrada que entiende
    env_key: str = ""                       # si se define, el módulo exige esa clave API

    def available(self, ctx: Context) -> Tuple[bool, str]:
        """Devuelve (ok, motivo). Por defecto solo comprueba `env_key`."""
        if self.env_key and not ctx.env.get(self.env_key):
            return False, f"falta la clave {self.env_key} (menú > Configuración)"
        return True, ""

    def run(self, target: str, ttype: str, ctx: Context) -> List[Finding]:
        raise NotImplementedError


REGISTRY: Dict[str, Type[BaseModule]] = {}


def register(cls: Type[BaseModule]) -> Type[BaseModule]:
    """Decorador: registra el módulo para autodescubrimiento."""
    REGISTRY[cls.name] = cls
    return cls
