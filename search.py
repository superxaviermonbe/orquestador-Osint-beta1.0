"""Capa común de buscadores vía API oficial (nada de scraping de Google).

Proveedores, por orden de preferencia (se usa el primero con clave):
  - SerpApi (resultados reales de Google) : SERPAPI_KEY
  - Brave Search API                      : BRAVE_API_KEY
  - Google Programmable Search            : GOOGLE_CSE_KEY + GOOGLE_CSE_CX
"""
from __future__ import annotations
from typing import Callable, List, Optional, Tuple

Result = Tuple[str, str, str]          # (título, url, snippet)


def _serpapi(ctx, q: str, n: int) -> List[Result]:
    r = ctx.get("https://serpapi.com/search.json",
                params={"engine": "google", "q": q, "num": n, "hl": "es", "api_key": ctx.env["SERPAPI_KEY"]})
    r.raise_for_status()
    return [(x.get("title", ""), x["link"], x.get("snippet", "")) for x in r.json().get("organic_results", [])]


def _brave(ctx, q: str, n: int) -> List[Result]:
    r = ctx.get("https://api.search.brave.com/res/v1/web/search", params={"q": q, "count": n},
                headers={"X-Subscription-Token": ctx.env["BRAVE_API_KEY"], "Accept": "application/json"})
    r.raise_for_status()
    return [(x["title"], x["url"], x.get("description", "")) for x in r.json().get("web", {}).get("results", [])]


def _google(ctx, q: str, n: int) -> List[Result]:
    r = ctx.get("https://www.googleapis.com/customsearch/v1",
                params={"key": ctx.env["GOOGLE_CSE_KEY"], "cx": ctx.env["GOOGLE_CSE_CX"], "q": q, "num": min(n, 10)})
    r.raise_for_status()
    return [(x["title"], x["link"], x.get("snippet", "")) for x in r.json().get("items", [])]


def provider(env: dict) -> Optional[Tuple[str, Callable]]:
    if env.get("SERPAPI_KEY"):
        return "SerpApi", _serpapi
    if env.get("BRAVE_API_KEY"):
        return "Brave", _brave
    if env.get("GOOGLE_CSE_KEY") and env.get("GOOGLE_CSE_CX"):
        return "Google CSE", _google
    return None
