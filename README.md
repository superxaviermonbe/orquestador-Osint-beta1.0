# Jsint — Toolkit OSINT modular con menú en terminal

```
     _  ____   ___  _   _  _____
    | |/ ___| |_ _|| \ | ||_   _|
 _  | |\___ \  | | |  \| |  | |
| |_| | ___) | | | | |\  |  | |
 \___/ |____/ |___||_| \_|  |_|
```

Recolecta información **de fuentes públicas** sobre una persona/entidad, correlaciona los datos y
abre un reporte en el navegador con un **grafo de relaciones interactivo**.

> ⚠️ **Uso ético y legal.** Solo sobre datos propios, con consentimiento o con autorización expresa
> (pentest, red team, investigación, formación). Respeta los Términos de Servicio de cada fuente y la
> normativa de protección de datos (RGPD/LOPDGDD). Los resultados son *indicios*: un mismo alias
> no implica la misma persona.

## Instalación

```bash
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```
Opcional (mejoran los resultados; si faltan, el módulo se marca como omitido):
`theHarvester`, `recon-ng`, Graphviz (`dot`, para `graph.png`) y una clave de [HaveIBeenPwned](https://haveibeenpwned.com/API/Key).

## Uso

```bash
python jsint.py            # menú interactivo (banner + preguntas guiadas + reporte en el navegador)
```
Flujo: **1) Nueva investigación** → confirmas uso autorizado → te pregunta nombre, correo, usuario,
teléfono y dominio (Enter para omitir) → ejecuta los módulos en paralelo con progreso en vivo →
abre `report.html` en el navegador. En **3) Configuración** guardas tu `HIBP_API_KEY` (en `~/.jsint.json`,
permisos 600), la profundidad de pivoteo y la región telefónica.

Modo no interactivo (scripts/CI):

```bash
python jsint.py example.com --authorized
python jsint.py persona@example.com --authorized --depth 1
python jsint.py --list-modules
python jsint.py --web      # interfaz web local en http://127.0.0.1:5000
```

## Salida (`reports/<objetivo>_<fecha>/`)

| Archivo | Contenido |
|---|---|
| `report.html` | Reporte completo: tarjetas resumen, **grafo interactivo** (sin dependencias, arrastrable), resumen de entidades, tabla filtrable de hallazgos, relaciones y avisos. Botón *Imprimir / guardar PDF*. |
| `report.json` | Todos los datos estructurados (hallazgos, entidades, relaciones). |
| `graph.dot` / `graph.png` | Grafo Graphviz (PNG si `dot` está instalado). |
| `maltego_entities.csv`, `maltego_links.csv` | Para Maltego: *Import → Import Graph from Table* (tipos `maltego.*` ya mapeados). |

## Módulos

| Módulo | Entrada | Fuente |
|---|---|---|
| `hibp` | email | HaveIBeenPwned API v3 (clave) |
| `gravatar` | email | Perfil público de Gravatar |
| `username` | username | 12 plataformas públicas |
| `domain` | dominio | WHOIS + DNS |
| `crtsh` | dominio | Certificate Transparency |
| `theharvester` | dominio | **theHarvester** (CLI + parseo JSON) |
| `reconng` | dominio | **Recon-ng** (resource script + parseo, best-effort) |
| `phone` | teléfono | Metadatos offline (`phonenumbers`) |
| `dorks` | nombre/email/alias/teléfono | Enlaces de búsqueda pública para revisión **manual** |
| `googledork` | nombre/email/alias/teléfono | Dorks ejecutados vía API (SerpApi/Brave/Google CSE) |
| `shodango` | dominio / IP | **Shodan vía Go** (`tools/shodan-go`, cliente shadowscatcher/shodan): DnsDomain y Honeyscore |
| `securitytxt` | dominio | Plugin de ejemplo |

`--depth N` / configuración: reutiliza entidades halladas (emails, alias, dominios) como nuevas entradas,
limitado por `--max-pivots`. La **correlación** enlaza email↔alias (misma parte local) y perfiles con el mismo
handle; esas relaciones salen discontinuas (baja confianza).

## Añadir APIs (más potencia)

1. **Claves**: menú → *3) Configuración* (se guardan en `~/.jsint.json`, permisos 600) o variables de entorno
   (`export SHODAN_API_KEY=...`). El entorno tiene prioridad. Las claves se ocultan (`***`) si aparecen en errores.
2. **Módulos incluidos que usan API**: `hibp`, `hunter`, `shodan`, `virustotal`, `emailrep`, `github`.
3. **Pivoteo**: con profundidad ≥1, el dominio → IPs (módulo `domain`) → Shodan/VirusTotal; el email → alias → GitHub/perfiles.
4. **Nueva API** = un archivo en `plugins/` con `env_key = "MI_API_KEY"`; añade la clave a `KEYS` en `osintkit/menu.py`
   para que aparezca en el menú. Pon la clave en **cabeceras**, no en la URL, siempre que la API lo permita.

APIs recomendadas para ampliar: SecurityTrails (DNS histórico), Censys, urlscan.io, AlienVault OTX,
AbuseIPDB, IPinfo, Veriphone/NumVerify (teléfonos), Hunter *email-verifier*, LeakCheck/IntelX (datos filtrados;
solo con autorización y base legal clara). Respeta cuotas y términos de cada servicio.

## Google dorking, Instagram y LinkedIn

Ni Instagram ni LinkedIn ofrecen API pública de búsqueda de personas, y el scraping (de ellos o de Google)
incumple sus términos. Jsint usa **APIs de buscador** y deja la decisión final en tus manos:

| Módulo | Cómo funciona | Qué necesitas |
|---|---|---|
| `googledork` | Ejecuta hasta 8 dorks por dato (general, `site:linkedin.com/in`, Instagram, Facebook, X, GitHub, PDF/CV, prensa...) y muestra los resultados en la sección **Búsquedas** del reporte | `SERPAPI_KEY` (Google real) **o** `BRAVE_API_KEY` **o** `GOOGLE_CSE_KEY`+`GOOGLE_CSE_CX` |
| `dorks` | Enlaces de búsqueda para abrir a mano en el navegador (sin clave) | nada |
| `instagram` | Graph API oficial (Business Discovery) para cuentas Business/Creator | ver abajo |

En el reporte cada resultado tiene **★ Relevante / ✕ Descartar**, una marca de coincidencia (alta/media/baja
según cuántas palabras del nombre aparecen en título+snippet), filtros para ocultar descartados o coincidencia
baja, y un botón para copiar las URLs relevantes. Las marcas se guardan en el navegador. En el menú puedes
añadir una **palabra de contexto** (ciudad, empresa...) que se añade a las búsquedas por nombre para afinar.
`DORK_MAX` limita las consultas por dato (por defecto 8) para cuidar la cuota de la API. Los resultados de
redes sociales con coincidencia alta/media se añaden al grafo como nodos de baja confianza.

**Obtener `IG_ACCESS_TOKEN` e `IG_USER_ID`** (ruta Facebook Login, la que usa el módulo `instagram`):
1. Tu Instagram debe ser Business/Creator y estar vinculado a una página de Facebook.
2. Crea una app tipo *Business* en developers.facebook.com y abre el *Graph API Explorer*.
3. Elige tu app, pulsa *Get User Access Token* y marca los permisos `instagram_basic`, `pages_show_list`
   y `pages_read_engagement` (verifica la lista actual en la doc de Meta). Ese es tu `IG_ACCESS_TOKEN`.
4. `GET /me/accounts` → id de tu página; `GET /{page-id}?fields=instagram_business_account` → ese `id` es tu `IG_USER_ID`.
5. El token del Explorer dura ~1 h: cámbialo por uno de 60 días (`/oauth/access_token?grant_type=fb_exchange_token`)
   y renuévalo antes de que caduque. La versión de la API se ajusta con `IG_GRAPH_VERSION` (por defecto v26.0).


## Shodan: módulo Python y binario Go

- `shodan` (Python, sin compilar): host → puertos, servicios, CVEs. Solo necesita `SHODAN_API_KEY`.
- `shodango` (opcional): usa el cliente Go [shadowscatcher/shodan](https://github.com/shadowscatcher/shodan) para
  *DnsDomain* (subdominios) y *Honeyscore*. Compílalo una vez (necesita Go ≥ 1.21 y red):
  `cd tools/shodan-go && go mod tidy && go build -o jsint-shodan .` Jsint lo detecta en `tools/shodan-go/`, en el PATH
  o en `$JSINT_SHODAN_BIN`. `jsint-shodan profile` comprueba que tu clave funciona.

## Estructura

```
jsint.py                  # menú (sin args) o CLI (con args)
osintkit/  menu.py cli.py webui.py engine.py correlate.py report.py models.py base.py
           modules/       # hibp gravatar username domain crtsh harvester reconng phone dorks
plugins/                  # tus módulos (autocargados)
tests/
```

## Crear un módulo / integrar otra herramienta

`plugins/mi_modulo.py`:

```python
from osintkit.base import BaseModule, register
from osintkit.models import Finding

@register
class Mi(BaseModule):
    name = "mi_modulo"; description = "Qué hace"
    accepts = frozenset({"domain"})
    def run(self, target, ttype, ctx):                  # ctx.get() = requests con timeout
        return [Finding("mi_modulo", "info", "Título", data={"k": "v"},
                        entities=[("email", "x@y.com")])]   # alimenta grafo y pivoteo
```
Para otras herramientas CLI, usa `subprocess` con lista de argumentos (nunca `shell=True`) y valida la
entrada, como en `modules/harvester.py`.

## Limitaciones

- Alias: detección por código HTTP; sitios con WAF (403/429) se ignoran.
- WHOIS suele estar redactado (RGPD); el operador telefónico no refleja portabilidad.
- El parseo de Recon-ng depende de la versión instalada (v5).
- No incluye scraping de buscadores ni *people-search* a propósito; `dorks` solo genera enlaces.
