"""Reportes: JSON, HTML autocontenido (con grafo interactivo), DOT/PNG y CSV para Maltego."""
from __future__ import annotations
import csv
import html
import json
import shutil
import subprocess
from pathlib import Path

from .correlate import profile_summary
from .models import ScanResult

COLORS = {"person": "#111827", "email": "#4C78A8", "username": "#F58518", "domain": "#54A24B",
          "phone": "#B279A2", "name": "#E45756", "profile": "#72B7B2", "breach": "#D62728",
          "ip": "#9D755D", "subdomain": "#9CA3AF", "org": "#E377C2"}

# Mapeo a tipos de entidad de Maltego (para Import Graph from Table)
MALTEGO = {"person": "maltego.Person", "name": "maltego.Person", "email": "maltego.EmailAddress",
           "username": "maltego.Alias", "phone": "maltego.PhoneNumber", "domain": "maltego.Domain",
           "subdomain": "maltego.DNSName", "ip": "maltego.IPv4Address", "profile": "maltego.URL",
           "org": "maltego.Organization", "breach": "maltego.Phrase"}


# ---------------------------------------------------------------- JSON / CSV / DOT
def safe_href(url: str) -> str:
    """Solo http(s): evita enlaces javascript: procedentes de resultados de internet."""
    return html.escape(url) if url and url.lower().startswith(("http://", "https://")) else ""


def to_json(res: ScanResult, path: Path) -> None:
    path.write_text(json.dumps(res.to_dict(), indent=2, ensure_ascii=False, default=str), encoding="utf-8")


def to_maltego_csv(res: ScanResult, outdir: Path) -> None:
    """Dos CSV: entidades y enlaces. En Maltego: Import > Import Graph from Table."""
    with open(outdir / "maltego_entities.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh); w.writerow(["EntityType", "Value"])
        for t, v in res.entities.values():
            w.writerow([MALTEGO.get(t, "maltego.Phrase"), v])
    with open(outdir / "maltego_links.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh); w.writerow(["Source", "Target", "Label", "Confidence"])
        for a, b, label, c in res.edges:
            w.writerow([res.entities[a][1], res.entities[b][1], label, c])


def to_dot(res: ScanResult) -> str:
    esc = lambda s: str(s).replace("\\", "\\\\").replace('"', '\\"')
    lines = ["digraph jsint {", "  rankdir=LR; node [style=filled,fontname=Helvetica,fontsize=10];"]
    for nid, (t, v) in res.entities.items():
        shape = "doublecircle" if t == "person" else "box"
        lines.append(f'  "{esc(nid)}" [label="{esc(t)}\\n{esc(v[:45])}",shape={shape},'
                     f'fillcolor="{COLORS.get(t, "#DDDDDD")}",fontcolor=white];')
    for a, b, label, conf in res.edges:
        style = "dashed" if conf < 0.5 else "solid"
        lines.append(f'  "{esc(a)}" -> "{esc(b)}" [label="{esc(label)}",style={style},fontsize=8];')
    lines.append("}")
    return "\n".join(lines)


def render_graph(res: ScanResult, outdir: Path) -> None:
    dot = to_dot(res)
    (outdir / "graph.dot").write_text(dot, encoding="utf-8")
    if shutil.which("dot"):                                   # Graphviz opcional
        subprocess.run(["dot", "-Tpng", "-o", str(outdir / "graph.png")], input=dot, text=True, timeout=60)


# ---------------------------------------------------------------- HTML
GRAPH_JS = r"""
(function(){
const data=JSON.parse(document.getElementById('graph-data').textContent);
const svg=document.getElementById('graph'),NS='http://www.w3.org/2000/svg',W=1000,H=620;
const mk=(t,a)=>{const e=document.createElementNS(NS,t);for(const k in a)e.setAttribute(k,a[k]);return e};
const nodes=data.nodes.map((n,i)=>Object.assign({},n,{x:W/2+Math.cos(i)*220+Math.random()*40,y:H/2+Math.sin(i)*220+Math.random()*40,vx:0,vy:0}));
const idx={};nodes.forEach(n=>idx[n.id]=n);
const links=data.edges.filter(e=>idx[e.from]&&idx[e.to]).map(e=>({s:idx[e.from],t:idx[e.to],label:e.label,c:e.confidence}));
links.forEach(l=>{l.el=mk('line',{stroke:'#9ca3af','stroke-width':1.5,'stroke-dasharray':l.c<0.5?'5,4':'0'});
  const tt=mk('title',{});tt.textContent=l.label+' ('+Math.round(l.c*100)+'%)';l.el.appendChild(tt);svg.appendChild(l.el)});
nodes.forEach(n=>{n.g=mk('g',{style:'cursor:grab'});
  n.c=mk('circle',{r:n.type==='person'?16:9,fill:n.color,stroke:'#fff','stroke-width':2});
  n.t=mk('text',{'font-size':10,dy:-13,'text-anchor':'middle',fill:'currentColor'});
  n.t.textContent=n.value.length>28?n.value.slice(0,27)+'…':n.value;
  const tt=mk('title',{});tt.textContent=n.type+': '+n.value;n.g.append(n.c,n.t,tt);svg.appendChild(n.g);
  n.g.addEventListener('mousedown',ev=>{n.drag=true;ev.preventDefault()})});
function pt(ev){const p=svg.createSVGPoint();p.x=ev.clientX;p.y=ev.clientY;return p.matrixTransform(svg.getScreenCTM().inverse())}
window.addEventListener('mousemove',ev=>{const n=nodes.find(x=>x.drag);if(!n)return;const p=pt(ev);n.x=p.x;n.y=p.y;kick(.3)});
window.addEventListener('mouseup',()=>nodes.forEach(n=>n.drag=false));
let alpha=1,run=false;
function draw(){links.forEach(l=>{l.el.setAttribute('x1',l.s.x);l.el.setAttribute('y1',l.s.y);l.el.setAttribute('x2',l.t.x);l.el.setAttribute('y2',l.t.y)});
  nodes.forEach(n=>{n.g.setAttribute('transform','translate('+n.x+','+n.y+')')})}
function step(){
  for(let i=0;i<nodes.length;i++){const a=nodes[i];
    for(let j=i+1;j<nodes.length;j++){const b=nodes[j];let dx=a.x-b.x,dy=a.y-b.y,d2=dx*dx+dy*dy+.01,d=Math.sqrt(d2),f=3000/d2;dx/=d;dy/=d;a.vx+=dx*f;a.vy+=dy*f;b.vx-=dx*f;b.vy-=dy*f}
    a.vx+=(W/2-a.x)*.002;a.vy+=(H/2-a.y)*.002}
  links.forEach(l=>{let dx=l.t.x-l.s.x,dy=l.t.y-l.s.y,d=Math.sqrt(dx*dx+dy*dy)+.01,f=(d-95)*.02;dx/=d;dy/=d;l.s.vx+=dx*f;l.s.vy+=dy*f;l.t.vx-=dx*f;l.t.vy-=dy*f});
  nodes.forEach(n=>{if(n.drag)return;n.vx*=.6;n.vy*=.6;n.x=Math.max(20,Math.min(W-20,n.x+n.vx*alpha));n.y=Math.max(20,Math.min(H-20,n.y+n.vy*alpha))});
  alpha*=.985;draw();if(alpha>.02)requestAnimationFrame(step);else run=false}
function kick(a){alpha=Math.max(alpha,a);if(!run){run=true;requestAnimationFrame(step)}}
kick(1);
})();
document.getElementById('q').addEventListener('input',e=>{const q=e.target.value.toLowerCase();
  document.querySelectorAll('#ft tr.row').forEach(r=>r.style.display=r.textContent.toLowerCase().includes(q)?'':'none')});
"""

CSS = """
:root{--bg:#fff;--fg:#111827;--mut:#6b7280;--bd:#e5e7eb;--card:#f9fafb}
@media(prefers-color-scheme:dark){:root{--bg:#0f172a;--fg:#e5e7eb;--mut:#94a3b8;--bd:#334155;--card:#1e293b}}
body{font-family:system-ui,sans-serif;background:var(--bg);color:var(--fg);max-width:1150px;margin:2rem auto;padding:0 1rem}
h1{margin-bottom:.2rem}.mut{color:var(--mut)}
.cards{display:flex;gap:.8rem;flex-wrap:wrap;margin:1rem 0}
.card{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:.7rem 1.1rem}
.card b{font-size:1.5rem;display:block}
table{border-collapse:collapse;width:100%}td,th{border:1px solid var(--bd);padding:.4rem;vertical-align:top;font-size:.88rem;text-align:left}
th{background:var(--card)}pre{margin:0;white-space:pre-wrap;font-size:.74rem;max-height:160px;overflow:auto}
.warn{background:#fef3c7;color:#78350f;padding:.7rem;border-radius:8px}
svg#graph{width:100%;height:auto;background:var(--card);border:1px solid var(--bd);border-radius:10px}
.leg span{display:inline-block;margin-right:1rem;font-size:.85rem}.leg i{display:inline-block;width:11px;height:11px;border-radius:50%;margin-right:4px}
input#q{width:100%;padding:.5rem;margin:.5rem 0;border:1px solid var(--bd);border-radius:6px;background:var(--bg);color:var(--fg)}
button{padding:.5rem 1rem;border-radius:6px;border:1px solid var(--bd);background:var(--card);color:var(--fg);cursor:pointer}
details{margin:.3rem 0}
.dk{border:1px solid var(--bd);border-radius:10px;padding:.6rem .9rem;margin:.6rem 0;background:var(--card)}
.dk h4{margin:.1rem 0}.dk code{font-size:.75rem;color:var(--mut)}
.res{border-top:1px solid var(--bd);padding:.5rem 0}.res a{font-weight:600}
.ru{font-size:.78rem;color:var(--mut);word-break:break-all}.rs{font-size:.86rem;margin:.2rem 0}
.badge{font-size:.7rem;padding:1px 7px;border-radius:99px;color:#fff;margin-left:.4rem}
.b-alta{background:#16a34a}.b-media{background:#d97706}.b-baja{background:#6b7280}
.res button{font-size:.75rem;padding:.2rem .6rem;margin-right:.3rem}
.res.keep{border-left:4px solid #16a34a;padding-left:.5rem}.res.drop{opacity:.35}.hide-drop .res.drop{display:none}
.chips a{display:inline-block;margin:.15rem .3rem .15rem 0;padding:.2rem .6rem;border:1px solid var(--bd);border-radius:99px;font-size:.8rem;text-decoration:none}
.bar{position:sticky;top:0;background:var(--bg);padding:.5rem 0;z-index:5;border-bottom:1px solid var(--bd)}@media print{button,input#q{display:none}svg#graph{height:520px}}
"""


DORK_JS = r"""
(function(){
const KEY='jsint:'+document.title; let st={};
try{st=JSON.parse(localStorage.getItem(KEY)||'{}')}catch(e){}
const save=()=>{try{localStorage.setItem(KEY,JSON.stringify(st))}catch(e){}};
const cnt=document.getElementById('dk-count');
function paint(r){const s=st[r.dataset.url];r.classList.toggle('keep',s==='keep');r.classList.toggle('drop',s==='drop')}
function count(){if(!cnt)return;const v=Object.values(st);cnt.textContent=v.filter(x=>x==='keep').length+' relevantes · '+v.filter(x=>x==='drop').length+' descartados'}
document.querySelectorAll('.res').forEach(r=>{paint(r);
  r.querySelector('.keep-b').onclick=()=>{st[r.dataset.url]=st[r.dataset.url]==='keep'?'':'keep';save();paint(r);count()};
  r.querySelector('.drop-b').onclick=()=>{st[r.dataset.url]=st[r.dataset.url]==='drop'?'':'drop';save();paint(r);count()}});
count();
const tg=document.getElementById('dk-hide');if(tg)tg.onchange=()=>document.getElementById('dorks').classList.toggle('hide-drop',tg.checked);
const lv=document.getElementById('dk-low');if(lv)lv.onchange=()=>document.querySelectorAll('.res[data-match="baja"]').forEach(r=>r.style.display=lv.checked?'none':'');
const cp=document.getElementById('dk-copy');if(cp)cp.onclick=()=>{const u=Object.keys(st).filter(k=>st[k]==='keep').join('\\n');
  (navigator.clipboard?navigator.clipboard.writeText(u):Promise.reject()).then(()=>cp.textContent='¡Copiado!').catch(()=>prompt('Relevantes:',u))};
})();
"""


def _dork_section(res: ScanResult) -> str:
    """Sección de búsquedas: resultados de dorks (para descartar) + enlaces manuales."""
    e = html.escape
    dres = [f for f in res.findings if f.kind == "dork-result"]
    manual = [f for f in res.findings if f.kind == "manual-search"]
    if not dres and not manual:
        return ""
    out = ["<div id=dorks><h2>Búsquedas (Google dorks)</h2>"]
    if dres:
        out.append("<div class=bar><span id=dk-count class=mut></span> &nbsp; "
                   "<label><input type=checkbox id=dk-hide> ocultar descartados</label> &nbsp; "
                   "<label><input type=checkbox id=dk-low> ocultar coincidencia baja</label> &nbsp; "
                   "<button id=dk-copy>Copiar URLs relevantes</button></div>"
                   "<p class=mut>Revisa cada resultado: <b>★ Relevante</b> o <b>✕ Descartar</b>. La marca de coincidencia "
                   "indica cuántas palabras del dato buscado aparecen en el título/snippet; puede haber homónimos. "
                   "Tus marcas se guardan en este navegador.</p>")
    groups = {}
    for f in dres:
        groups.setdefault((f.data["target"], f.data["label"], f.data["query"]), []).append(f)
    order = {"alta": 0, "media": 1, "baja": 2}
    for (tgt, label, q), fs in groups.items():
        fs.sort(key=lambda f: (order[f.data["match"]], f.data["rank"]))
        out.append(f"<div class=dk><h4>{e(label)} · {e(tgt)} <span class=mut>({len(fs)})</span></h4><code>{e(q)}</code>")
        for f in fs:
            href = safe_href(f.url)
            title = f"<a href=\"{href}\" target=_blank rel=\"noopener noreferrer\">{e(f.title)}</a>" if href else e(f.title)
            out.append(f"<div class=res data-url=\"{e(f.url)}\" data-match=\"{e(f.data['match'])}\"><div>{title}"
                       f"<span class=\"badge b-{e(f.data['match'])}\">{e(f.data['match'])}</span></div>"
                       f"<div class=ru>{e(f.url)}</div><div class=rs>{e(f.data['snippet'])}</div>"
                       "<button class=keep-b>★ Relevante</button><button class=drop-b>✕ Descartar</button></div>")
        out.append("</div>")
    for f in manual:
        chips = "".join(f"<a href=\"{safe_href(u)}\" target=_blank rel=\"noopener noreferrer\">{e(k)} ↗</a>"
                        for k, u in f.data["links"].items())
        out.append(f"<div class=dk><h4>Búsqueda manual · {e(f.data['links'] and f.title)}</h4><div class=chips>{chips}</div></div>")
    out.append("</div>")
    return "".join(out)


def to_html(res: ScanResult) -> str:
    e = html.escape
    rows = "".join(
        f"<tr class=row><td>{e(f.source)}</td><td>{e(f.kind)}</td><td>{e(f.title)}"
        + (f' <a href="{safe_href(f.url)}" target="_blank" rel="noopener noreferrer">↗</a>' if safe_href(f.url) else "")
        + f"</td><td>{f.confidence:.0%}</td>"
        f"<td><pre>{e(json.dumps(f.data, ensure_ascii=False, indent=1, default=str)[:2500])}</pre></td></tr>"
        for f in res.findings if f.kind != "dork-result") or "<tr><td colspan=5>Sin hallazgos</td></tr>"
    summ = "".join(f"<details><summary><b>{e(t)}</b> ({len(vs)})</summary><ul>"
                   + "".join(f"<li>{e(v)}</li>" for v in vs[:80]) + "</ul></details>"
                   for t, vs in profile_summary(res).items())
    errs = "".join(f"<li><b>{e(x['module'])}</b>: {e(x['error'])}</li>" for x in res.errors) or "<li>ninguno</li>"
    edges = "".join(f"<tr><td>{e(res.entities[a][1])}</td><td>{e(res.entities[b][1])}</td><td>{e(l)}</td><td>{c:.0%}</td></tr>"
                    for a, b, l, c in res.edges)
    gdata = {"nodes": [{"id": k, "type": t, "value": v, "color": COLORS.get(t, "#999")}
                       for k, (t, v) in res.entities.items()],
             "edges": [{"from": a, "to": b, "label": l, "confidence": c} for a, b, l, c in res.edges]}
    gjson = json.dumps(gdata, ensure_ascii=False).replace("</", "<\\/")
    legend = "".join(f'<span><i style="background:{c}"></i>{t}</span>' for t, c in COLORS.items())
    cards = "".join(f'<div class=card><b>{n}</b>{l}</div>' for n, l in
                    [(len(res.findings), "hallazgos"), (len(res.entities), "entidades"),
                     (len(res.edges), "relaciones"), (len({f.source for f in res.findings}), "módulos con datos")]
                    + ([(sum(f.kind == "dork-result" for f in res.findings), "resultados de dorks")]
                       if any(f.kind == "dork-result" for f in res.findings) else []))
    page = """<!doctype html><html lang="es"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Jsint – __T__</title><style>__CSS__</style><body>
<h1>Jsint · Reporte OSINT</h1>
<p class=mut><b>Objetivo:</b> __T__ · <b>Fecha (UTC):</b> __D__ <button onclick="window.print()" style="float:right">Imprimir / guardar PDF</button></p>
<p class=warn>Datos de fuentes públicas. La confianza es orientativa: coincidencias de username o nombre pueden ser
homónimos. Verifica antes de concluir y usa esta información solo con autorización o base legítima.</p>
<div class=cards>__CARDS__</div>
<h2>Grafo de relaciones</h2>
<p class=mut>Arrastra los nodos. Línea discontinua = relación heurística (baja confianza).</p>
<svg id=graph viewBox="0 0 1000 620"></svg><p class=leg>__LEGEND__</p>
<script id=graph-data type="application/json">__G__</script>
__DORKS__<h2>Resumen de entidades</h2>__SUMM__
<h2>Hallazgos</h2><input id=q placeholder="Filtrar hallazgos...">
<table id=ft><tr><th>Módulo</th><th>Tipo</th><th>Hallazgo</th><th>Conf.</th><th>Datos</th></tr>__ROWS__</table>
<h2>Relaciones</h2><table><tr><th>Origen</th><th>Destino</th><th>Relación</th><th>Conf.</th></tr>__EDGES__</table>
<h2>Avisos / módulos omitidos</h2><ul>__ERRS__</ul>
<script>__JS__</script></html>"""
    for k, v in {"__CSS__": CSS, "__T__": e(res.target), "__D__": e(res.started), "__CARDS__": cards,
                 "__LEGEND__": legend, "__G__": gjson, "__SUMM__": summ, "__ROWS__": rows,
                 "__EDGES__": edges, "__ERRS__": errs, "__DORKS__": _dork_section(res),
                 "__JS__": GRAPH_JS + DORK_JS}.items():
        page = page.replace(k, v)
    return page


def write_all(res: ScanResult, outdir: Path, formats=("json", "html", "dot", "csv")) -> list:
    outdir.mkdir(parents=True, exist_ok=True)
    written = []
    if "json" in formats:
        to_json(res, outdir / "report.json"); written.append("report.json")
    if "html" in formats:
        (outdir / "report.html").write_text(to_html(res), encoding="utf-8"); written.append("report.html")
    if "dot" in formats:
        render_graph(res, outdir); written.append("graph.dot")
    if "csv" in formats:
        to_maltego_csv(res, outdir); written.append("maltego_*.csv")
    return written
