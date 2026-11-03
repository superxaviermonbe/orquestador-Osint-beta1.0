"""Interfaz web mínima (Flask). Solo escucha en 127.0.0.1 por defecto."""
from __future__ import annotations
import html

from flask import Flask, jsonify, request

from .base import Context
from .engine import Engine
from .modules import load_all
from .report import to_html

app = Flask(__name__)
FORM = """<!doctype html><meta charset=utf-8><title>osintkit</title>
<body style="font-family:system-ui;max-width:640px;margin:3rem auto">
<h1>osintkit</h1><form method=post action=/scan>
<input name=target placeholder="email, username, teléfono, dominio..." style="width:100%;padding:.6rem" required>
<p>Profundidad de pivoteo: <select name=depth><option>0<option>1<option>2</select></p>
<p><label><input type=checkbox name=authorized required> Confirmo que tengo autorización/base legítima
para investigar este objetivo.</label></p><button>Escanear</button></form>
<p><small>API JSON: <code>/api/scan?target=...&authorized=1</code></small></p></body>"""


def _scan(target, depth):
    return Engine(Context(), depth=min(int(depth or 0), 2)).scan(target.strip())


@app.get("/")
def index():
    return FORM


@app.post("/scan")
def scan():
    if not request.form.get("authorized"):
        return "Debes confirmar el uso autorizado.", 400
    return to_html(_scan(request.form["target"], request.form.get("depth")))


@app.get("/api/scan")
def api_scan():
    if request.args.get("authorized") != "1":
        return jsonify(error="añade authorized=1 para confirmar uso autorizado"), 400
    return jsonify(_scan(request.args["target"], request.args.get("depth")).to_dict())


def run(host="127.0.0.1", port=5000):
    load_all()
    app.run(host=host, port=port)
