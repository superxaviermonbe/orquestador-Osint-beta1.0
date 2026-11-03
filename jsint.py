#!/usr/bin/env python3
"""Jsint. Sin argumentos -> menú interactivo.  Con argumentos -> CLI (python jsint.py -h)."""
import sys

if "--web" in sys.argv:
    from osintkit.webui import run
    run(); sys.exit(0)
if len(sys.argv) == 1:
    from osintkit.menu import main
else:
    from osintkit.cli import main
sys.exit(main())
