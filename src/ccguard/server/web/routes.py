"""ccguard web UI routes (Jinja2 + HTMX)."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

_TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

router = APIRouter()


@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "login.html", {})
