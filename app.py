"""Poland Energy Attack Visualizer - FastAPI backend.

Serves a read-only API over a single JSON dataset, the two source PDFs and
the static frontend. No database, no auth, no write endpoints. The dataset is
validated with Pydantic (including cross-references) when the app starts, so
a broken data file fails fast instead of rendering wrong content.
"""
from __future__ import annotations

import hashlib
import json
from contextlib import asynccontextmanager
from functools import lru_cache
from pathlib import Path
from typing import Literal, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, model_validator

BASE_DIR = Path(__file__).resolve().parent
DATA_FILE = BASE_DIR / "data" / "incidents.json"
STATIC_DIR = BASE_DIR / "static"

@asynccontextmanager
async def lifespan(_: FastAPI):
    load_data()  # fail fast on an invalid dataset
    yield


app = FastAPI(
    title="Poland Energy Attack Visualizer",
    description="Defensive, source-grounded reconstruction of the 29 December 2025 "
    "Polish energy-sector cyberattacks (CERT Polska).",
    version="1.1.0",
    lifespan=lifespan,
)

# --------------------------------------------------------------------------- #
# Dataset models
# --------------------------------------------------------------------------- #
Zone = Literal["internet", "edge", "apn", "it", "ot", "plc", "impact"]
Confidence = Literal["confirmed", "likely", "attempted", "unknown"]
Outcome = Literal["success", "attempted", "blocked", "unknown"]
Precision = Literal["exact", "approximate", "date-only", "date-range"]
Phase = Literal[
    "preparation", "initial-access", "reconnaissance", "credential-access",
    "persistence", "lateral-movement", "impact",
]
Category = Literal["renewable-energy", "large-chp", "second-chp", "manufacturing"]
Status = Literal["confirmed", "attempted", "partially-prevented"]


class HealthResponse(BaseModel):
    status: str


class Source(BaseModel):
    id: str
    short: str
    title: str
    publisher: str
    file: str
    url: Optional[str] = None       # publication page on cert.pl
    pdf_url: Optional[str] = None   # official PDF, used when no local copy exists
    printed_page_offset: int = 0


class Metadata(BaseModel):
    title: str
    description: str
    sources: list[Source]
    location_accuracy_notice: str
    attribution_notice: str
    page_notice: str


class SourceReference(BaseModel):
    source_id: str
    section: str
    page: int


class MitreTechnique(BaseModel):
    framework: Literal["Enterprise", "ICS"]
    technique_id: str
    technique_name: str


class Incident(BaseModel):
    id: str
    name: str
    short_name: str
    category: Category
    facility_type: str
    facility_count_min: int
    country: str
    location_precision: str
    date: str
    status: Status
    domains: list[Literal["it", "ot"]]
    summary: str
    initial_access: list[str]
    affected_assets: list[str]
    technologies: list[str]
    protocols: list[str]
    actions: list[str]
    impact: list[str]
    impact_types: list[str]
    mitre_attack: list[MitreTechnique]
    source_references: list[SourceReference]


class TimelineEvent(BaseModel):
    id: str
    date: str
    date_end: Optional[str] = None
    time: Optional[str] = None
    date_label: str
    precision: Precision
    incident_id: Optional[str]  # None = campaign-wide
    title: str
    description: str
    phase: Phase
    confidence: Confidence
    outcome: Outcome
    source_references: list[SourceReference]


class PathNode(BaseModel):
    id: str
    label: str
    zone: Zone
    role: str
    activity: str
    service: str
    impact: str
    confidence: Confidence
    outcome: Outcome
    phase: Phase
    source: SourceReference


class PathEdge(BaseModel):
    from_: str = Field(alias="from")
    to: str
    label: str


class AttackPath(BaseModel):
    id: str
    name: str
    incident_id: str
    nodes: list[PathNode]
    edges: list[PathEdge]


class Dataset(BaseModel):
    metadata: Metadata
    incidents: list[Incident]
    timeline: list[TimelineEvent]
    attack_paths: list[AttackPath]

    @model_validator(mode="after")
    def check_references(self) -> "Dataset":
        errors: list[str] = []
        source_ids = {s.id for s in self.metadata.sources}
        incident_ids = {i.id for i in self.incidents}

        def check_ref(owner: str, ref: SourceReference) -> None:
            if ref.source_id not in source_ids:
                errors.append(f"{owner}: unknown source_id '{ref.source_id}'")
            if ref.page < 1:
                errors.append(f"{owner}: invalid page {ref.page}")

        for inc in self.incidents:
            if not inc.source_references:
                errors.append(f"incident {inc.id}: no source_references")
            for r in inc.source_references:
                check_ref(f"incident {inc.id}", r)
        for e in self.timeline:
            if e.incident_id is not None and e.incident_id not in incident_ids:
                errors.append(f"event {e.id}: unknown incident '{e.incident_id}'")
            if not e.source_references:
                errors.append(f"event {e.id}: no source_references")
            for r in e.source_references:
                check_ref(f"event {e.id}", r)
        for p in self.attack_paths:
            if p.incident_id not in incident_ids:
                errors.append(f"path {p.id}: unknown incident '{p.incident_id}'")
            node_ids = {n.id for n in p.nodes}
            for n in p.nodes:
                check_ref(f"node {n.id}", n.source)
            for edge in p.edges:
                if edge.from_ not in node_ids or edge.to not in node_ids:
                    errors.append(f"path {p.id}: dangling edge {edge.from_} -> {edge.to}")
        if errors:
            raise ValueError("Dataset integrity errors:\n  " + "\n  ".join(errors))
        return self


@lru_cache(maxsize=1)
def load_data() -> dict:
    """Load and validate the dataset once per process; returns plain JSON data."""
    raw = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    Dataset.model_validate(raw)  # raises with a readable message on bad data
    raw["timeline"] = sorted(
        raw["timeline"],
        # Chronological; events without a clock time come first on their day.
        key=lambda e: (e["date"], e.get("time") or "", e["id"]),
    )
    return raw


class Summary(BaseModel):
    total_incidents: int
    facilities_min: int
    by_category: dict[str, int]
    by_status: dict[str, int]
    total_timeline_events: int
    total_attack_paths: int
    total_nodes: int
    nodes_by_outcome: dict[str, int]
    technologies: list[str]
    protocols: list[str]
    phases: list[str]
    impact_types: list[str]


# --------------------------------------------------------------------------- #
# API endpoints
# --------------------------------------------------------------------------- #
@app.get("/api/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="ok")


@app.get("/api/metadata", response_model=Metadata)
def get_metadata() -> dict:
    return load_data()["metadata"]


@app.get("/api/incidents", response_model=list[Incident])
def get_incidents() -> list[dict]:
    return load_data()["incidents"]


@app.get("/api/incidents/{incident_id}", response_model=Incident)
def get_incident(incident_id: str) -> dict:
    for inc in load_data()["incidents"]:
        if inc["id"] == incident_id:
            return inc
    raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")


@app.get("/api/timeline", response_model=list[TimelineEvent])
def get_timeline() -> list[dict]:
    return load_data()["timeline"]


@app.get("/api/attack-paths")
def get_attack_paths() -> list[dict]:
    # Returned as stored (edges keep their "from" key); validated at startup.
    return load_data()["attack_paths"]


@app.get("/api/summary", response_model=Summary)
def get_summary() -> Summary:
    data = load_data()
    incidents, paths, timeline = data["incidents"], data["attack_paths"], data["timeline"]

    def count(values) -> dict[str, int]:
        out: dict[str, int] = {}
        for v in values:
            out[v] = out.get(v, 0) + 1
        return out

    nodes = [n for p in paths for n in p["nodes"]]
    return Summary(
        total_incidents=len(incidents),
        facilities_min=sum(i["facility_count_min"] for i in incidents),
        by_category=count(i["category"] for i in incidents),
        by_status=count(i["status"] for i in incidents),
        total_timeline_events=len(timeline),
        total_attack_paths=len(paths),
        total_nodes=len(nodes),
        nodes_by_outcome=count(n["outcome"] for n in nodes),
        technologies=sorted({t for i in incidents for t in i["technologies"]}),
        protocols=sorted({p for i in incidents for p in i["protocols"]}),
        phases=sorted({e["phase"] for e in timeline} | {n["phase"] for n in nodes}),
        impact_types=sorted({t for i in incidents for t in i["impact_types"]}),
    )


@app.get("/reports/{source_id}", response_model=None)
def get_report(source_id: str) -> Response:
    """Serve a source PDF inline (open at a page with #page=N).

    Uses the local copy next to app.py when present; otherwise redirects to
    the official PDF on cert.pl. Browsers keep the #page=N fragment across
    the redirect, so page links work either way.
    """
    for s in load_data()["metadata"]["sources"]:
        if s["id"] != source_id:
            continue
        pdf = (BASE_DIR / s["file"]).resolve()
        if BASE_DIR in pdf.parents and pdf.is_file():
            return FileResponse(
                pdf,
                media_type="application/pdf",
                headers={"Content-Disposition": f'inline; filename="{pdf.name}"'},
            )
        if s.get("pdf_url"):
            return RedirectResponse(s["pdf_url"], status_code=307)
        break
    raise HTTPException(status_code=404, detail=f"Report '{source_id}' not available")


# --------------------------------------------------------------------------- #
# Errors as clean JSON
# --------------------------------------------------------------------------- #
@app.exception_handler(HTTPException)
async def http_exception_handler(_: Request, exc: HTTPException) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content={"error": exc.detail})


@app.exception_handler(Exception)
async def unhandled_exception_handler(_: Request, exc: Exception) -> JSONResponse:
    return JSONResponse(status_code=500, content={"error": "Internal server error"})


# --------------------------------------------------------------------------- #
# Static frontend
# --------------------------------------------------------------------------- #
def asset_version() -> str:
    """Short hash of the static assets, used to bust browser caches."""
    h = hashlib.sha1()
    for name in ("app.js", "styles.css"):
        h.update((STATIC_DIR / name).read_bytes())
    return h.hexdigest()[:10]


@app.get("/", response_class=HTMLResponse)
def index() -> HTMLResponse:
    html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    return HTMLResponse(
        html.replace("__ASSET_VERSION__", asset_version()),
        headers={"Cache-Control": "no-cache"},
    )


class CachedStatic(StaticFiles):
    async def get_response(self, path: str, scope):  # type: ignore[override]
        response = await super().get_response(path, scope)
        if isinstance(response, Response) and response.status_code == 200:
            # Safe to cache long: index.html references assets with ?v=<hash>.
            response.headers.setdefault("Cache-Control", "public, max-age=86400")
        return response


app.mount("/static", CachedStatic(directory=STATIC_DIR), name="static")
