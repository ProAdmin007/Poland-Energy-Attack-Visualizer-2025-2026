/* Poland Energy Attack Visualizer - frontend logic.
   Vanilla JS. D3 is optional: all views degrade to accessible text/lists. */
(function () {
  "use strict";

  const HAS_D3 = typeof window.d3 !== "undefined";
  const ZONES = {
    internet: { color: "var(--zone-internet)", label: "Internet / external" },
    edge: { color: "var(--zone-edge)", label: "Edge / VPN" },
    apn: { color: "var(--zone-apn)", label: "Private APN / WAN" },
    it: { color: "var(--zone-it)", label: "IT" },
    ot: { color: "var(--zone-ot)", label: "OT / SCADA" },
    plc: { color: "var(--zone-plc)", label: "PLC / field devices" },
    impact: { color: "var(--zone-impact)", label: "Impact / destructive" },
  };
  // Schematic, NON-geographic cluster positions (percentages within the SVG box).
  const CLUSTER_POS = {
    "renewable-energy-farms": { x: 30, y: 30 },
    "large-chp-plant": { x: 68, y: 38 },
    "second-chp-plant": { x: 45, y: 62 },
    "manufacturing-company": { x: 74, y: 70 },
  };

  const PHASES = {
    preparation: "Preparation",
    "initial-access": "Initial access",
    reconnaissance: "Reconnaissance",
    "credential-access": "Credential access",
    persistence: "Persistence",
    "lateral-movement": "Lateral movement",
    impact: "Impact",
  };
  const IMPACT_TYPES = {
    "loss-of-view-control": "Loss of view / control",
    "device-destruction": "Device rendered inoperable",
    "data-destruction": "Data destruction",
    "process-disruption": "Physical process disruption",
    "credential-theft": "Credential theft",
    "data-theft": "Data theft",
    "recovery-hindrance": "Recovery hindered",
  };
  const OUTCOMES = {
    success: "Succeeded",
    attempted: "Attempted / failed",
    blocked: "Blocked by defenses",
    unknown: "Unknown",
  };
  const CATEGORIES = {
    "renewable-energy": "Renewable energy",
    "large-chp": "Large CHP plant",
    "second-chp": "Second CHP plant",
    manufacturing: "Manufacturing (non-energy)",
  };
  // Terms the search must support; offered as suggestions in the search box.
  const SEARCH_TERMS = ["FortiGate", "Hitachi", "Mikronika", "Moxa", "Siemens", "WAGO", "Teltonika",
    "ABB", "Schneider Electric", "DynoWiper", "LazyWiper", "RDP", "SSH", "SMB", "S7", "Modbus",
    "DNP3", "IEC 101", "VNC", "private APN"];
  const EMPTY_FILTERS = { search: "", category: "", domain: "", status: "", tech: "", protocol: "",
    phase: "", outcome: "", impact: "", nonEnergy: true };

  const state = {
    metadata: {},
    incidents: [],
    timeline: [],
    paths: [],
    summary: {},
    filters: Object.assign({}, EMPTY_FILTERS),
    activePathIndex: 0,
    activeIncident: null,
    layouts: {},        // per path id: node id -> {x, y}, kept when switching paths
    graphNodes: null,   // d3 selections of the current graph, for filter highlighting
    graphLinks: null,
    timelineZoom: "dec", // most events fall in December 2025
  };

  // --------------------------------------------------------------------- //
  async function api(path) {
    const res = await fetch(path);
    if (!res.ok) throw new Error(path + " -> " + res.status);
    return res.json();
  }

  function el(tag, attrs, children) {
    const n = document.createElement(tag);
    if (attrs) for (const k in attrs) {
      if (k === "class") n.className = attrs[k];
      else if (k === "html") n.innerHTML = attrs[k];
      else n.setAttribute(k, attrs[k]);
    }
    (children || []).forEach((c) => n.appendChild(typeof c === "string" ? document.createTextNode(c) : c));
    return n;
  }

  // Compact source line that opens the local PDF at the cited page.
  function sourceLine(ref) {
    const src = (state.metadata.sources || []).find((s) => s.id === ref.source_id);
    const title = src ? src.short || src.title : ref.source_id;
    const printed = src && src.printed_page_offset ? ref.page - src.printed_page_offset : null;
    const link = el("a", {
      class: "src-link", href: `/reports/${ref.source_id}#page=${ref.page}`,
      target: "_blank", rel: "noopener",
      title: printed ? `Printed page ${printed} in the report footer` : "",
    }, [`PDF p. ${ref.page}`]);
    return el("div", { class: "source-line" }, [`Source: CERT Polska, ${title}, ${ref.section}, `, link, "."]);
  }

  function chip(text, cls) { return el("span", { class: "chip " + (cls || "") }, [text]); }

  function textHas(text, term) { return String(text).toLowerCase().indexOf(term.toLowerCase()) !== -1; }

  // --------------------------------------------------------------------- //
  async function init() {
    if (!HAS_D3) document.getElementById("d3-fallback").classList.remove("hidden");
    try {
      const [meta, incidents, timeline, paths, summary] = await Promise.all([
        api("/api/metadata"), api("/api/incidents"), api("/api/timeline"),
        api("/api/attack-paths"), api("/api/summary"),
      ]);
      state.metadata = meta; state.incidents = incidents;
      state.timeline = timeline; state.paths = paths; state.summary = summary;
    } catch (e) {
      document.getElementById("app-description").textContent =
        "Failed to load data from the API: " + e.message;
      return;
    }
    renderHeader();
    renderSummary();
    buildFilters();
    buildTimelineZoom();
    renderLegend();
    renderPathSwitch();
    renderAttackPath();
    renderAll();
    renderSources();
  }

  function renderHeader() {
    document.getElementById("app-description").textContent = state.metadata.description || "";
    document.getElementById("location-notice").textContent = "⚠ " + (state.metadata.location_accuracy_notice || "");
    document.getElementById("attribution-notice").textContent = state.metadata.attribution_notice || "";
    document.getElementById("page-notice").textContent = state.metadata.page_notice || "";
  }

  function renderSummary() {
    const s = state.summary;
    const byOutcome = s.nodes_by_outcome || {};
    const cards = [
      { num: s.total_incidents, lbl: "Incident groups" },
      { num: "≥ " + s.facilities_min, lbl: "Affected facilities / organizations" },
      { num: s.total_attack_paths, lbl: "Attack paths" },
      { num: s.total_nodes, lbl: "Graph nodes" },
      { num: byOutcome.attempted || 0, lbl: "Attempted / failed steps" },
      { num: s.total_timeline_events, lbl: "Timeline events" },
    ];
    const box = document.getElementById("summary-cards");
    box.innerHTML = "";
    cards.forEach((c) => box.appendChild(
      el("div", { class: "sum-card" }, [el("div", { class: "num" }, [String(c.num)]), el("div", { class: "lbl" }, [c.lbl])])
    ));
  }

  // select id -> filter key, plus the options to fill it with ([value, label] pairs).
  const SELECT_FILTERS = {
    "filter-category": "category", "filter-domain": "domain", "filter-status": "status",
    "filter-tech": "tech", "filter-protocol": "protocol", "filter-phase": "phase",
    "filter-outcome": "outcome", "filter-impact": "impact",
  };

  function fillSelect(id, pairs) {
    const sel = document.getElementById(id);
    pairs.forEach(([v, label]) => sel.appendChild(el("option", { value: v }, [label])));
  }

  function buildFilters() {
    const s = state.summary;
    fillSelect("filter-category", Object.keys(s.by_category || {}).map((c) => [c, CATEGORIES[c] || c]));
    fillSelect("filter-status", Object.keys(s.by_status || {}).map((k) => [k, k]));
    fillSelect("filter-tech", (s.technologies || []).map((t) => [t, t]));
    fillSelect("filter-protocol", (s.protocols || []).map((p) => [p, p]));
    fillSelect("filter-phase", (s.phases || []).map((p) => [p, PHASES[p] || p]));
    fillSelect("filter-impact", (s.impact_types || []).map((t) => [t, IMPACT_TYPES[t] || t]));

    const dl = document.getElementById("search-terms");
    SEARCH_TERMS.forEach((t) => dl.appendChild(el("option", { value: t }, [])));

    document.getElementById("search-box").addEventListener("input", (e) => {
      state.filters.search = e.target.value.trim().toLowerCase(); renderAll();
    });
    Object.keys(SELECT_FILTERS).forEach((id) =>
      document.getElementById(id).addEventListener("change", (e) => {
        state.filters[SELECT_FILTERS[id]] = e.target.value; renderAll();
      }));
    document.getElementById("filter-nonenergy").addEventListener("change", (e) => {
      state.filters.nonEnergy = e.target.checked; renderAll();
    });
    document.getElementById("reset-filters").addEventListener("click", resetFilters);
  }

  function resetFilters() {
    state.filters = Object.assign({}, EMPTY_FILTERS);
    document.getElementById("search-box").value = "";
    Object.keys(SELECT_FILTERS).forEach((id) => { document.getElementById(id).value = ""; });
    document.getElementById("filter-nonenergy").checked = true;
    renderAll();
  }

  // Incident-level filters (also applied to the incident's timeline events).
  function incidentMatches(inc) {
    const f = state.filters;
    if (!f.nonEnergy && inc.category === "manufacturing") return false;
    if (f.category && inc.category !== f.category) return false;
    if (f.status && inc.status !== f.status) return false;
    if (f.domain && !(inc.domains || []).includes(f.domain)) return false;
    if (f.impact && !(inc.impact_types || []).includes(f.impact)) return false;
    if (f.tech && !inc.technologies.includes(f.tech)) return false;
    if (f.protocol && !inc.protocols.includes(f.protocol)) return false;
    if (f.search && !textHas(JSON.stringify(inc), f.search)) return false;
    return true;
  }

  function filteredIncidents() { return state.incidents.filter(incidentMatches); }

  // Campaign-wide events (no incident) only pass when no incident-specific filter is set.
  function eventMatches(e) {
    const f = state.filters;
    if (e.incident_id) {
      const inc = state.incidents.find((i) => i.id === e.incident_id);
      if (!inc) return false;
      const saved = f.search; f.search = "";   // search is matched on the event itself below
      const ok = incidentMatches(inc);
      f.search = saved;
      if (!ok) return false;
    } else if (f.category || f.status || f.domain || f.impact) {
      return false;
    }
    if (f.phase && e.phase !== f.phase) return false;
    if (f.outcome && e.outcome !== f.outcome) return false;
    if (f.search && !textHas(e.title + " " + e.description + " " + e.date_label, f.search)) return false;
    if (!e.incident_id) {
      if (f.tech && !textHas(e.description, f.tech)) return false;
      if (f.protocol && !textHas(e.description, f.protocol)) return false;
    }
    return true;
  }

  function filteredTimeline() { return state.timeline.filter(eventMatches); }

  // Node-level highlighting in the graph (does not remove nodes).
  const OT_ZONES = ["apn", "ot", "plc"];
  function nodeMatches(n) {
    const f = state.filters;
    if (f.phase && n.phase !== f.phase) return false;
    if (f.outcome && n.outcome !== f.outcome) return false;
    if (f.domain === "ot" && n.zone === "it") return false;
    if (f.domain === "it" && OT_ZONES.includes(n.zone)) return false;
    const text = [n.label, n.role, n.activity, n.service, n.impact].join(" ");
    if (f.tech && !textHas(text, f.tech === "FortiGate" ? "forti" : f.tech)) return false;
    if (f.protocol && !textHas(text, f.protocol)) return false;
    if (f.search && !textHas(text, f.search)) return false;
    return true;
  }

  function nodeFilterActive() {
    const f = state.filters;
    return !!(f.phase || f.outcome || f.domain || f.tech || f.protocol || f.search);
  }

  // --------------------------------------------------------------------- //
  function renderAll() {
    renderPolandMap();
    renderIncidentList();
    renderTimeline();
    renderTable();
    renderMitre();
    // The graph is not rebuilt here (that would reset a manual layout);
    // filters only change which nodes are highlighted.
    applyGraphHighlight();
    renderFilterResult();
  }

  function renderFilterResult() {
    const nInc = filteredIncidents().length, nEvt = filteredTimeline().length;
    let txt = `${nInc} of ${state.incidents.length} incidents · ${nEvt} of ${state.timeline.length} events`;
    if (state.graphNodes && nodeFilterActive()) {
      const hits = state.graphNodes.filter((n) => nodeMatches(n)).size();
      txt += ` · ${hits} highlighted node${hits === 1 ? "" : "s"}`;
    }
    document.getElementById("filter-result").textContent = txt;
  }

  function applyGraphHighlight() {
    if (!state.graphNodes) return;
    const path = state.paths[state.activePathIndex];
    const inc = state.incidents.find((i) => i.id === path.incident_id);
    const pathHidden = inc && !incidentMatches(inc);
    const active = nodeFilterActive();
    const dim = (n) => pathHidden || (active && !nodeMatches(n));
    state.graphNodes.classed("dim", dim).classed("hit", (n) => active && !pathHidden && nodeMatches(n));
    state.graphLinks.classed("dim", (l) => dim(l.source) || dim(l.target));
    const note = document.getElementById("path-hidden-note");
    if (note) note.classList.toggle("hidden", !pathHidden);
  }

  function renderPolandMap() {
    const box = document.getElementById("poland-map");
    const shown = new Set(filteredIncidents().map((i) => i.id));
    // Simplified schematic polygon (NOT a real Poland boundary) + abstract dots.
    const poly = "10,40 30,15 55,12 80,22 92,45 85,72 60,88 30,82 12,62";
    let svg = `<svg viewBox="0 0 100 100" role="img" aria-label="Schematic, non-geographic cluster map">
      <polygon class="poland-shape" points="${poly}" />`;
    state.incidents.forEach((inc) => {
      const p = CLUSTER_POS[inc.id] || { x: 50, y: 50 };
      const active = shown.has(inc.id);
      const color = inc.status === "confirmed" ? "var(--green)" : inc.status === "attempted" ? "var(--orange)" : "var(--accent)";
      const selected = state.activeIncident === inc.id ? " selected" : "";
      svg += `<circle class="cluster-dot${selected}" data-id="${inc.id}" cx="${p.x}" cy="${p.y}" r="${active ? 5 : 3}"
        fill="${color}" opacity="${active ? 1 : 0.25}" tabindex="0" role="button"
        aria-label="${inc.name}"><title>${inc.name}</title></circle>
        <text class="cluster-label" x="${p.x}" y="${p.y + 9}" text-anchor="middle"
        opacity="${active ? 1 : 0.35}">${inc.short_name || inc.name}</text>`;
    });
    svg += `</svg>`;
    box.innerHTML = svg;
    box.querySelectorAll(".cluster-dot").forEach((c) => {
      const go = () => selectIncident(c.getAttribute("data-id"));
      c.addEventListener("click", go);
      c.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); go(); } });
    });
  }

  function renderIncidentList() {
    const box = document.getElementById("incident-list");
    box.innerHTML = "";
    const list = filteredIncidents();
    if (!list.length) { box.appendChild(el("p", { class: "col-hint" }, ["No incidents match the current filters."])); return; }
    list.forEach((inc) => {
      const color = `var(--zone-${(inc.domains || []).includes("ot") ? "ot" : "it"})`;
      const card = el("div", { class: "incident-card" + (state.activeIncident === inc.id ? " active" : ""), tabindex: "0", role: "button" }, [
        el("h3", {}, [inc.name, el("span", { class: "badge badge-" + inc.status }, [inc.status])]),
        el("div", { class: "meta" }, [inc.facility_type + " — " + inc.date]),
        el("div", { class: "chips" }, (inc.impact_types || []).map((t) => chip(IMPACT_TYPES[t] || t, "chip-impact"))),
      ]);
      card.style.borderLeftColor = color;
      card.addEventListener("click", () => selectIncident(inc.id));
      card.addEventListener("keydown", (e) => { if (e.key === "Enter") selectIncident(inc.id); });
      box.appendChild(card);
    });
  }

  function selectIncident(id) {
    state.activeIncident = id;
    // Switch center graph to the matching path if one exists.
    const idx = state.paths.findIndex((p) => p.incident_id === id);
    if (idx >= 0 && idx !== state.activePathIndex) {
      state.activePathIndex = idx; renderPathSwitch(); renderAttackPath();
    }
    renderIncidentList();
    renderPolandMap();
    showIncidentDetail(id);
  }

  function showIncidentDetail(id) {
    const inc = state.incidents.find((i) => i.id === id);
    if (!inc) return;
    const panel = document.getElementById("detail-panel");
    panel.innerHTML = "";
    panel.appendChild(el("h3", {}, [inc.name]));
    panel.appendChild(el("div", { class: "chips" }, [
      chip(inc.status, "badge-" + inc.status),
      chip(CATEGORIES[inc.category] || inc.category),
    ]));
    panel.appendChild(el("p", {}, [inc.summary]));

    const dl = el("dl", {}, []);
    const addList = (label, arr) => {
      if (!arr || !arr.length) return;
      dl.appendChild(el("dt", {}, [label]));
      const ul = el("ul", {}, []);
      arr.forEach((x) => ul.appendChild(el("li", {}, [x])));
      dl.appendChild(el("dd", {}, [ul]));
    };
    dl.appendChild(el("dt", {}, ["Facility"])); dl.appendChild(el("dd", {}, [inc.facility_type]));
    dl.appendChild(el("dt", {}, ["Date / location"])); dl.appendChild(el("dd", {}, [inc.date + " — " + inc.country + " (" + inc.location_precision + ")"]));
    addList("Initial access", inc.initial_access);
    addList("Affected assets", inc.affected_assets);
    addList("Attacker actions", inc.actions);
    addList("Impact", inc.impact);
    dl.appendChild(el("dt", {}, ["Impact types"]));
    dl.appendChild(el("dd", {}, [el("div", { class: "chips" }, (inc.impact_types || []).map((t) => chip(IMPACT_TYPES[t] || t, "chip-impact")))]));
    dl.appendChild(el("dt", {}, ["Technologies"])); dl.appendChild(el("dd", {}, [inc.technologies.join(", ")]));
    dl.appendChild(el("dt", {}, ["Protocols"])); dl.appendChild(el("dd", {}, [inc.protocols.join(", ")]));
    dl.appendChild(el("dt", {}, ["MITRE ATT&CK"]));
    dl.appendChild(el("dd", {}, [el("div", { class: "chips" },
      inc.mitre_attack.map((m) => chip(m.technique_id + " " + m.technique_name, "chip-mitre")))]));

    const events = state.timeline.filter((e) => e.incident_id === inc.id);
    if (events.length) {
      dl.appendChild(el("dt", {}, ["Timeline events"]));
      const ul = el("ul", { class: "event-links" }, []);
      events.forEach((e) => {
        const a = el("a", { href: "#timeline" }, [e.date_label + " — " + e.title]);
        a.addEventListener("click", (ev) => { ev.preventDefault(); showTimelineDetail(e); });
        ul.appendChild(el("li", {}, [a]));
      });
      dl.appendChild(el("dd", {}, [ul]));
    }
    panel.appendChild(dl);

    inc.source_references.forEach((ref) => panel.appendChild(sourceLine(ref)));
  }

  // --------------------------------------------------------------------- //
  function renderPathSwitch() {
    const box = document.getElementById("path-switch");
    box.innerHTML = "";
    state.paths.forEach((p, i) => {
      const b = el("button", { class: i === state.activePathIndex ? "active" : "" }, [p.name]);
      b.addEventListener("click", () => { state.activePathIndex = i; renderPathSwitch(); renderAttackPath(); });
      box.appendChild(b);
    });
  }

  function renderLegend() {
    const box = document.getElementById("zone-legend");
    box.innerHTML = "";
    Object.keys(ZONES).forEach((z) => {
      box.appendChild(el("span", { class: "item" }, [
        el("span", { class: "swatch", style: "background:" + ZONES[z].color }, []), ZONES[z].label,
      ]));
    });
    // node border = outcome
    box.appendChild(el("span", { class: "legend-sep" }, ["Border:"]));
    Object.keys(OUTCOMES).forEach((o) => {
      box.appendChild(el("span", { class: "item" }, [
        el("span", { class: "swatch swatch-outline outcome-" + o }, []), OUTCOMES[o],
      ]));
    });
  }

  const OUTCOME_STROKE = {
    success: { color: "#0a1628", dash: "0" },
    attempted: { color: "var(--orange)", dash: "5 3" },
    blocked: { color: "var(--green)", dash: "0" },
    unknown: { color: "var(--text-dim)", dash: "2 3" },
  };

  // Graph geometry (viewBox units).
  const G = { boxW: 168, boxH: 54, colGap: 192, rowGap: 104, pad: 40 };

  // Hop distance from the entry node(s), used as the row of each node so the
  // graph reads top-to-bottom in attack order.
  function nodeDepths(path) {
    const incoming = new Set(path.edges.map((e) => e.to));
    const out = {};
    path.edges.forEach((e) => { (out[e.from] = out[e.from] || []).push(e.to); });
    const depth = {};
    const queue = path.nodes.filter((n) => !incoming.has(n.id)).map((n) => n.id);
    queue.forEach((id) => { depth[id] = 0; });
    while (queue.length) {
      const id = queue.shift();
      (out[id] || []).forEach((t) => { if (depth[t] == null) { depth[t] = depth[id] + 1; queue.push(t); } });
    }
    path.nodes.forEach((n) => { if (depth[n.id] == null) depth[n.id] = 0; });
    return depth;
  }

  // Default ("slot") position of every node: one row per hop, centered.
  function layeredLayout(path) {
    const depth = nodeDepths(path);
    const rows = {};
    path.nodes.forEach((n) => { (rows[depth[n.id]] = rows[depth[n.id]] || []).push(n.id); });
    const maxPerRow = Math.max.apply(null, Object.values(rows).map((r) => r.length));
    const W = Math.max(760, maxPerRow * G.colGap + G.pad * 2);
    const nRows = Object.keys(rows).length;
    const H = G.pad * 2 + G.boxH + (nRows - 1) * G.rowGap;
    const slots = {};
    Object.keys(rows).forEach((d) => {
      const ids = rows[d];
      ids.forEach((id, k) => {
        slots[id] = { x: W / 2 + (k - (ids.length - 1) / 2) * G.colGap, y: G.pad + G.boxH / 2 + d * G.rowGap, depth: +d };
      });
    });
    return { slots, W, H, nRows };
  }

  // Where the segment from a's center to b's center enters b's (padded) box.
  function boxEntry(a, b) {
    const dx = a.x - b.x, dy = a.y - b.y;
    const hw = G.boxW / 2 + 4, hh = G.boxH / 2 + 4;
    const s = Math.min(hw / (Math.abs(dx) || 1e-6), hh / (Math.abs(dy) || 1e-6));
    return s >= 1 ? { x: b.x, y: b.y } : { x: b.x + dx * s, y: b.y + dy * s };
  }

  function fitText(textEl, maxW) {
    const full = textEl.textContent;
    if (textEl.getComputedTextLength() <= maxW) return;
    let s = full;
    while (s.length > 1 && textEl.getComputedTextLength() > maxW) {
      s = s.slice(0, -1);
      textEl.textContent = s + "…";
    }
  }

  function renderAttackPath() {
    const path = state.paths[state.activePathIndex];
    const box = document.getElementById("attack-path");
    state.graphNodes = null; state.graphLinks = null;
    box.innerHTML = "";
    if (!path) { box.appendChild(el("p", { class: "col-hint" }, ["No attack path available."])); return; }
    if (!HAS_D3) { renderPathFallback(path, box); return; }

    const btn = (label, title) => el("button", { type: "button", class: "path-btn", title: title, "aria-label": title }, [label]);
    const zoomOut = btn("−", "Zoom out"), zoomIn = btn("+", "Zoom in"), fitBtn = btn("Fit", "Fit graph to view");
    const resetBtn = btn("Reset layout", "Put all nodes back in attack order");
    const fsBtn = btn("⛶ Full screen", "Show the graph full screen");
    box.appendChild(el("div", { class: "path-toolbar" }, [
      el("span", { class: "col-hint" }, ["Top to bottom = attack order. Drag nodes · arrow keys move a focused node · double-click returns it · scroll to zoom."]),
      el("div", { class: "path-btns" }, [zoomOut, zoomIn, fitBtn, resetBtn, fsBtn]),
    ]));
    box.appendChild(el("p", { id: "path-hidden-note", class: "path-note hidden" },
      ["This path's incident is excluded by the current filters."]));

    const { slots, W, H, nRows } = layeredLayout(path);
    const saved = state.layouts[path.id] || {};
    // Fresh node objects (never mutate the dataset): saved position, else its slot.
    const nodes = path.nodes.map((n) => Object.assign({}, n, saved[n.id] || { x: slots[n.id].x, y: slots[n.id].y }));
    const byId = {};
    nodes.forEach((n) => { byId[n.id] = n; });
    const links = path.edges.filter((e) => byId[e.from] && byId[e.to])
      .map((e) => ({ from: e.from, to: e.to, label: e.label, source: byId[e.from], target: byId[e.to] }));

    const svg = d3.select(box).append("svg").attr("class", "path-graph").attr("viewBox", `0 0 ${W} ${H}`)
      .attr("role", "img").attr("aria-label", path.name);
    svg.append("defs").append("marker").attr("id", "arrow").attr("viewBox", "0 0 10 10").attr("refX", 9).attr("refY", 5)
      .attr("markerWidth", 7).attr("markerHeight", 7).attr("orient", "auto-start-reverse")
      .append("path").attr("d", "M0,0 L10,5 L0,10 z").attr("fill", "var(--edge)");

    const root = svg.append("g"); // pan/zoom container

    // Faint row guides with step numbers, so the attack order stays visible.
    const slotXs = Object.values(slots).map((s) => s.x);
    const guideX = Math.min.apply(null, slotXs) - G.boxW / 2 - 14;
    const guideEnd = Math.max.apply(null, slotXs) + G.boxW / 2 + 14;
    const guides = root.append("g").attr("class", "row-guides");
    for (let d = 0; d < nRows; d++) {
      const y = G.pad + G.boxH / 2 + d * G.rowGap;
      guides.append("line").attr("x1", guideX + 6).attr("x2", guideEnd).attr("y1", y).attr("y2", y);
      guides.append("text").attr("x", guideX).attr("y", y + 4).attr("text-anchor", "end")
        .text(d === 0 ? "Entry" : "Step " + d);
    }

    const linkG = root.append("g").selectAll("g").data(links).enter().append("g").attr("class", "edge-g");
    const linkLine = linkG.append("line").attr("class", "edge-line");
    const linkLabel = linkG.append("text").attr("class", "edge-label").attr("text-anchor", "middle").text((d) => d.label);

    const neighbors = {};
    links.forEach((l) => {
      (neighbors[l.from] = neighbors[l.from] || new Set()).add(l.to);
      (neighbors[l.to] = neighbors[l.to] || new Set()).add(l.from);
    });
    let node; // assigned below; focus() is only called after that
    const focus = (n) => {
      node.classed("faded", (m) => !!n && m.id !== n.id && !(neighbors[n.id] || new Set()).has(m.id));
      linkG.classed("faded", (l) => !!n && l.from !== n.id && l.to !== n.id);
    };

    const save = () => {
      state.layouts[path.id] = {};
      nodes.forEach((n) => { state.layouts[path.id][n.id] = { x: n.x, y: n.y }; });
    };
    const moveTo = (n, x, y) => {
      n.x = Math.max(G.boxW / 2, Math.min(W - G.boxW / 2, x));
      n.y = Math.max(G.boxH / 2, Math.min(H - G.boxH / 2, y));
    };
    const toSlot = (n) => { n.x = slots[n.id].x; n.y = slots[n.id].y; };

    node = root.append("g").selectAll(".node-g").data(nodes).enter().append("g")
      .attr("class", "node-g").attr("tabindex", 0).attr("role", "button")
      .attr("aria-label", (n) => `${n.label}: ${OUTCOMES[n.outcome] || n.outcome}. Arrow keys move it.`)
      .on("click", (ev, n) => { if (!n.__dragged) selectNode(n, path); })
      .on("keydown", (ev, n) => {
        const step = ev.shiftKey ? 40 : 10;
        const moves = { ArrowLeft: [-step, 0], ArrowRight: [step, 0], ArrowUp: [0, -step], ArrowDown: [0, step] };
        if (ev.key === "Enter") selectNode(n, path);
        else if (moves[ev.key]) {
          ev.preventDefault();
          moveTo(n, n.x + moves[ev.key][0], n.y + moves[ev.key][1]);
          draw(); save();
        }
      })
      .on("mouseenter focus", (ev, n) => focus(n))
      .on("mouseleave blur", () => focus(null))
      .on("dblclick", (ev, n) => { ev.stopPropagation(); toSlot(n); draw(300); save(); });

    node.append("title").text((n) => `${n.label} — ${n.role}`);
    node.append("rect").attr("class", "node-rect")
      .attr("x", -G.boxW / 2).attr("y", -G.boxH / 2).attr("width", G.boxW).attr("height", G.boxH).attr("rx", 7)
      .attr("fill", (n) => ZONES[n.zone] ? ZONES[n.zone].color : "#555")
      .attr("stroke", (n) => (OUTCOME_STROKE[n.outcome] || OUTCOME_STROKE.success).color)
      .attr("stroke-dasharray", (n) => (OUTCOME_STROKE[n.outcome] || OUTCOME_STROKE.success).dash)
      .attr("stroke-width", (n) => n.outcome === "success" ? 2 : 3);
    const tx = -G.boxW / 2 + 9, maxText = G.boxW - 18;
    node.append("text").attr("class", "node-label").attr("x", tx).attr("y", -G.boxH / 2 + 18).text((n) => n.label)
      .each(function () { fitText(this, maxText); });
    node.append("text").attr("class", "node-sub").attr("x", tx).attr("y", -G.boxH / 2 + 33).text((n) => n.service)
      .each(function () { fitText(this, maxText); });
    node.append("text").attr("class", "node-sub node-status").attr("x", tx).attr("y", -G.boxH / 2 + 46)
      .text((n) => n.confidence + " · " + (OUTCOMES[n.outcome] || n.outcome).toLowerCase());
    state.graphNodes = node;
    state.graphLinks = linkG;

    function draw(ms) {
      const t = (sel) => (ms ? sel.transition().duration(ms) : sel);
      t(linkLine)
        .attr("x1", (d) => d.source.x).attr("y1", (d) => d.source.y)
        .attr("x2", (d) => boxEntry(d.source, d.target).x).attr("y2", (d) => boxEntry(d.source, d.target).y);
      t(linkLabel)
        .attr("x", (d) => (d.source.x + d.target.x) / 2)
        .attr("y", (d) => (d.source.y + d.target.y) / 2 + 4);
      t(node).attr("transform", (d) => `translate(${d.x},${d.y})`);
    }
    draw();

    node.call(d3.drag()
      .on("start", (ev, d) => { d.__dragged = false; })
      .on("drag", (ev, d) => { d.__dragged = true; moveTo(d, ev.x, ev.y); draw(); })
      .on("end", (ev, d) => { if (d.__dragged) save(); }));

    const zoom = d3.zoom().scaleExtent([0.3, 3]).on("zoom", (ev) => root.attr("transform", ev.transform));
    svg.call(zoom).on("dblclick.zoom", null); // dblclick is used to return a node to its slot

    function fit(ms) {
      const xs = nodes.map((n) => n.x), ys = nodes.map((n) => n.y);
      // Left margin includes the step labels next to the guides.
      const x0 = Math.min(Math.min.apply(null, xs) - G.boxW / 2 - 20, guideX - 52);
      const x1 = Math.max.apply(null, xs) + G.boxW / 2 + 20;
      const y0 = Math.min.apply(null, ys) - G.boxH / 2 - 24, y1 = Math.max.apply(null, ys) + G.boxH / 2 + 20;
      const k = Math.min(3, W / (x1 - x0), H / (y1 - y0));
      const tr = d3.zoomIdentity.translate(W / 2 - k * (x0 + x1) / 2, H / 2 - k * (y0 + y1) / 2).scale(k);
      (ms ? svg.transition().duration(ms) : svg).call(zoom.transform, tr);
    }
    fit();

    zoomIn.addEventListener("click", () => svg.transition().duration(200).call(zoom.scaleBy, 1.25));
    zoomOut.addEventListener("click", () => svg.transition().duration(200).call(zoom.scaleBy, 0.8));
    fitBtn.addEventListener("click", () => fit(300));
    resetBtn.addEventListener("click", () => {
      delete state.layouts[path.id];
      nodes.forEach(toSlot);
      draw(300);
      fit(300);
    });
    const panel = box.closest(".col-center");
    fsBtn.addEventListener("click", () => {
      if (document.fullscreenElement) document.exitFullscreen();
      else if (panel.requestFullscreen) panel.requestFullscreen();
    });
    if (!panel.requestFullscreen) fsBtn.classList.add("hidden");

    applyGraphHighlight();
    renderFilterResult();
  }

  function selectNode(n, path) {
    if (state.graphNodes) state.graphNodes.classed("selected", (m) => m.id === n.id);
    showNodeDetail(n, path);
  }

  function renderPathFallback(path, box) {
    box.appendChild(el("p", { class: "col-hint" }, ["Text view (D3 unavailable). Click a node for details."]));
    path.nodes.forEach((n) => {
      const node = el("div", { class: "path-fallback-node" }, [
        el("strong", {}, [n.label]), " — " + (ZONES[n.zone] ? ZONES[n.zone].label : n.zone),
        el("div", { class: "col-hint" }, [n.service + " · " + n.confidence + " · " + (OUTCOMES[n.outcome] || n.outcome)]),
      ]);
      node.style.borderLeftColor = ZONES[n.zone] ? ZONES[n.zone].color : "#555";
      node.addEventListener("click", () => showNodeDetail(n, path));
      box.appendChild(node);
    });
    // edges as arrows
    box.appendChild(el("p", { class: "col-hint" }, [
      "Flow: " + path.nodes.map((n) => n.label).join("  →  "),
    ]));
  }

  function showNodeDetail(n, path) {
    const panel = document.getElementById("detail-panel");
    panel.innerHTML = "";
    panel.appendChild(el("h3", {}, [n.label]));
    const zoneColor = ZONES[n.zone] ? ZONES[n.zone].color : "#555";
    panel.appendChild(el("div", { class: "chips" }, [
      el("span", { class: "zone-chip", style: "background:" + zoneColor }, [ZONES[n.zone] ? ZONES[n.zone].label : n.zone]),
      el("span", { class: "conf-tag conf-" + n.confidence, title: "How certain the evidence is" }, ["Evidence: " + n.confidence]),
      el("span", { class: "conf-tag outcome-tag outcome-" + n.outcome, title: "What the action achieved" }, [OUTCOMES[n.outcome] || n.outcome]),
      chip(PHASES[n.phase] || n.phase),
    ]));
    const dl = el("dl", {}, []);
    const row = (k, v) => { dl.appendChild(el("dt", {}, [k])); dl.appendChild(el("dd", {}, [v || "—"])); };
    row("Role", n.role);
    row("Observed activity", n.activity);
    row("Service / protocol", n.service);
    row("Impact", n.impact);
    row("Part of path", path.name);
    panel.appendChild(dl);
    panel.appendChild(sourceLine(n.source));
  }

  // --------------------------------------------------------------------- //
  // ---- Timeline ---------------------------------------------------------- //
  // Each event gets a number (chronological order of the filtered list). The
  // chart shows numbered markers in one lane per incident; the list below
  // carries the same numbers with full text. No text labels on the chart, so
  // nothing can overlap.
  const TL_ZOOMS = {
    dec: { from: new Date(2025, 11, 1), to: new Date(2026, 0, 1), ticks: () => d3.timeDay.every(2), fmt: "%d %b" },
    all: { from: new Date(2025, 2, 1), to: new Date(2026, 0, 1), ticks: () => d3.timeMonth.every(1), fmt: "%b %Y" },
  };
  const TL = { laneH: 48, left: 132, right: 24, top: 22, axisH: 28, W: 1100, r: 9, rowOffset: 16 };

  function buildTimelineZoom() {
    const btns = document.querySelectorAll("#timeline-zoom button");
    btns.forEach((b) => b.addEventListener("click", () => setTimelineZoom(b.getAttribute("data-zoom"))));
  }

  function setTimelineZoom(z) {
    state.timelineZoom = z;
    document.querySelectorAll("#timeline-zoom button").forEach((o) =>
      o.classList.toggle("active", o.getAttribute("data-zoom") === z));
    renderTimeline();
  }

  function dayOf(s) { const p = s.split("-").map(Number); return new Date(p[0], p[1] - 1, p[2]); }

  function eventColor(e) {
    if (e.outcome === "blocked") return "var(--green)";
    if (e.outcome === "attempted") return "var(--orange)";
    if (e.outcome === "unknown") return "var(--text-dim)";
    if (e.phase === "impact") return "var(--red)";
    return "var(--tl-neutral)";
  }

  function laneLabel(id) {
    const inc = state.incidents.find((i) => i.id === id);
    return inc ? inc.short_name || inc.name : "Campaign-wide";
  }

  function showTip(ev, text) {
    const tip = document.getElementById("tooltip");
    tip.textContent = text;
    tip.classList.remove("hidden");
    const x = Math.min(ev.clientX + 14, window.innerWidth - tip.offsetWidth - 8);
    tip.style.left = x + "px";
    tip.style.top = ev.clientY + 14 + "px";
  }
  function hideTip() { document.getElementById("tooltip").classList.add("hidden"); }

  function selectEvent(e) {
    document.querySelectorAll(".tl-item").forEach((li) =>
      li.classList.toggle("active", li.getAttribute("data-id") === e.id));
    document.querySelectorAll(".tl-marker").forEach((m) =>
      m.classList.toggle("active", (m.getAttribute("data-ids") || "").split(" ").includes(e.id)));
    showTimelineDetail(e);
  }

  function renderTimeline() {
    const box = document.getElementById("timeline");
    box.innerHTML = "";
    hideTip();
    const numbered = filteredTimeline().map((e, i) => ({ e: e, n: i + 1 }));
    renderTimelineList(numbered);
    renderTimelineLegend();
    if (!numbered.length) {
      box.appendChild(el("p", { class: "col-hint" }, ["No timeline events match the current filters."]));
      return;
    }
    if (!HAS_D3) {
      box.appendChild(el("p", { class: "col-hint" }, ["Chart unavailable without D3; see the event list below."]));
      return;
    }

    const zoom = TL_ZOOMS[state.timelineZoom] || TL_ZOOMS.dec;
    const laneIds = state.incidents.map((i) => i.id).concat([null])
      .filter((id) => numbered.some((x) => (x.e.incident_id || null) === id));
    const H = TL.top + laneIds.length * TL.laneH + TL.axisH;
    const x = d3.scaleTime().domain([zoom.from, zoom.to]).range([TL.left, TL.W - TL.right]);
    const dayW = x(d3.timeDay.offset(zoom.from, 1)) - x(zoom.from);

    const svg = d3.select(box).append("svg").attr("class", "tl-chart").attr("viewBox", `0 0 ${TL.W} ${H}`)
      .attr("role", "img").attr("aria-label", "Attack timeline");
    svg.append("defs").append("clipPath").attr("id", "tl-clip").append("rect")
      .attr("x", TL.left).attr("y", 0).attr("width", TL.W - TL.left - TL.right).attr("height", H);

    // Lanes
    laneIds.forEach((id, i) => {
      const y = TL.top + i * TL.laneH;
      svg.append("rect").attr("class", "tl-lane" + (i % 2 ? " odd" : ""))
        .attr("x", TL.left).attr("y", y).attr("width", TL.W - TL.left - TL.right).attr("height", TL.laneH);
      svg.append("text").attr("class", "tl-lane-label").attr("x", TL.left - 10).attr("y", y + TL.laneH / 2 + 4)
        .attr("text-anchor", "end").text(laneLabel(id));
    });

    // Axis + month/day grid
    const axisY = TL.top + laneIds.length * TL.laneH;
    // Drop the tick at the window's end (it would collide with the one before).
    const ticks = x.ticks(zoom.ticks()).filter((d) => d < zoom.to);
    svg.append("g").attr("class", "tl-axis").attr("transform", `translate(0,${axisY})`)
      .call(d3.axisBottom(x).tickValues(ticks).tickFormat(d3.timeFormat(zoom.fmt)).tickSizeOuter(0));
    svg.append("g").attr("class", "tl-grid").selectAll("line").data(ticks).enter().append("line")
      .attr("x1", (d) => x(d)).attr("x2", (d) => x(d)).attr("y1", TL.top).attr("y2", axisY);

    // Attack day
    const attack = new Date(2025, 11, 29);
    const ax = x(attack) + (state.timelineZoom === "dec" ? dayW / 2 : 0);
    svg.append("line").attr("class", "tl-attack-day").attr("x1", ax).attr("x2", ax).attr("y1", TL.top - 6).attr("y2", axisY);
    const nearEdge = ax > TL.W - TL.right - 60;
    svg.append("text").attr("class", "tl-attack-label").attr("x", nearEdge ? ax + 4 : ax).attr("y", TL.top - 9)
      .attr("text-anchor", nearEdge ? "end" : "middle").text("29 Dec – attacks");

    const plot = svg.append("g").attr("clip-path", "url(#tl-clip)");

    // Place markers: per lane, try rows (center, above, below); merge into a
    // "+N" cluster when no row is free.
    const rows = [0, -TL.rowOffset, TL.rowOffset];
    const minGap = TL.r * 2 + 2;
    const markers = [];
    numbered.forEach((item) => {
      const e = item.e;
      const start = dayOf(e.date);
      const end = d3.timeDay.offset(dayOf(e.date_end || e.date), 1);
      if (end <= zoom.from || start >= zoom.to) return; // outside the window
      const lane = laneIds.indexOf(e.incident_id || null);
      const yMid = TL.top + lane * TL.laneH + TL.laneH / 2;
      const cx = Math.max(TL.left + TL.r, e.date_end ? x(start) : x(start) + dayW / 2);
      const laneMarkers = markers.filter((m) => m.lane === lane);
      // A row is free when no existing marker's circle would touch this one.
      const row = rows.find((off) => laneMarkers.every((m) => Math.hypot(m.cx - cx, m.row - off) >= minGap));
      if (row === undefined) {
        const near = laneMarkers.reduce((a, m) => (Math.abs(m.cx - cx) < Math.abs(a.cx - cx) ? m : a));
        near.items.push(item);
        return;
      }
      markers.push({ lane: lane, row: row, cx: cx, cy: yMid + row, items: [item], endX: e.date_end ? x(end) : null });
    });

    // Period bars behind the markers
    plot.selectAll(".tl-bar").data(markers.filter((m) => m.endX)).enter().append("rect")
      .attr("class", "tl-bar").attr("x", (m) => m.cx).attr("y", (m) => m.cy - 3)
      .attr("width", (m) => Math.max(2, m.endX - m.cx)).attr("height", 6).attr("rx", 3)
      .attr("fill", (m) => eventColor(m.items[0].e));

    const g = plot.selectAll(".tl-marker").data(markers).enter().append("g")
      .attr("class", "tl-marker").attr("tabindex", 0).attr("role", "button")
      .attr("data-ids", (m) => m.items.map((it) => it.e.id).join(" "))
      .attr("transform", (m) => `translate(${m.cx},${m.cy})`)
      .attr("aria-label", (m) => m.items.length > 1
        ? `${m.items.length} events, zoom in`
        : `${m.items[0].n}. ${m.items[0].e.date_label}: ${m.items[0].e.title}`);

    const activate = (m) => {
      if (m.items.length > 1) {
        if (state.timelineZoom !== "dec") setTimelineZoom("dec");
        else selectEvent(m.items[0].e);
      } else {
        selectEvent(m.items[0].e);
      }
    };
    g.on("click", (ev, m) => activate(m))
      .on("keydown", (ev, m) => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); activate(m); } })
      .on("mousemove", (ev, m) => showTip(ev, m.items.length > 1
        ? m.items.map((it) => `${it.n}. ${it.e.date_label} — ${it.e.title}`).join("\n") + "\nClick to zoom in."
        : `${m.items[0].n}. ${m.items[0].e.date_label}\n${m.items[0].e.title}\n(${m.items[0].e.precision})`))
      .on("mouseleave", hideTip);

    g.append("circle").attr("r", TL.r)
      .attr("class", (m) => "tl-dot" + (m.items.length === 1 && m.items[0].e.precision === "approximate" ? " approx" : ""))
      .attr("fill", (m) => m.items.length > 1 ? "var(--panel-2)" : eventColor(m.items[0].e))
      .attr("stroke", (m) => m.items.length > 1 || m.items[0].e.precision === "approximate"
        ? eventColor(m.items[0].e) : "var(--bg)");
    g.append("text").attr("class", "tl-num").attr("text-anchor", "middle").attr("dy", "0.35em")
      .text((m) => m.items.length > 1 ? "+" + m.items.length : m.items[0].n);
  }

  function renderTimelineList(numbered) {
    const list = document.getElementById("timeline-list");
    list.innerHTML = "";
    const ol = el("ol", { class: "tl-list" }, []);
    numbered.forEach((item) => {
      const e = item.e;
      const li = el("li", { class: "tl-item", "data-id": e.id, tabindex: "0" }, [
        el("span", { class: "tl-n", style: "background:" + eventColor(e) }, [String(item.n)]),
        el("span", { class: "tl-date" }, [e.date_label]),
        el("span", { class: "tl-lane-tag" }, [laneLabel(e.incident_id || null)]),
        el("span", { class: "tl-title" }, [e.title]),
        chip(e.precision, "chip-prec"),
      ]);
      li.addEventListener("click", () => selectEvent(e));
      li.addEventListener("keydown", (ev) => { if (ev.key === "Enter") selectEvent(e); });
      ol.appendChild(li);
    });
    if (!numbered.length) list.appendChild(el("p", { class: "col-hint" }, ["No events."]));
    else list.appendChild(ol);
  }

  function renderTimelineLegend() {
    const box = document.getElementById("timeline-legend");
    box.innerHTML = "";
    const item = (sw, label) => box.appendChild(el("span", { class: "item" }, [sw, label]));
    const dot = (color, ring) => el("span", { class: "swatch", style: ring
      ? `border:2px solid ${color};border-radius:50%;background:transparent`
      : `background:${color};border-radius:50%` }, []);
    item(dot("var(--red)"), "Destructive impact");
    item(dot("var(--orange)"), "Attempted / failed");
    item(dot("var(--green)"), "Blocked by defenses");
    item(dot("var(--tl-neutral)"), "Other activity");
    item(dot("var(--tl-neutral)", true), "Approximate time");
    item(el("span", { class: "swatch", style: "height:6px;width:20px;border-radius:3px;background:var(--tl-neutral)" }, []), "Period");
    item(el("span", { class: "swatch", style: "background:var(--panel-2);border:2px solid var(--tl-neutral);border-radius:50%" }, []), "+N = grouped, click to zoom");
  }

  function showTimelineDetail(e) {
    const panel = document.getElementById("detail-panel");
    panel.innerHTML = "";
    panel.appendChild(el("h3", {}, [e.title]));
    panel.appendChild(el("span", { class: "conf-tag conf-" + e.confidence }, [e.confidence]));
    const dl = el("dl", {}, []);
    dl.appendChild(el("dt", {}, ["When"])); dl.appendChild(el("dd", {}, [e.date_label + "  (" + e.precision + ")"]));
    dl.appendChild(el("dt", {}, ["What"])); dl.appendChild(el("dd", {}, [e.description]));
    const inc = state.incidents.find((i) => i.id === e.incident_id);
    if (inc) { dl.appendChild(el("dt", {}, ["Incident"])); dl.appendChild(el("dd", {}, [inc.name])); }
    panel.appendChild(dl);
    (e.source_references || []).forEach((ref) => panel.appendChild(sourceLine(ref)));
  }

  // --------------------------------------------------------------------- //
  function renderTable() {
    const tbody = document.querySelector("#asset-table tbody");
    tbody.innerHTML = "";
    filteredIncidents().forEach((inc) => {
      const tr = el("tr", {}, [
        el("td", {}, [inc.name]),
        el("td", {}, [el("span", { class: "badge badge-" + inc.status }, [inc.status])]),
        el("td", {}, [inc.affected_assets.slice(0, 4).join("; ") + (inc.affected_assets.length > 4 ? "…" : "")]),
        el("td", {}, [inc.technologies.join(", ")]),
        el("td", {}, [inc.protocols.join(", ")]),
        el("td", {}, [inc.impact.slice(0, 3).join("; ")]),
      ]);
      tr.style.cursor = "pointer";
      tr.addEventListener("click", () => selectIncident(inc.id));
      tbody.appendChild(tr);
    });
  }

  function renderMitre() {
    const box = document.getElementById("mitre-list");
    box.innerHTML = "";
    const seen = {};
    filteredIncidents().forEach((inc) => inc.mitre_attack.forEach((m) => {
      const key = m.framework + m.technique_id;
      if (seen[key]) return; seen[key] = 1;
      box.appendChild(el("div", { class: "mitre-chip" }, [
        el("span", { class: "fw" }, [m.framework]),
        el("div", {}, [el("span", { class: "tid" }, [m.technique_id]), " " + m.technique_name]),
      ]));
    }));
    if (!box.children.length) box.appendChild(el("p", { class: "col-hint" }, ["No techniques match the current filters."]));
  }

  function renderSources() {
    const ul = document.getElementById("source-list");
    ul.innerHTML = "";
    (state.metadata.sources || []).forEach((s) => {
      const li = el("li", {}, [
        el("a", { href: `/reports/${s.id}`, target: "_blank", rel: "noopener" }, [s.title]),
        " — " + s.publisher + " (" + s.file + ")",
      ]);
      if (s.url) {
        li.appendChild(document.createTextNode(" · "));
        li.appendChild(el("a", { href: s.url, target: "_blank", rel: "noopener" }, ["original publication"]));
      }
      ul.appendChild(li);
    });
  }

  document.addEventListener("DOMContentLoaded", init);
})();
