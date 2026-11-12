/* LogGrok AI (Graylog Edition) - front-end */

const qs = (sel) => document.querySelector(sel);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g,
  (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const STORAGE_KEY = "ai-grok-builder:v1";
const THEME_KEY = "ai-grok-builder:theme";

const state = {
  sample: "",
  ranges: [],
  config: {
    name: "AI generated grok rule",
    description: "",
    condition: "always",
    condition_field: "",
    condition_value: "",
    condition_regex: "",
    source_field: "message",
  },
  fields: {},
  fieldsSample: "",
  inputTitle: "",
  model: "",
  names: [],
  preview: null,
  editingIndex: null,
  creating: null,
  autoguard: "",
};

/* ---------------------------------------------------------------- helpers */

let toastTimer = null;
function toast(msg, isError = false) {
  const t = qs("#toast");
  t.textContent = msg;
  t.classList.toggle("toast-error", isError);
  t.classList.remove("d-none");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.add("d-none"), 3500);
}

function savedTheme() {
  try { return localStorage.getItem(THEME_KEY); } catch (_) { return null; }
}

function applyTheme(theme, persist = true) {
  const dark = theme === "dark";
  document.documentElement.setAttribute("data-bs-theme", dark ? "dark" : "light");
  const btn = qs("#btn-theme");
  if (btn) {
    btn.innerHTML = dark ? "&#9728; Light" : "&#127769; Dark";
    btn.title = dark ? "Switch to light mode" : "Switch to dark mode";
    btn.setAttribute("aria-pressed", dark ? "true" : "false");
  }
  if (persist) {
    try { localStorage.setItem(THEME_KEY, dark ? "dark" : "light"); } catch (_) {}
  }
}

function toggleTheme() {
  const dark = document.documentElement.getAttribute("data-bs-theme") === "dark";
  applyTheme(dark ? "light" : "dark");
}

async function api(path, body) {
  const resp = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  let data = {};
  try { data = await resp.json(); } catch (_) { /* no body */ }
  if (!resp.ok || data.error) {
    const err = new Error(data.error || `HTTP ${resp.status}`);
    err.data = data;
    throw err;
  }
  return data;
}

async function apiGet(path) {
  const resp = await fetch(path);
  let data = {};
  try { data = await resp.json(); } catch (_) { /* no body */ }
  if (!resp.ok || data.error) throw new Error(data.error || `HTTP ${resp.status}`);
  return data;
}

const slice = (r) => state.sample.slice(r.start, r.end);
const NAME_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

function persist() {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify({
      sample: state.sample,
      inputTitle: state.inputTitle,
      ranges: state.ranges,
      config: state.config,
      fields: state.fields,
      fieldsSample: state.fieldsSample,
      autoguard: state.autoguard,
      model: qs("#model-input").value,
      context: qs("#context")?.value || "",
      max_repairs: qs("#max-repairs")?.value || "1",
      enrich: !!document.getElementById("chk-enrich")?.checked,
    }));
  } catch (_) { /* storage full/blocked - non fatal */ }
}

function restore() {
  let saved;
  try { saved = JSON.parse(localStorage.getItem(STORAGE_KEY) || "null"); }
  catch (_) { return; }
  if (!saved) return;
  if (typeof saved.sample === "string") {
    state.sample = saved.sample;
    qs("#sample").value = saved.sample;
  }
  if (typeof saved.inputTitle === "string") state.inputTitle = saved.inputTitle;
  if (Array.isArray(saved.ranges)) {
    state.ranges = saved.ranges.filter(
      (r) => r && Number.isInteger(r.start) && Number.isInteger(r.end));
  }
  if (saved.config && typeof saved.config === "object") {
    Object.assign(state.config, saved.config);
  }
  if (typeof saved.autoguard === "string") state.autoguard = saved.autoguard;
  if (saved.fields && typeof saved.fields === "object" && !Array.isArray(saved.fields)) {
    state.fields = saved.fields;
    state.fieldsSample = typeof saved.fieldsSample === "string" ? saved.fieldsSample : "";
  }
  if (saved.model) state.model = saved.model;
  if (typeof saved.context === "string") {
    const c = qs("#context"); if (c) c.value = saved.context;
  }
  if (typeof saved.max_repairs === "string") {
    const r = qs("#max-repairs"); if (r) r.value = saved.max_repairs;
  }
  if (typeof saved.enrich === "boolean") {
    const e = document.getElementById("chk-enrich"); if (e) e.checked = saved.enrich;
  }
  writeConfigToForm();
}

/* ---------------------------------------------------------------- rendering */

function setMatchBadge(prev) {
  const b = qs("#match-badge");
  b.className = "badge text-bg-secondary";
  if (!prev || !state.sample) { b.textContent = "no pattern yet"; return; }
  const n = Object.keys(prev.fields || {}).length;
  if (prev.compile_error) {
    b.classList.add("text-bg-danger");
    b.textContent = "error";
    b.title = prev.compile_error;
  } else if (prev.status === "full") {
    b.classList.add("text-bg-success");
    b.textContent = `full match · ${n} field${n === 1 ? "" : "s"}`;
    b.title = "";
  } else if (prev.status === "partial") {
    b.classList.add("text-bg-warning");
    b.textContent = `partial match · ${n} field${n === 1 ? "" : "s"}`;
    b.title = "Pattern does not cover the whole sample";
  } else {
    b.classList.add("text-bg-danger");
    b.textContent = "no match";
    b.title = "";
  }
}

function renderWarnings(list, compileError) {
  const box = qs("#warnings");
  const items = [...(list || [])];
  let html = "";
  if (compileError) {
    html += `<div class="text-danger">${esc(compileError)}</div>`;
  }
  for (const w of items) html += `<div class="text-warning-emphasis">${esc(w)}</div>`;
  box.innerHTML = html || '<span class="text-secondary">No issues.</span>';
}

function renderCanvas() {
  const c = qs("#canvas");
  c.innerHTML = "";
  if (!state.sample) {
    c.innerHTML = '<span class="text-secondary">No sample yet. Paste a log line or fetch one from Graylog.</span>';
    return;
  }
  const sorted = [...state.ranges].sort((a, b) => a.start - b.start);
  let pos = 0;
  for (const r of sorted) {
    if (r.start < pos) continue; // safety against overlaps
    if (r.start > pos) c.appendChild(document.createTextNode(state.sample.slice(pos, r.start)));
    const span = document.createElement("span");
    span.className = "hl";
    span.textContent = state.sample.slice(r.start, r.end);
    span.title = `${r.key} · ${r.pattern}`;
    span.dataset.idx = String(state.ranges.indexOf(r));
    span.addEventListener("click", (e) => {
      e.stopPropagation();
      openEdit(Number(span.dataset.idx), span);
    });
    c.appendChild(span);
    pos = r.end;
  }
  if (pos < state.sample.length) c.appendChild(document.createTextNode(state.sample.slice(pos)));
}

function renderFields() {
  const tbody = qs("#fields-body");
  if (!state.ranges.length) {
    tbody.innerHTML = '<tr><td colspan="3" class="text-secondary small p-3">No captures yet.</td></tr>';
    return;
  }
  tbody.innerHTML = "";
  state.ranges.forEach((r, i) => {
    const tr = document.createElement("tr");
    tr.style.cursor = "pointer";
    tr.innerHTML = `<td class="font-monospace">${esc(r.key)}</td>` +
      `<td class="small">${esc(r.pattern)}</td>` +
      `<td class="font-monospace text-truncate" style="max-width:9rem" title="${esc(slice(r))}">${esc(slice(r))}</td>`;
    tr.addEventListener("click", (e) => {
      e.stopPropagation();
      const el = qs(`#canvas .hl[data-idx="${i}"]`);
      if (el) {
        el.scrollIntoView({ block: "center", behavior: "smooth" });
        el.classList.add("flash");
        setTimeout(() => el.classList.remove("flash"), 1300);
      }
      openEdit(i, el || tr);
    });
    tbody.appendChild(tr);
  });
}

let refreshTimer = null;
function scheduleRefresh() {
  clearTimeout(refreshTimer);
  refreshTimer = setTimeout(refresh, 250);
}

function renderExistingFields() {
  const wrap = qs("#existing-fields-wrap");
  const tbody = qs("#existing-fields-body");
  const fields = state.fields || {};
  const keys = Object.keys(fields).sort((a, b) => a.localeCompare(b));
  if (!keys.length) {
    wrap.classList.add("d-none");
    tbody.innerHTML = "";
    return;
  }
  const ordered = keys.filter((k) => k !== "message");
  if (keys.includes("message")) ordered.unshift("message");
  wrap.classList.remove("d-none");
  tbody.innerHTML = "";
  for (const k of ordered) {
    const v = fields[k];
    const disp = typeof v === "object" && v !== null ? JSON.stringify(v) : String(v);
    const isMessage = k === "message";
    const captured = !isMessage && state.ranges.some((r) => r.key === k);
    const tr = document.createElement("tr");
    if (isMessage) {
      tr.className = "text-secondary";
      tr.title = "The raw message text - not capturable";
    } else {
      tr.style.cursor = "pointer";
      if (captured) tr.classList.add("table-active");
      tr.title = captured ? "Click to remove this capture" : "Click to add as a capture";
      tr.addEventListener("click", () => toggleFieldCapture(k, v));
    }
    tr.innerHTML = `<td class="font-monospace small">${captured ? "&#10003; " : ""}${esc(k)}</td>` +
      `<td class="font-monospace small text-truncate" style="max-width:12rem" ` +
      `title="${esc(disp)}">${esc(disp)}</td>`;
    tbody.appendChild(tr);
  }
}

async function toggleFieldCapture(key, value) {
  const idx = state.ranges.findIndex((r) => r.key === key);
  if (idx >= 0) {
    state.ranges.splice(idx, 1);
    renderFields();
    renderExistingFields();
    scheduleRefresh();
    return;
  }
  if (!state.sample) return toast("No sample loaded", true);
  const text = String(value ?? "");
  if (!text) return toast("That field has no value to capture", true);
  const start = state.sample.indexOf(text);
  if (start < 0) return toast(`"${text.slice(0, 40)}" is not in the sample`, true);
  const end = start + text.length;
  if (state.ranges.some((r) => !(end <= r.start || start >= r.end))) {
    return toast("That text overlaps an existing capture", true);
  }
  try {
    const out = await api("/api/captures/from-fields", {
      sample: state.sample, fields: { [key]: value },
    });
    const r = (out.ranges || [])[0];
    if (!r) return toast("Could not turn that field into a capture", true);
    state.ranges.push(r);
    renderFields();
    renderExistingFields();
    scheduleRefresh();
  } catch (e) {
    toast(e.message, true);
  }
}

function conditionFieldNames() {
  const names = [];
  for (const k of Object.keys(state.fields || {})) if (k !== "message") names.push(k);
  for (const r of state.ranges) if (r.key && r.key !== "message") names.push(r.key);
  return [...new Set(names)].sort((a, b) => a.localeCompare(b));
}

function renderConditionFields() {
  const sel = qs("#cfg-cond-field");
  let current = state.config.condition_field || "";
  if (current === "message") current = ""; // the message field is always present
  const names = conditionFieldNames();
  sel.innerHTML = "";
  if (!names.length && !current) {
    sel.innerHTML = '<option value="">(no fields yet - fetch a message or add captures)</option>';
    return;
  }
  if (current && !names.includes(current)) names.unshift(current);
  for (const n of names) {
    const o = document.createElement("option");
    o.value = n;
    o.textContent = n;
    sel.appendChild(o);
  }
  sel.value = current || names[0];
}

async function refresh() {
  closePop();
  renderCanvas();
  renderFields();
  renderExistingFields();
  renderConditionFields();
  if (!state.sample) {
    qs("#grok-out").value = "";
    qs("#rule-out").value = "";
    setMatchBadge(null);
    renderWarnings([]);
    persist();
    return;
  }
  try {
    const out = await api("/api/render", {
      sample: state.sample, ranges: state.ranges, config: state.config,
    });
    state.preview = out;
    qs("#grok-out").value = out.grok || "";
    qs("#rule-out").value = out.rule || "";
    setMatchBadge(out);
    renderWarnings(out.warnings, out.compile_error);
  } catch (e) {
    setMatchBadge(null);
    renderWarnings([], e.message);
  }
  persist();
}

/* ---------------------------------------------------------------- popover */

function showPop(rect) {
  const pop = qs("#capture-pop");
  pop.classList.remove("d-none");
  const vw = window.innerWidth;
  const top = rect ? rect.bottom + window.scrollY + 6 : window.scrollY + 120;
  const left = rect ? Math.min(rect.left + window.scrollX, vw - 320) : 40;
  pop.style.top = `${top}px`;
  pop.style.left = `${Math.max(8, left)}px`;
  qs("#pop-error").classList.add("d-none");
  qs("#pop-key").focus();
}

function openEdit(index, anchorEl) {
  state.editingIndex = index;
  state.creating = null;
  const r = state.ranges[index];
  qs("#pop-title").textContent = "Edit capture";
  qs("#pop-range").textContent = `“${slice(r)}”`;
  qs("#pop-key").value = r.key;
  qs("#pop-pattern").value = r.pattern;
  qs("#pop-delete").classList.remove("d-none");
  showPop(anchorEl && anchorEl.getBoundingClientRect ? anchorEl.getBoundingClientRect() : null);
}

function openCreate(start, end, rect) {
  state.editingIndex = null;
  state.creating = { start, end };
  qs("#pop-title").textContent = "Create capture";
  qs("#pop-range").textContent = `“${state.sample.slice(start, end)}”`;
  qs("#pop-key").value = "";
  qs("#pop-pattern").value = "GREEDYDATA";
  qs("#pop-delete").classList.add("d-none");
  showPop(rect || null);
}

function closePop() {
  qs("#capture-pop").classList.add("d-none");
  state.editingIndex = null;
  state.creating = null;
}

function popError(msg) {
  const el = qs("#pop-error");
  el.textContent = msg;
  el.classList.remove("d-none");
}

function savePop() {
  const key = qs("#pop-key").value.trim();
  const pattern = qs("#pop-pattern").value.trim();
  if (!NAME_RE.test(key)) return popError("Key must match [A-Za-z_][A-Za-z0-9_]*");
  if (!NAME_RE.test(pattern)) return popError("Pattern must match [A-Za-z_][A-Za-z0-9_]*");
  if (state.editingIndex !== null) {
    const r = state.ranges[state.editingIndex];
    r.key = key;
    r.pattern = pattern;
  } else if (state.creating) {
    state.ranges.push({ key, pattern, start: state.creating.start, end: state.creating.end });
  }
  closePop();
  scheduleRefresh();
}

function deleteCapture() {
  if (state.editingIndex === null) return;
  state.ranges.splice(state.editingIndex, 1);
  closePop();
  scheduleRefresh();
}

/* ---------------------------------------------------------------- config form */

function writeConfigToForm() {
  qs("#cfg-name").value = state.config.name;
  qs("#cfg-desc").value = state.config.description;
  qs("#cfg-cond").value = state.config.condition;
  qs("#cfg-cond-value").value = state.config.condition_value;
  qs("#cfg-cond-regex").value = state.config.condition_regex;
  qs("#cfg-source-field").value = state.config.source_field;
  renderConditionFields();
  syncConditionVisibility();
}

function readConfigFromForm() {
  state.config = {
    name: qs("#cfg-name").value.trim() || "AI generated grok rule",
    description: qs("#cfg-desc").value,
    condition: qs("#cfg-cond").value,
    condition_field: qs("#cfg-cond-field").value.trim(),
    condition_value: qs("#cfg-cond-value").value,
    condition_regex: qs("#cfg-cond-regex").value,
    source_field: qs("#cfg-source-field").value.trim() || "message",
  };
  syncConditionVisibility();
}

function syncConditionVisibility() {
  const c = qs("#cfg-cond").value;
  qs("#cond-field").classList.toggle("d-none", c !== "has_field" && c !== "contains");
  qs("#cond-value").classList.toggle("d-none", c !== "contains");
  qs("#cond-regex").classList.toggle("d-none", c !== "regex");
}

/* ---------------------------------------------------------------- startup data */

function setBadge(el, ok, label, title) {
  const b = qs(el);
  b.className = `badge text-bg-${ok ? "success" : "danger"}`;
  b.textContent = label;
  b.title = title || "";
}

async function loadHealth() {
  try {
    const h = await apiGet("/api/health");
    setBadge("#badge-ollama", h.ollama.ok, h.ollama.ok ? "Ollama online" : "Ollama offline",
      h.ollama.error || "");
    setBadge("#badge-graylog", h.graylog.ok,
      h.graylog.ok ? "Graylog online" : (h.graylog.configured ? "Graylog error" : "Graylog off"),
      h.graylog.error || "");
  } catch (e) {
    setBadge("#badge-ollama", false, "Ollama unknown", e.message);
  }
}

async function loadModels() {
  const sel = qs("#model-input");
  try {
    const data = await apiGet("/api/ollama/models");
    const prev = state.model || sel.value;
    sel.innerHTML = "";
    for (const m of data.models) {
      const opt = document.createElement("option");
      opt.value = m.id;
      opt.textContent = m.label || m.id;
      sel.appendChild(opt);
    }
    if (!data.models.length) {
      sel.innerHTML = '<option value="">no models found</option>';
    } else {
      const ids = data.models.map((m) => m.id);
      const pick = [prev, data.default, state.model].find((v) => v && ids.includes(v));
      sel.value = pick || ids[0];
      state.model = sel.value;
    }
    return data.models.length;
  } catch (e) {
    sel.innerHTML = '<option value="">Ollama unreachable</option>';
    toast(`Could not list models: ${e.message}`, true);
    return 0;
  }
}

async function loadPatterns() {
  try {
    const data = await apiGet("/api/patterns");
    state.names = data.names;
    const dl = qs("#patterns-list");
    dl.innerHTML = "";
    for (const name of data.names) {
      const opt = document.createElement("option");
      opt.value = name;
      dl.appendChild(opt);
    }
    const synced = (data.synced || []).length;
    qs("#catalog-count").textContent = `${data.names.length} patterns` +
      (synced ? ` (${synced} synced)` : "");
  } catch (e) {
    qs("#catalog-count").textContent = "catalog unavailable";
  }
}

/* ---------------------------------------------------------------- actions */

async function doGenerate() {
  const sample = qs("#sample").value;
  if (!sample.trim()) return toast("Paste a log line first", true);
  state.sample = sample;
  state.ranges = [];
  const status = qs("#generate-status");
  status.textContent = "asking model…";
  qs("#generate-warnings").innerHTML = "";
  try {
    const out = await api("/api/generate", {
      sample, model: qs("#model-input").value.trim(),
      context: qs("#context")?.value || "",
      max_repairs: parseInt(qs("#max-repairs")?.value, 10) || 0,
      enrich: !!document.getElementById("chk-enrich")?.checked,
    });
    state.ranges = Array.isArray(out.ranges) ? out.ranges : [];
    if (out.suggested_name) {
      const parts = [];
      if (state.inputTitle) parts.push(state.inputTitle);
      parts.push(out.suggested_name);
      qs("#cfg-name").value = parts.join(" - ");
    }
    if (out.suggested_description) qs("#cfg-desc").value = out.suggested_description;
    // Apply the model's message-matching guard unless the user set their own
    // condition. Re-proposes a fresh guard on re-generate when the current one
    // came from us; manual edits to the condition clear that state.
    const canReplaceGuard =
      state.config.condition === "always" ||
      (state.config.condition === "regex" &&
       state.config.condition_regex === state.autoguard);
    if (out.guard && canReplaceGuard) {
      qs("#cfg-cond").value = "regex";
      qs("#cfg-cond-regex").value = out.guard;
      state.autoguard = out.guard;
    }
    readConfigFromForm();
    const verified = out.status === "full" ? "full match"
      : `not fully matching (${out.status})`;
    status.textContent = `${out.ranges.length} captures from ${out.model} - ${verified}` +
      (out.repaired ? ", auto-repaired" : "") +
      (out.enriched ? ", enriched" : "") +
      (out.guard ? `, message guard: ${out.guard}` : "") +
      (out.examples_used ? `, ${out.examples_used} examples` : "") +
      (out.attempts > 1 ? ` [${out.attempts} calls]` : "");
    const warn = out.warnings || [];
    qs("#generate-warnings").innerHTML = warn.length
      ? warn.map((w) => `<div class="text-warning-emphasis">${esc(w)}</div>`).join("")
      : "";
    scheduleRefresh();
  } catch (e) {
    status.textContent = "";
    const d = e.data || {};
    let html = `<div class="text-danger">${esc(e.message)}</div>`;
    for (const w of d.warnings || []) html += `<div class="text-warning-emphasis">${esc(w)}</div>`;
    if (d.raw) html += `<details class="mt-1"><summary class="small">raw model output</summary><pre class="small">${esc(d.raw)}</pre></details>`;
    qs("#generate-warnings").innerHTML = html;
  }
}

/* ------------------------------------------------------------------ search */

function messagesStatusText(out) {
  // `filtered` says whether the server compared anything against rules.
  if (out.filtered === false) {
    return `${out.messages.length} message(s)` + (out.notice ? ` (${out.notice})` : "");
  }
  const parts = [`${out.messages.length} with no rule yet`];
  if (out.covered) parts.push(`${out.covered} already covered`);
  if (out.scanned) parts.push(`scanned ${out.scanned}`);
  if (out.rules_used) parts.push(`${out.rules_used} rules`);
  if (out.unparsed_rules) {
    parts.push(`${out.unparsed_rules} rules unreadable`);
  }
  let text = parts.join(" · ");
  if (out.notice) text += ` (${out.notice})`;
  if (!out.messages.length && out.exhausted) {
    text = `every one of the ${out.scanned || 0} scanned messages already ` +
      "has a rule - widen the time range or the query";
  }
  return text;
}

async function doSearchMessages() {
  const status = qs("#msg-status");
  const list = qs("#messages-list");
  status.textContent = "searching…";
  list.innerHTML = "";
  const onlyUncovered = !!document.getElementById("msg-only-uncovered")?.checked;
  try {
    const payload = {
      query: qs("#msg-query").value.trim() || "*",
      range: Number(qs("#msg-range").value),
      limit: Number(qs("#msg-limit").value),
    };
    if (onlyUncovered) {
      payload.require_unmatched = true;
      payload.max_scan = Number(qs("#msg-scan").value) || 300;
    } else {
      payload.require_unmatched = false;
    }
    const out = await api("/api/messages", payload);
    status.textContent = messagesStatusText(out);
    for (const m of out.messages) {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "msg-item";
      const inputTag = m.input_title ? `[${m.input_title}] ` : "";
      btn.textContent = `[${m.timestamp || "?"}] ${inputTag}${m.message || "(no message field)"}`;
      btn.addEventListener("click", async () => {
        const sample = m.message || "";
        qs("#sample").value = sample;
        state.sample = sample;
        state.ranges = [];
        state.inputTitle = m.input_title || "";
        updatePipelineOption();
        if (state.config.condition === "regex" &&
            state.config.condition_regex === state.autoguard) {
          // a guard freshly applied by AI no longer matches a new sample
          qs("#cfg-cond").value = "always";
          qs("#cfg-cond-regex").value = "";
        }
        state.autoguard = "";
        state.fields = (m.fields && typeof m.fields === "object") ? m.fields : {};
        state.fieldsSample = sample;
        if (state.inputTitle) qs("#cfg-name").value = state.inputTitle;
        readConfigFromForm();
        const ctx = qs("#context");
        if (ctx) {
          const kept = (ctx.value || "").split("\n")
            .filter((l) => !/^Graylog input:/.test(l.trim()));
          if (m.input_title) kept.unshift(`Graylog input: ${m.input_title}`);
          ctx.value = kept.join("\n").trim();
        }
        bootstrap.Modal.getInstance(qs("#messages-modal"))?.hide();
        try {
          const out = await api("/api/captures/from-fields", { sample, fields: state.fields });
          state.ranges = Array.isArray(out.ranges) ? out.ranges : [];
        } catch (e) {
          toast(`Auto-capture failed: ${e.message}`, true);
        }
        scheduleRefresh();
        const n = state.ranges.length;
        toast(n ? `Sample loaded - ${n} field capture${n === 1 ? "" : "s"} created`
                : "Sample loaded - no fields matched the text");
      });
      list.appendChild(btn);
    }
  } catch (e) {
    status.textContent = "";
    toast(e.message, true);
  }
}

async function doRuleParse() {
  readConfigFromForm();
  const status = qs("#rule-status");
  status.textContent = "validating…";
  status.className = "small align-self-center text-secondary";
  try {
    await api("/api/rule/parse", {
      sample: state.sample, ranges: state.ranges, config: state.config,
    });
    status.className = "small align-self-center text-success";
    status.textContent = "Graylog accepted the rule syntax";
  } catch (e) {
    status.className = "small align-self-center text-danger";
    status.textContent = e.message;
  }
}

async function doGrokTest() {
  const status = qs("#rule-status");
  status.textContent = "testing…";
  status.className = "small align-self-center text-secondary";
  try {
    const out = await api("/api/graylog/grok-test", {
      sample: state.sample, ranges: state.ranges,
    });
    status.className = "small align-self-center text-success";
    status.textContent = "Graylog grok test: " + JSON.stringify(out.result).slice(0, 300);
  } catch (e) {
    status.className = "small align-self-center text-danger";
    status.textContent = e.message;
  }
}

async function doRuleSimulate() {
  readConfigFromForm();
  if (!state.sample) return toast("No sample / pattern yet", true);
  const status = qs("#rule-status");
  status.textContent = "simulating…";
  status.className = "small align-self-center text-secondary";
  try {
    const out = await api("/api/rule/simulate", {
      sample: state.sample, ranges: state.ranges, config: state.config,
    });
    status.className = "small align-self-center text-success";
    status.textContent = "Graylog simulation: " +
      JSON.stringify(out.simulated || {}).slice(0, 300);
    const missing = out.missing_fields || [];
    if (missing.length) {
      status.className = "small align-self-center text-warning";
      status.textContent = `simulation produced none of: ${missing.join(", ")}`
        + " - the rule may never match";
    }
  } catch (e) {
    status.className = "small align-self-center text-danger";
    status.textContent = e.message;
    toast(e.message, true);
  }
}

async function doCheckDuplicates() {
  readConfigFromForm();
  if (!state.sample) return toast("No sample / pattern yet", true);
  const status = qs("#rule-status");
  status.textContent = "checking duplicates…";
  status.className = "small align-self-center text-secondary";
  try {
    const out = await api("/api/rule/duplicates", {
      sample: state.sample, ranges: state.ranges, config: state.config,
    });
    renderDupResult(out);
  } catch (e) {
    status.className = "small align-self-center text-danger";
    status.textContent = e.message;
    toast(e.message, true);
  }
}

function renderDupResult(out) {
  const status = qs("#rule-status");
  const exact = out.exact || [];
  const similar = out.similar || [];
  if (!exact.length && !similar.length) {
    status.classList.remove("text-danger");
    status.className = "small align-self-center text-success";
    status.textContent = `no duplicates among ${out.checked || 0} existing rules`;
    toast(`No existing rule matches${out.checked ? ` (checked ${out.checked})` : ""}`);
    return;
  }
  const names = [
    ...exact.map((m) => `"${m.title}" (identical)`),
    ...similar.map((m) => `"${m.title}" (${Math.round((m.score || 0) * 100)}% match)`),
  ];
  status.className = "small align-self-center text-warning";
  status.textContent = `${names.length} possible duplicate${names.length > 1 ? "s" : ""}`;
  toast(`Possible duplicates:\n${names.join("\n")}`, true);
}

function dupConfirmText(pipelineName) {
  return new Promise(async (resolve) => {
    readConfigFromForm();
    let duplicates = "";
    try {
      const out = await api("/api/rule/duplicates", {
        sample: state.sample, ranges: state.ranges, config: state.config,
      });
      const names = [
        ...(out.exact || []).map((m) => `- "${m.title}"  [identical]`),
        ...(out.similar || []).map((m) =>
          `- "${m.title}"  [${Math.round((m.score || 0) * 100)}% match]`),
      ];
      if (names.length)
        duplicates = `\n\nPossible duplicate${names.length > 1 ? "s" : ""} exist:\n` +
          names.join("\n");
    } catch (_e) {
      // Graylog unreachable etc.; proceed with the plain confirmation.
    }
    let msg = `Create rule "${state.config.name}" in Graylog?`;
    if (pipelineName) msg += `\n\n(Also add to pipeline "${pipelineName}" stage 0)`;
    msg += duplicates;
    resolve(confirm(msg));
  });
}

async function doPush() {
  readConfigFromForm();
  if (!state.sample) return toast("No sample / pattern yet", true);
  const pipelineName = (qs("#chk-pipeline")?.checked) ? state.inputTitle || "" : "";
  if (!await dupConfirmText(pipelineName)) return;
  const status = qs("#rule-status");
  status.textContent = "pushing…";
  status.className = "small align-self-center text-secondary";
  try {
    const out = await api("/api/rule/push", {
      sample: state.sample, ranges: state.ranges, config: state.config,
      pipeline_name: pipelineName || undefined,
    });
    status.className = "small align-self-center text-success";
    status.textContent = `created rule "${out.title}"` +
      (out.learned === false
        ? " - not saved as a learned example (pattern is not a full match)"
        : "");
    if (out.simulation_warning) {
      toast(out.simulation_warning, true);
      status.textContent += " - Graylog simulation warning";
    }
    const p = out.pipeline;
    if (p) {
      if (p.error) {
        toast(`Rule created, but pipeline add failed: ${p.error}`, true);
      } else if (p.already_present) {
        toast(`Rule already in pipeline "${p.title}" stage 0`);
      } else {
        toast(`Pushed rule + added to pipeline "${p.title}" stage 0`);
      }
    } else {
      toast("Rule pushed to Graylog");
    }
    loadExamples();
  } catch (e) {
    status.className = "small align-self-center text-danger";
    status.textContent = e.message;
  }
}

async function doSyncPatterns() {
  const status = qs("#catalog-count");
  status.textContent = "syncing…";
  try {
    const out = await api("/api/patterns/sync", {});
    await loadPatterns();
    toast(`Synced ${out.count} patterns from Graylog`);
  } catch (e) {
    await loadPatterns();
    toast(e.message, true);
  }
}

/* ---------------------------------------------------------------- graylog fields */

state.fields_available = [];

function updatePipelineOption() {
  const wrap = qs("#pipeline-push-wrap");
  if (!wrap) return;
  if (state.inputTitle) {
    qs("#pipeline-target").textContent = state.inputTitle;
    wrap.classList.remove("d-none");
  } else {
    wrap.classList.add("d-none");
    qs("#chk-pipeline").checked = false;
  }
}

function setFieldsCount(count) {
  qs("#fields-count").textContent = count ? `${count} in Graylog` : "";
  qs("#fields-modal-count").textContent = count ? `(${count})` : "";
}

function renderFieldsList() {
  const wrap = qs("#fields-list");
  const filter = (qs("#fields-filter").value || "").trim().toLowerCase();
  const names = state.fields_available.filter(
    (n) => !filter || n.toLowerCase().includes(filter));
  wrap.innerHTML = "";
  if (!names.length) {
    wrap.innerHTML = `<span class="text-secondary small">` +
      `${state.fields_available.length ? "No match." : "No fields loaded."}</span>`;
    return;
  }
  for (const n of names) {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "btn btn-sm btn-outline-secondary py-0 px-2 font-monospace";
    b.textContent = n;
    b.title = "Copy field name";
    b.addEventListener("click", () => {
      if (navigator.clipboard) navigator.clipboard.writeText(n);
      toast(`Copied "${n}"`);
    });
    wrap.appendChild(b);
  }
}

async function loadFields(refresh = false) {
  const status = qs("#fields-status");
  status.textContent = refresh ? "refreshing…" : "loading…";
  try {
    const out = await apiGet("/api/graylog/fields" + (refresh ? "?refresh=1" : ""));
    state.fields_available = Array.isArray(out.fields) ? out.fields : [];
    status.textContent = `${state.fields_available.length} field(s)`;
    setFieldsCount(state.fields_available.length);
    renderFieldsList();
  } catch (e) {
    status.textContent = e.message;
  }
}

/* ---------------------------------------------------------------- examples */

state.examples = [];

async function apiDelete(path) {
  const resp = await fetch(path, { method: "DELETE" });
  let data = {};
  try { data = await resp.json(); } catch (_) { /* no body */ }
  if (!resp.ok || data.error) throw new Error(data.error || `HTTP ${resp.status}`);
  return data;
}

function setExamplesCount(count, inPrompt) {
  const label = `${count} saved${inPrompt !== undefined ? ` · ${inPrompt} in prompt` : ""}`;
  qs("#examples-count").textContent = label;
  qs("#ex-modal-count").textContent = `(${count})`;
}

function renderExamples() {
  const tbody = qs("#examples-body");
  if (!state.examples.length) {
    tbody.innerHTML = '<tr><td colspan="4" class="text-secondary small p-3">' +
      'No examples yet. Save the current sample or push a rule to Graylog.</td></tr>';
    return;
  }
  tbody.innerHTML = "";
  for (const ex of state.examples) {
    const caps = (ex.segments || []).filter((s) => s.type === "capture");
    const keys = caps.map((c) => c.key).join(", ");
    const tr = document.createElement("tr");
    const sample = ex.sample || "";
    const preview = sample.length > 120 ? sample.slice(0, 120) + "…" : sample;
    tr.innerHTML =
      `<td class="font-monospace small" title="${esc(sample)}">${esc(preview)}</td>` +
      `<td class="small text-truncate" style="max-width:14rem" title="${esc(keys)}">` +
      `${caps.length} &middot; ${esc(keys)}</td>` +
      `<td class="small text-secondary">${esc(ex.source || "manual")}</td>` +
      `<td class="text-nowrap">` +
      `<button class="btn btn-sm btn-outline-secondary py-0 px-1" data-ex-edit="${esc(ex.id)}">Edit</button> ` +
      `<button class="btn btn-sm btn-outline-danger py-0 px-1" data-ex-del="${esc(ex.id)}">Delete</button>` +
      `</td>`;
    tbody.appendChild(tr);
  }
  tbody.querySelectorAll("[data-ex-edit]").forEach((b) =>
    b.addEventListener("click", () => openExampleForm(b.dataset.exEdit)));
  tbody.querySelectorAll("[data-ex-del]").forEach((b) =>
    b.addEventListener("click", () => deleteExample(b.dataset.exDel)));
}

async function loadExamples() {
  try {
    const data = await apiGet("/api/examples");
    state.examples = data.examples || [];
    setExamplesCount(state.examples.length, data.in_prompt);
    renderExamples();
    return state.examples;
  } catch (e) {
    toast(`Could not load examples: ${e.message}`, true);
    return [];
  }
}

function segmentsFromRanges() {
  const sorted = [...state.ranges].sort((a, b) => a.start - b.start);
  const out = [];
  let pos = 0;
  for (const r of sorted) {
    if (r.start < pos) continue;
    if (r.start > pos) out.push({ type: "text", value: state.sample.slice(pos, r.start) });
    out.push({ type: "capture", key: r.key, pattern: r.pattern,
      value: state.sample.slice(r.start, r.end) });
    pos = r.end;
  }
  if (pos < state.sample.length) out.push({ type: "text", value: state.sample.slice(pos) });
  return out;
}

function openExampleForm(id) {
  const form = qs("#example-form");
  form.classList.remove("d-none");
  qs("#example-form-error").textContent = "";
  if (id) {
    const ex = state.examples.find((e) => e.id === id);
    if (!ex) return;
    qs("#example-form-title").textContent = `Edit example ${id}`;
    qs("#ex-sample").value = ex.sample || "";
    qs("#ex-segments").value = JSON.stringify({ segments: ex.segments || [] }, null, 2);
    form.dataset.id = id;
  } else {
    qs("#example-form-title").textContent = "Add example";
    qs("#ex-sample").value = "";
    qs("#ex-segments").value = "";
    delete form.dataset.id;
  }
}

function closeExampleForm() {
  qs("#example-form").classList.add("d-none");
  delete qs("#example-form").dataset.id;
}

async function saveExampleForm() {
  const sample = qs("#ex-sample").value;
  let segments;
  try {
    const parsed = JSON.parse(qs("#ex-segments").value || "{}");
    segments = Array.isArray(parsed) ? parsed : parsed.segments;
  } catch (e) {
    qs("#example-form-error").textContent = `Invalid JSON: ${e.message}`;
    return;
  }
  if (!Array.isArray(segments) || !segments.length) {
    qs("#example-form-error").textContent = "Segments must be a non-empty array";
    return;
  }
  const id = qs("#example-form").dataset.id;
  try {
    if (id) await api(`/api/examples/${id}`, { sample, segments });
    else await api("/api/examples", { sample, segments });
    closeExampleForm();
    await loadExamples();
    toast(id ? "Example updated" : "Example added");
  } catch (e) {
    qs("#example-form-error").textContent = e.message;
  }
}

async function saveCurrentExample() {
  if (!state.sample || !state.ranges.length) {
    return toast("No sample and captures to save yet", true);
  }
  try {
    await api("/api/examples", { sample: state.sample, ranges: state.ranges });
    await loadExamples();
    toast("Saved current pattern as an example");
  } catch (e) {
    toast(e.message, true);
  }
}

async function deleteExample(id) {
  if (!confirm("Delete this example?")) return;
  try {
    await apiDelete(`/api/examples/${id}`);
    await loadExamples();
    toast("Example deleted");
  } catch (e) {
    toast(e.message, true);
  }
}

async function clearExamples() {
  if (!confirm("Delete ALL saved examples?")) return;
  try {
    const out = await api("/api/examples/clear", {});
    await loadExamples();
    toast(`Cleared ${out.removed} example(s)`);
  } catch (e) {
    toast(e.message, true);
  }
}

/* ---------------------------------------------------------------- wire up */

function init() {
  restore();
  applyTheme(document.documentElement.getAttribute("data-bs-theme") || "light", false);
  const themeMedia = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;
  if (themeMedia) {
    themeMedia.addEventListener?.("change", (e) => {
      if (!savedTheme()) applyTheme(e.matches ? "dark" : "light", false);
    });
  }
  qs("#btn-theme").addEventListener("click", toggleTheme);

  qs("#btn-generate").addEventListener("click", doGenerate);
  qs("#btn-clear").addEventListener("click", () => {
    state.sample = "";
    state.ranges = [];
    state.fields = {};
    state.fieldsSample = "";
    state.inputTitle = "";
    qs("#sample").value = "";
    qs("#generate-warnings").innerHTML = "";
    qs("#generate-status").textContent = "";
    updatePipelineOption();
    scheduleRefresh();
  });
  qs("#btn-model-refresh").addEventListener("click", async () => {
    const n = await loadModels();
    if (n) toast(`Found ${n} model${n === 1 ? "" : "s"} in Ollama`);
  });
  qs("#btn-msg-search").addEventListener("click", doSearchMessages);
  const scanToggle = () => {
    const wrap = qs("#msg-scan-wrap");
    const on = !!document.getElementById("msg-only-uncovered")?.checked;
    wrap.classList.toggle("d-none", !on);
  };
  scanToggle();
  document.getElementById("msg-only-uncovered")?.addEventListener("change", scanToggle);
  qs("#btn-parse").addEventListener("click", doRuleParse);
  qs("#btn-simulate").addEventListener("click", doRuleSimulate);
  qs("#btn-grok-test").addEventListener("click", doGrokTest);
  qs("#btn-dup").addEventListener("click", doCheckDuplicates);
  qs("#btn-push").addEventListener("click", doPush);
  qs("#btn-sync-patterns").addEventListener("click", doSyncPatterns);
  qs("#btn-view-fields").addEventListener("click", () => {
    if (!state.fields_available.length) loadFields();
  });
  qs("#btn-fields-refresh").addEventListener("click", () => loadFields(true));
  qs("#fields-filter").addEventListener("input", renderFieldsList);
  qs("#btn-save-example").addEventListener("click", saveCurrentExample);
  qs("#btn-example-add-current").addEventListener("click", async () => {
    await saveCurrentExample();
    await loadExamples();
  });
  qs("#btn-examples-refresh").addEventListener("click", loadExamples);
  qs("#btn-examples-clear").addEventListener("click", clearExamples);
  qs("#btn-example-fill").addEventListener("click", () => {
    if (!state.sample || !state.ranges.length) return toast("No current sample/captures", true);
    qs("#ex-sample").value = state.sample;
    qs("#ex-segments").value = JSON.stringify({ segments: segmentsFromRanges() }, null, 2);
  });
  qs("#btn-example-save").addEventListener("click", saveExampleForm);
  qs("#btn-example-cancel").addEventListener("click", closeExampleForm);
  qs("#btn-add-capture").addEventListener("click", () => {
    toast("Select the text in the sample you want to capture", true);
  });

  qs("#sample").addEventListener("input", () => {
    const val = qs("#sample").value;
    if (val === state.sample) return;
    state.sample = val;
    state.inputTitle = "";
    updatePipelineOption();
    if (state.ranges.length) {
      state.ranges = [];
      toast("Sample changed - captures cleared");
    }
    if (state.fieldsSample && val !== state.fieldsSample) {
      state.fields = {};
      state.fieldsSample = "";
    }
    scheduleRefresh();
  });

  for (const id of ["#cfg-name", "#cfg-desc", "#cfg-cond", "#cfg-cond-field",
    "#cfg-cond-value", "#cfg-cond-regex", "#cfg-source-field"]) {
    const onEdit = () => {
      if (id === "#cfg-cond" || id === "#cfg-cond-regex") state.autoguard = "";
      readConfigFromForm(); scheduleRefresh();
    };
    qs(id).addEventListener("input", onEdit);
    qs(id).addEventListener("change", onEdit);
  }

  qs("#pop-save").addEventListener("click", savePop);
  qs("#pop-delete").addEventListener("click", deleteCapture);
  qs("#pop-cancel").addEventListener("click", closePop);
  qs("#pop-key").addEventListener("keydown", (e) => { if (e.key === "Enter") savePop(); });
  qs("#pop-pattern").addEventListener("keydown", (e) => { if (e.key === "Enter") savePop(); });

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closePop();
  });
  document.addEventListener("click", (e) => {
    const pop = qs("#capture-pop");
    if (pop.classList.contains("d-none")) return;
    if (pop.contains(e.target)) return;
    if (e.target.closest && e.target.closest("#canvas")) return;
    closePop();
  });

  document.querySelectorAll("[data-copy]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const el = document.getElementById(btn.dataset.copy);
      try {
        await navigator.clipboard.writeText(el.value);
        toast("Copied to clipboard");
      } catch (_) {
        el.select();
        document.execCommand("copy");
        toast("Copied to clipboard");
      }
    });
  });

  const canvas = qs("#canvas");
  canvas.addEventListener("mouseup", () => {
    setTimeout(() => {
      const sel = window.getSelection();
      if (!sel || sel.isCollapsed || !sel.rangeCount) return;
      const range = sel.getRangeAt(0);
      if (!canvas.contains(range.startContainer) || !canvas.contains(range.endContainer)) return;
      const pre = document.createRange();
      pre.selectNodeContents(canvas);
      pre.setEnd(range.startContainer, range.startOffset);
      const start = pre.toString().length;
      const pre2 = document.createRange();
      pre2.selectNodeContents(canvas);
      pre2.setEnd(range.endContainer, range.endOffset);
      const end = pre2.toString().length;
      if (!state.sample || start >= end) return;
      if (state.ranges.some((r) => !(end <= r.start || start >= r.end))) {
        toast("Selection overlaps an existing capture", true);
        sel.removeAllRanges();
        return;
      }
      const rect = range.getBoundingClientRect();
      sel.removeAllRanges();
      openCreate(start, end, rect);
    }, 0);
  });

  renderCanvas();
  renderFields();
  renderExistingFields();
  renderConditionFields();
  loadHealth();
  loadModels();
  loadPatterns();
  loadExamples();
  loadFields();
  updatePipelineOption();
  readConfigFromForm();
  if (state.sample) refresh();
}

document.addEventListener("DOMContentLoaded", init);
