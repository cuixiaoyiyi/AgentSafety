"""Generate a single self-contained English HTML reading-guide for the whole project.

Left pane = collapsible file tree; right pane = file viewer (Markdown rendered, code
and data shown verbatim).  The landing page summarizes the overall process, results,
and conclusions, with numbers pulled live from the metric JSONs so it never drifts.

    python -m capagent.experiments.build_guide
    -> writes INDEX.html at the paper-folder root.
"""
from __future__ import annotations

import html
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.dirname(HERE)                       # capagent/capagent
PROJ = os.path.dirname(PKG)                        # capagent/
PAPER_ROOT = os.path.dirname(PROJ)                 # the paper folder
OUT_HTML = os.path.join(PAPER_ROOT, "INDEX.html")

TEXT_EXT = {".py", ".md", ".yaml", ".yml", ".json", ".csv", ".txt", ".capagent",
            ".toml", ".cfg", ".ini", ".gitignore"}
SKIP_DIRS = {"_repos", "__pycache__", ".git", ".pytest_cache", "node_modules"}
SKIP_FILES = {"INDEX.html"}
MAX_BYTES = 600_000


def _included(rel: str) -> bool:
    parts = rel.replace("\\", "/").split("/")
    if any(p in SKIP_DIRS for p in parts):
        return False
    if os.path.basename(rel) in SKIP_FILES:
        return False
    ext = os.path.splitext(rel)[1].lower()
    base = os.path.basename(rel).lower()
    return ext in TEXT_EXT or base in (".gitignore",)


def collect_files():
    files = {}
    # top-level docs beside the package
    for top in ("capagent_implementation_plan.md",):
        p = os.path.join(PAPER_ROOT, top)
        if os.path.isfile(p):
            files[top] = _read(p)
    for dirpath, dirnames, filenames in os.walk(PROJ):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            fp = os.path.join(dirpath, fn)
            rel = os.path.relpath(fp, PAPER_ROOT).replace("\\", "/")
            if not _included(rel):
                continue
            try:
                if os.path.getsize(fp) > MAX_BYTES:
                    files[rel] = f"[file omitted from guide: {os.path.getsize(fp)} bytes > {MAX_BYTES}]"
                    continue
                files[rel] = _read(fp)
            except Exception as e:
                files[rel] = f"[unreadable: {e}]"
    # note the binary PDF (linked, not embedded)
    for f in os.listdir(PAPER_ROOT):
        if f.lower().endswith(".pdf"):
            files["_paper_pdf"] = f
    return files


def _read(p):
    with open(p, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def _load_metrics():
    def j(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    synth = j(os.path.join(HERE, "out", "metrics_summary.json"))
    real = j(os.path.join(HERE, "out_real", "real_metrics.json"))
    return synth, real


def _front_matter(synth, real):
    s = synth or {}
    r = real or {}
    sk = r.get("sink_by_kind", {})
    return f"""
<h1>Capability-Safe Tool Use in Agentic Programs &mdash; CapAgent</h1>
<p class="lead">A prototype that checks <b>capability-safe tool use</b>: an agent must not
perform a high-impact tool effect (delete / overwrite / external-send / exec / patch /
harness-write / verdict / memory-instruction / delegation / credential) unless the current
abstract state holds a capability matching the effect's <b>kind, resource scope, label, and
provenance</b>. This page is an index to the whole project &mdash; pick a file on the left.</p>

<h2>1. What was built (process)</h2>
<ol>
<li><b>Formal core</b> (<code>capagent/core/</code>): the small language <code>&lambda;cap</code>
(IR), a property-directed abstract domain, an explicit-state capability-safety checker
(prefix property, Defs 5&ndash;8), and a Boolean-semiring matrix engine with Kleene closure and
certificates. The two engines are cross-validated to agree on every case.</li>
<li><b>Toolchain</b> (<code>capagent/tools/</code>): all ten commands of the implementation
plan &mdash; caprule-miner, contract-extractor, guard-extractor, acg-builder, translator,
matrix-compiler, capsafe-checker, witness-replayer, report-generator, and an offline
advisory llm-assist &mdash; plus five diagnostic baselines.</li>
<li><b>Synthetic evaluation</b> (<code>capagent/experiments/out/</code>): policy kernels
(one buggy/fixed family per effect kind), extracted agent scaffolds, security witnesses,
and negative controls.</li>
<li><b>Real-repository evaluation, Milestone 5</b> (<code>capagent/experiments/out_real/</code>):
{r.get('repos','N')} pinned real agent frameworks are scanned for a high-impact sink/guard
inventory, a per-framework <b>registry adapter</b> automatically builds an Action-Capability
Graph from each tool registry and checks it, and manually-curated witnesses are replayed
against real sink locations.</li>
</ol>

<h2>2. Results</h2>
<h3>Synthetic suite ({s.get('cases_total','?')} cases)</h3>
<ul>
<li>Known-bug replay rate: <b>{s.get('known_bug_replay_rate','?')}</b>;
fixed-version discharge rate: <b>{s.get('fixed_version_discharge_rate','?')}</b>.</li>
<li>Negative-control false rejections: <b>{s.get('controls_false_rejections','?')}</b>;
diagnostic quality: <b>{s.get('diagnostic_quality','?')}</b>.</li>
<li>Explicit-state vs. matrix agreement: <b>{s.get('explicit_matrix_agreement','?')}</b>
(max matrix dim {s.get('matrix_dim_max','?')}).</li>
<li>Baseline comparison: only CapAgent reaches precision = recall = 1.0; sink-only and
allowlist over-report, guard-dominator misses scope/kind mismatches, taint misses
pure-authorization bugs. (See <code>tables/table4_baseline_comparison.csv</code>.)</li>
</ul>
<h3>Real frameworks ({r.get('repos','?')} repos, {r.get('total_files','?')} files,
{r.get('total_loc','?'):,} LOC)</h3>
<ul>
<li>Automated high-impact <b>sink inventory: {r.get('total_sink_sites','?')} sites</b>
(Exec={sk.get('Exec','?')}, Overwrite={sk.get('Overwrite','?')}, Delete={sk.get('Delete','?')},
SendExt={sk.get('SendExt','?')}, CredAccess={sk.get('CredAccess','?')}); guard sites:
{r.get('total_guard_sites','?')}.</li>
<li>Registry adapter: <b>{r.get('registry_tools_total','?')} registered tools</b> discovered
across {r.get('registry_frameworks_with_tools','?')} frameworks,
<b>{r.get('registry_high_impact_total','?')} high-impact</b>,
<b>{r.get('registry_unguarded_reachable_total','?')}</b> reachable from a model choice with no
capability requirement attached in the registry.</li>
<li>Grounded witness replay: {r.get('witness_pairs','?')} pairs, known-bug replay
<b>{r.get('known_bug_replay_rate','?')}</b>, fixed discharge
<b>{r.get('fixed_discharge_rate','?')}</b>.</li>
</ul>

<h2>3. Conclusions</h2>
<ol>
<li><b>Capability-safety unifies high-impact agent failures</b> across the four families
(runtime/exec, privilege crossing, harness integrity, resource leakage) as a single
missing/mismatched capability over &lang;kind, resource, label, provenance&rang;.</li>
<li><b>Action contracts make agents analyzable.</b> Effect contracts and tool registries are
recoverable from real source at scale; high-impact effects are pervasive and unevenly
mediated (guard density varies ~20&times; across frameworks).</li>
<li><b>The approach explains fixes</b>: every repair maps to guard insertion, scope
refinement, provenance validation, or declassification, and makes the bad state unreachable.</li>
<li><b>More diagnostic than simpler defenses.</b> A tool-name allowlist is not a capability;
only the capability-specific abstraction avoids both the over-reporting of sink/allowlist
scans and the blind spots of guard-dominator and taint analyses.</li>
<li><b>Lightweight and checkable.</b> Matrices are tiny and sparse; certificates re-check
without a language model.</li>
<li><b>Deliberately narrow.</b> The guarantee is relative to accepted contracts and sound
extraction; it proves capability-safe high-impact effects, not task/intent/alignment
correctness. Building a fully faithful ACG for an arbitrary agent loop still needs
per-framework adapters (the registry adapter is a first automated step).</li>
</ol>
<p class="hint">Tip: start with <code>README.md</code>, <code>EXPERIMENT_REPORT.md</code>, and
<code>capagent/experiments/out_real/REAL_REPORT.md</code>.</p>
"""


def build_tree(files):
    root = {}
    for rel in files:
        if rel.startswith("_"):
            continue
        parts = rel.split("/")
        node = root
        for p in parts[:-1]:
            node = node.setdefault(p, {})
        node.setdefault("__files__", []).append(parts[-1])
    return root


def render_tree(node, prefix=""):
    html_parts = ["<ul>"]
    for name in sorted(k for k in node if k != "__files__"):
        full = prefix + name + "/"
        html_parts.append(
            f'<li class="dir"><span class="caret" onclick="toggle(this)">{html.escape(name)}/</span>'
            + render_tree(node[name], full) + "</li>")
    for fn in sorted(node.get("__files__", [])):
        rel = prefix + fn
        html_parts.append(
            f'<li class="file" onclick="show(\'{html.escape(rel)}\')">{html.escape(fn)}</li>')
    html_parts.append("</ul>")
    return "".join(html_parts)


def build():
    files = collect_files()
    synth, real = _load_metrics()
    front = _front_matter(synth, real)
    tree = build_tree(files)
    tree_html = render_tree(tree)
    pdf = files.get("_paper_pdf", "")
    data = {k: v for k, v in files.items() if not k.startswith("_")}
    # escape "</" so an embedded literal </script> cannot close the host <script> tag
    payload = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")
    html_doc = _HTML_TEMPLATE.replace("__TREE__", tree_html) \
        .replace("__FRONT__", front) \
        .replace("__PDF__", html.escape(pdf)) \
        .replace("__DATA__", payload)
    with open(OUT_HTML, "w", encoding="utf-8") as f:
        f.write(html_doc)
    return {"files_indexed": len(data), "out": OUT_HTML}


_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>CapAgent &mdash; Project Reading Guide</title>
<style>
 * { box-sizing: border-box; }
 body { margin:0; font-family: -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
        color:#1b1f24; height:100vh; display:flex; }
 #side { width:340px; min-width:260px; max-width:50%; border-right:1px solid #e1e4e8;
         overflow:auto; padding:10px 6px; background:#fafbfc; resize:horizontal; }
 #main { flex:1; overflow:auto; padding:24px 34px; }
 h1 { font-size:24px; } h2 { border-bottom:1px solid #eaecef; padding-bottom:5px; margin-top:26px; }
 .lead { font-size:15px; color:#24292e; } .hint{color:#57606a;font-size:13px;}
 #side ul { list-style:none; margin:0; padding-left:14px; }
 #side .file { cursor:pointer; padding:2px 6px; border-radius:4px; font-size:13px; color:#0550ae; }
 #side .file:hover { background:#eef4ff; }
 #side .file.active { background:#dbeafe; font-weight:600; }
 .caret { cursor:pointer; font-weight:600; font-size:13px; display:block; padding:2px 0; }
 .caret:before { content:"\25be "; color:#57606a; }
 .collapsed > ul { display:none; } .collapsed > .caret:before { content:"\25b8 "; }
 #brand { font-weight:700; padding:6px; font-size:14px; cursor:pointer; }
 pre { background:#f6f8fa; padding:14px; border-radius:6px; overflow:auto; font-size:12.5px;
       line-height:1.45; font-family:ui-monospace,SFMono-Regular,Consolas,monospace; }
 table { border-collapse:collapse; margin:12px 0; font-size:13px; display:block; overflow:auto; }
 th,td { border:1px solid #d0d7de; padding:5px 9px; text-align:left; } th{background:#f6f8fa;}
 code { background:#eff1f3; padding:1px 5px; border-radius:4px; font-size:90%; }
 h3 { margin-top:18px; } a{color:#0550ae;} .path{color:#57606a;font-size:12px;margin-bottom:8px;}
</style></head><body>
<div id="side">
 <div id="brand" onclick="home()">&#9776; CapAgent &mdash; Reading Guide</div>
 __TREE__
</div>
<div id="main"></div>
<script>
const FILES = __DATA__;
const FRONT = document.createElement('template');
function esc(s){return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}

// minimal markdown -> html
function md(src){
 const lines = src.split(/\r?\n/); let out=[]; let i=0;
 function inline(t){
  t = esc(t);
  t = t.replace(/`([^`]+)`/g,'<code>$1</code>');
  t = t.replace(/\*\*([^*]+)\*\*/g,'<b>$1</b>');
  t = t.replace(/\[([^\]]+)\]\(([^)]+)\)/g,'<a href="$2">$1</a>');
  return t;
 }
 while(i<lines.length){
  let ln=lines[i];
  if(/^```/.test(ln)){ let buf=[]; i++; while(i<lines.length && !/^```/.test(lines[i])){buf.push(lines[i]);i++;} i++;
     out.push('<pre>'+esc(buf.join('\n'))+'</pre>'); continue; }
  let h=ln.match(/^(#{1,6})\s+(.*)/);
  if(h){ out.push('<h'+h[1].length+'>'+inline(h[2])+'</h'+h[1].length+'>'); i++; continue; }
  if(/^\s*\|.*\|\s*$/.test(ln)){ let tbl=[]; while(i<lines.length && /\|/.test(lines[i])){tbl.push(lines[i]);i++;}
     out.push(renderTable(tbl,inline)); continue; }
  if(/^\s*[-*]\s+/.test(ln)){ out.push('<ul>'); while(i<lines.length && /^\s*[-*]\s+/.test(lines[i])){
     out.push('<li>'+inline(lines[i].replace(/^\s*[-*]\s+/,''))+'</li>'); i++;} out.push('</ul>'); continue; }
  if(/^\s*\d+\.\s+/.test(ln)){ out.push('<ol>'); while(i<lines.length && /^\s*\d+\.\s+/.test(lines[i])){
     out.push('<li>'+inline(lines[i].replace(/^\s*\d+\.\s+/,''))+'</li>'); i++;} out.push('</ol>'); continue; }
  if(/^\s*$/.test(ln)){ i++; continue; }
  if(/^---+$/.test(ln)){ out.push('<hr>'); i++; continue; }
  let para=[ln]; i++; while(i<lines.length && !/^\s*$/.test(lines[i]) && !/^[#`|]/.test(lines[i]) && !/^\s*[-*]\s/.test(lines[i])){para.push(lines[i]);i++;}
  out.push('<p>'+inline(para.join(' '))+'</p>');
 }
 return out.join('\n');
}
function renderTable(rows,inline){
 rows=rows.filter(r=>!/^\s*\|?\s*[-:| ]+\s*\|?\s*$/.test(r));
 let h='<table>';
 rows.forEach((r,ri)=>{ let cells=r.split('|').map(c=>c.trim()).filter((c,idx,a)=>!(idx===0&&c==='')&&!(idx===a.length-1&&c===''));
   h+='<tr>'; cells.forEach(c=>{h+= ri===0?('<th>'+inline(c)+'</th>'):('<td>'+inline(c)+'</td>');}); h+='</tr>'; });
 return h+'</table>';
}
function renderCSV(src){
 let rows=src.trim().split(/\r?\n/).map(r=>r.split(','));
 let h='<table>'; rows.forEach((cells,ri)=>{h+='<tr>';cells.forEach(c=>{h+= ri===0?('<th>'+esc(c)+'</th>'):('<td>'+esc(c)+'</td>');});h+='</tr>';}); return h+'</table>';
}
function show(rel){
 document.querySelectorAll('#side .file').forEach(e=>e.classList.remove('active'));
 [...document.querySelectorAll('#side .file')].filter(e=>e.getAttribute('onclick').includes("'"+rel+"'")).forEach(e=>e.classList.add('active'));
 let c=FILES[rel]; let m=document.getElementById('main');
 if(c===undefined){m.innerHTML='<p>not found</p>';return;}
 let ext=rel.split('.').pop().toLowerCase();
 let head='<div class="path">'+esc(rel)+'</div>';
 if(ext==='md'){ m.innerHTML=head+md(c); }
 else if(ext==='csv'){ m.innerHTML=head+renderCSV(c); }
 else { m.innerHTML=head+'<pre>'+esc(c)+'</pre>'; }
 m.scrollTop=0;
}
function home(){ document.getElementById('main').innerHTML=`__FRONT__`;
 let pdf="__PDF__"; if(pdf){document.getElementById('main').innerHTML+='<p class="hint">Paper PDF (not embedded): <code>'+pdf+'</code></p>';} }
function toggle(el){ el.parentElement.classList.toggle('collapsed'); }
home();
</script></body></html>"""


if __name__ == "__main__":
    res = build()
    print(f"files_indexed={res['files_indexed']} out=INDEX.html")
