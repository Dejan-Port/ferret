"""Web UI za upravljanje agentima i tokenima."""
import json


_RULE_PRESETS = [
    ("SSH",       "tcp:22"),
    ("RDP",       "tcp:3389"),
    ("VNC",       "tcp:5900"),
    ("HTTP",      "tcp:80"),
    ("HTTPS",     "tcp:443"),
    ("Firebird",  "tcp:3050"),
    ("MySQL",     "tcp:3306"),
    ("Postgres",  "tcp:5432"),
    ("SNMP",      "udp:161"),
    ("Sve TCP",   "tcp:*"),
    ("Sve UDP",   "udp:*"),
    ("Sve",       "*:*"),
]


def render_ui(agents: list[dict]) -> str:
    rows = ""
    for a in agents:
        online  = a.get("online") and not a.get("revoked")
        revoked = a.get("revoked")
        dot     = ('<span style="color:#22c55e">●</span>' if online
                   else '<span style="color:#6b7280">●</span>')
        status  = "online" if online else ("revokovan" if revoked else "offline")
        caps    = a.get("capabilities") or "—"
        token   = a.get("token", "")
        has_cert = bool(a.get("cert_pem"))

        try:
            rules_list = json.loads(a.get("rules") or "[]")
            rules_html = " ".join(
                f'<span class="rule-badge">{_esc(r)}</span>'
                for r in rules_list
            ) if rules_list else '<span style="color:#4b5270;font-size:11px">—</span>'
        except Exception:
            rules_html = "—"

        rules_data = _esc(a.get("rules") or "[]").replace('"', "&quot;")

        cert_btn = (
            f'<button class="btn-sm btn-cert" onclick="downloadBundle(\'{token}\')"'
            f' title="Preuzmi CA sertifikat">CA cert</button> '
            if has_cert else ""
        )
        inst_btns = (
            f'<button class="btn-sm btn-linux" onclick="downloadInstaller(\'{token}\',\'linux\')"'
            f' title="Preuzmi Linux installer">🐧</button> '
            f'<button class="btn-sm btn-win" onclick="downloadInstaller(\'{token}\',\'windows\')"'
            f' title="Preuzmi Windows installer">🪟</button> '
        )

        edit_btn = '<button class="btn-sm btn-edit" onclick="openEdit(\'' + token + '\')">Pravila</button> '
        rev_btn  = '<button class="btn-sm btn-rev" onclick="revoke(\'' + token + '\')">Revokuj</button>'
        action_btns = (inst_btns + cert_btn + edit_btn + rev_btn) if not revoked else '—'
        tr_class = 'revoked' if revoked else ''

        rows += f"""
        <tr class="{tr_class}" data-token="{token}" data-rules="{rules_data}">
          <td>{dot} {status}</td>
          <td><strong>{_esc(a.get('name',''))}</strong></td>
          <td style="color:#8b93a7">{_esc(a.get('note',''))}</td>
          <td>
            <code class="token-cell" title="{token}">{token[:8]}…</code>
            <button class="btn-copy-token" onclick="copyText('{token}')" title="Kopiraj token">⎘</button>
          </td>
          <td>{rules_html}</td>
          <td style="color:#8b93a7">{_esc(caps) if caps != '—' else '—'}</td>
          <td style="color:#4b5270">{_esc(a.get('last_seen','') or '—')}</td>
          <td style="color:#4b5270">{_esc(a.get('created_at',''))}</td>
          <td>{action_btns}</td>
        </tr>"""

    presets_js = json.dumps([{"label": l, "value": v} for l, v in _RULE_PRESETS])

    return f"""<!DOCTYPE html>
<html lang="sr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Agent Manager</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0f1117;color:#e2e4ed;padding:32px}}
h1{{font-size:20px;font-weight:700;margin-bottom:6px;color:#fff}}
.subtitle{{font-size:12px;color:#4b5270;margin-bottom:28px}}
.card{{background:#151821;border:1px solid #252840;border-radius:10px;padding:24px;margin-bottom:24px}}
.card h2{{font-size:11px;font-weight:600;color:#8b93a7;text-transform:uppercase;letter-spacing:1.2px;margin-bottom:18px}}
.form-row{{display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end}}
label{{display:block;font-size:10px;color:#8b93a7;margin-bottom:4px;text-transform:uppercase;letter-spacing:.5px}}
input[type=text]{{background:#1e2235;border:1px solid #2d3354;border-radius:7px;color:#e2e4ed;font-family:inherit;font-size:13px;padding:8px 12px;outline:none;min-width:180px}}
input[type=text]:focus{{border-color:#3b5bdb}}
.rules-builder{{margin-top:14px}}
.presets{{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:10px}}
.preset-btn{{padding:4px 10px;background:#1e2235;border:1px solid #2d3354;border-radius:20px;color:#8b93a7;font-size:12px;cursor:pointer;font-family:inherit;transition:all .12s}}
.preset-btn:hover{{border-color:#3b5bdb;color:#e2e4ed}}
.preset-btn.active{{background:#1e3a8a;border-color:#3b5bdb;color:#bfdbfe}}
.rules-tags{{display:flex;flex-wrap:wrap;gap:6px;min-height:32px;padding:8px 10px;background:#0f1117;border:1px solid #252840;border-radius:7px;align-items:center;margin-bottom:10px}}
.rule-tag{{display:inline-flex;align-items:center;gap:5px;background:#1e2235;border:1px solid #2d3354;border-radius:4px;padding:3px 8px;font-size:12px;font-family:monospace;color:#7dd3fc}}
.rule-tag button{{background:none;border:none;color:#4b5270;cursor:pointer;font-size:14px;line-height:1;padding:0}}
.rule-tag button:hover{{color:#fca5a5}}
.custom-rule-row{{display:flex;gap:6px}}
.custom-rule-row input{{min-width:140px;font-family:monospace}}
.rule-badge{{display:inline-block;background:#1e2235;border:1px solid #2d3354;border-radius:4px;padding:2px 7px;font-size:11px;font-family:monospace;color:#7dd3fc;margin:1px}}
.btn{{padding:8px 18px;background:#3b5bdb;color:#fff;border:none;border-radius:7px;font-size:13px;cursor:pointer;font-family:inherit;transition:background .12s}}
.btn:hover{{background:#2f4ac0}}
.btn-green{{background:#166534;color:#86efac}}
.btn-green:hover{{background:#15803d}}
.btn-sm{{padding:4px 10px;border:none;border-radius:5px;font-size:12px;cursor:pointer;font-family:inherit}}
.btn-edit{{background:#1e3a8a;color:#bfdbfe}}
.btn-edit:hover{{background:#1e40af}}
.btn-rev{{background:#7f1d1d;color:#fca5a5}}
.btn-rev:hover{{background:#991b1b}}
.btn-cert{{background:#134e4a;color:#99f6e4}}
.btn-cert:hover{{background:#0f766e}}
.btn-linux{{background:#1a2e1a;color:#86efac;font-size:13px}}
.btn-linux:hover{{background:#14532d}}
.btn-win{{background:#1e2a3a;color:#93c5fd;font-size:13px}}
.btn-win:hover{{background:#1e3a8a}}
.btn-ghost{{padding:8px 16px;background:#1e2235;color:#e2e4ed;border:none;border-radius:7px;font-size:13px;cursor:pointer;font-family:inherit}}
.btn-copy-token{{background:none;border:none;color:#4b5270;cursor:pointer;font-size:14px;padding:0 4px;vertical-align:middle}}
.btn-copy-token:hover{{color:#7dd3fc}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th{{text-align:left;font-size:10px;color:#4b5270;text-transform:uppercase;letter-spacing:.8px;padding:8px 12px;border-bottom:1px solid #252840}}
td{{padding:9px 12px;border-bottom:1px solid #1a1d27;vertical-align:middle}}
tr.revoked td{{opacity:.35}}
tr:last-child td{{border-bottom:none}}
code.token-cell{{background:#1e2235;border-radius:4px;padding:2px 7px;font-size:12px;color:#7dd3fc;cursor:pointer;font-family:monospace;border:1px solid #2d3354}}
code.token-cell:hover{{border-color:#3b5bdb}}
.overlay{{position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:100;display:none;align-items:center;justify-content:center}}
.modal{{background:#151821;border:1px solid #252840;border-radius:12px;padding:28px;max-width:520px;width:90%}}
.modal h2{{font-size:15px;font-weight:600;margin-bottom:6px;color:#fff}}
.modal p{{font-size:12px;color:#8b93a7;margin-bottom:14px}}
.token-box{{display:block;background:#0f1117;border:1px solid #252840;border-radius:8px;padding:14px;font-size:12px;color:#7dd3fc;word-break:break-all;margin-bottom:10px;font-family:monospace;user-select:all}}
.cert-notice{{background:#052e16;border:1px solid #166534;border-radius:8px;padding:12px 14px;font-size:12px;color:#86efac;margin-bottom:14px}}
.cert-notice strong{{color:#4ade80}}
.modal-actions{{display:flex;gap:10px;flex-wrap:wrap}}
.toast{{position:fixed;bottom:24px;right:24px;background:#052e16;color:#86efac;border:1px solid #166534;border-radius:8px;padding:12px 20px;font-size:13px;display:none;z-index:999}}
.empty-row td{{text-align:center;color:#4b5270;padding:28px}}
</style>
</head>
<body>
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
  <h1>Agent Manager</h1>
  <a href="#" onclick="window.location='audit?admin='+encodeURIComponent(localStorage.getItem('adminToken')||'');return false;" style="font-size:12px;color:#8b93a7;text-decoration:none;background:#1e2235;border:1px solid #2d3354;border-radius:6px;padding:6px 14px">📋 Audit log</a>
</div>
<p class="subtitle">Upravljanje outbound agentima i ACL pravilima</p>

<!-- Kreiranje novog agenta -->
<div class="card">
  <h2>Novi agent</h2>
  <p style="color:#4b5270;font-size:13px;margin-bottom:12px">
    Generiše <strong>invite token</strong> koji važi <strong>5 minuta</strong>.
    Agent se konektuje, šalje HWID, i čeka odobrenje admina.
  </p>
  <div class="form-row">
    <div>
      <label>Naziv</label>
      <input type="text" id="name" placeholder="Firma ABC" required>
    </div>
    <div>
      <label>Napomena</label>
      <input type="text" id="note" placeholder="Opis lokacije, servera...">
    </div>
  </div>
  <div class="rules-builder" style="margin-top:16px">
    <label>Dozvoljen saobraćaj (ACL pravila)</label>
    <div class="presets" id="presets"></div>
    <div class="rules-tags" id="ruleTags"></div>
    <div class="custom-rule-row">
      <input type="text" id="customRule" placeholder="npr. tcp:8080" onkeydown="if(event.key==='Enter'){{event.preventDefault();addCustom()}}">
      <button class="btn-ghost" onclick="addCustom()">Dodaj</button>
    </div>
  </div>
  <div style="margin-top:16px">
    <button class="btn" onclick="createInvite()">Generiši invite token (5 min)</button>
  </div>
</div>

<!-- Pending agenti -->
<div class="card" id="pendingCard" style="display:none">
  <h2 style="color:#fbbf24">⏳ Čekaju odobrenje</h2>
  <table id="pendingTable">
    <tr><th>Naziv</th><th>HWID (prvih 16)</th><th>Kreiran</th><th></th></tr>
  </table>
</div>

<!-- Tabela agenata -->
<div class="card">
  <h2>Agenti ({len(agents)})</h2>
  <table>
    <tr>
      <th>Status</th><th>Naziv</th><th>Napomena</th>
      <th>Token</th><th>ACL pravila</th><th>Capabilities</th>
      <th>Poslednji put viđen</th><th>Kreiran</th><th></th>
    </tr>
    {rows if rows else '<tr class="empty-row"><td colspan="9">Nema agenata</td></tr>'}
  </table>
</div>

<!-- Modal: prikaz kreiranog tokena + sertifikata -->
<div class="overlay" id="tokenModal">
  <div class="modal">
    <h2>Token kreiran</h2>
    <p>Upiši token u <code style="color:#7dd3fc">agent.conf</code> na klijentskoj mašini.</p>
    <code class="token-box" id="tokenValue"></code>

    <div class="cert-notice" id="certNotice" style="display:none">
      <strong>Klijentski sertifikat je generisan.</strong><br>
      Preuzmi bundle (cert + key + CA) i sačuvaj na klijentskoj mašini.
      <strong>Privatni ključ se ne čuva na serveru</strong> — ovo je jedina šansa za preuzimanje.
    </div>

    <div class="modal-actions">
      <button class="btn" onclick="copyText(document.getElementById('tokenValue').textContent)">Kopiraj token</button>
      <button class="btn btn-green" id="downloadBtn" style="display:none" onclick="downloadBundle(null)">Preuzmi bundle (.pem)</button>
      <button class="btn-ghost" onclick="closeTokenModal()">Zatvori</button>
    </div>
  </div>
</div>

<!-- Modal: izmena pravila -->
<div class="overlay" id="editModal">
  <div class="modal">
    <h2>Izmena ACL pravila</h2>
    <p>Promene stupaju na snagu odmah — nema potrebe da agent ponovo konektuje.</p>
    <div class="presets" id="editPresets"></div>
    <div class="rules-tags" id="editRuleTags"></div>
    <div class="custom-rule-row">
      <input type="text" id="editCustomRule" placeholder="npr. tcp:8080" onkeydown="if(event.key==='Enter'){{event.preventDefault();addEditCustom()}}">
      <button class="btn-ghost" onclick="addEditCustom()">Dodaj</button>
    </div>
    <div style="display:flex;gap:10px;margin-top:16px">
      <button class="btn" onclick="saveRules()">Sačuvaj</button>
      <button class="btn-ghost" onclick="closeModal('editModal')">Otkaži</button>
    </div>
  </div>
</div>

<div class="toast" id="toast"></div>

<!-- Login modal -->
<div class="overlay" id="loginOverlay" style="display:none">
  <div class="modal" style="max-width:360px;text-align:center">
    <h2 style="margin-bottom:8px">🐾 Ferret</h2>
    <p style="color:#4b5270;margin-bottom:20px;font-size:14px">Unesi admin token</p>
    <input type="password" id="loginInput" placeholder="Admin token"
           style="width:100%;padding:10px 14px;background:#1a1d2e;border:1px solid #2d3354;
                  border-radius:8px;color:#e2e8f0;font-size:14px;margin-bottom:12px;outline:none">
    <button class="btn" style="width:100%" onclick="doLogin()">Prijavi se</button>
    <div id="loginErr" style="color:#f87171;font-size:13px;margin-top:10px;display:none">
      Nevalidan token
    </div>
  </div>
</div>

<script>
var PRESETS = {presets_js};
var newRules  = [];
var editRules = [];
var editToken = '';
var _lastBundle = null;  // {{cert_pem, key_pem, ca_pem, token}}

// ── Presets ──────────────────────────────────────────────────────────────────

function buildPresets(containerId, rulesArr, toggleFn) {{
  var el = document.getElementById(containerId);
  el.innerHTML = PRESETS.map(function(p) {{
    var active = rulesArr.indexOf(p.value) >= 0 ? 'active' : '';
    return '<button class="preset-btn '+active+'" onclick="'+toggleFn+'(this,\\''+p.value+'\\')" type="button">'+p.label+'</button>';
  }}).join('');
}}

function renderTags(containerId, rulesArr, removeFn) {{
  var el = document.getElementById(containerId);
  if(!rulesArr.length) {{
    el.innerHTML = '<span style="color:#4b5270;font-size:12px">Klikni preset ili dodaj ručno</span>';
    return;
  }}
  el.innerHTML = rulesArr.map(function(r) {{
    return '<span class="rule-tag"><span>'+r+'</span><button onclick="'+removeFn+'(\\''+r+'\\')" type="button">×</button></span>';
  }}).join('');
}}

buildPresets('presets', newRules, 'toggleNew');
renderTags('ruleTags', newRules, 'removeNew');

// ── Novi agent ────────────────────────────────────────────────────────────────

function toggleNew(btn, val) {{
  var i = newRules.indexOf(val);
  if(i >= 0) {{ newRules.splice(i,1); btn.classList.remove('active'); }}
  else        {{ newRules.push(val);  btn.classList.add('active'); }}
  renderTags('ruleTags', newRules, 'removeNew');
}}
function removeNew(val) {{
  newRules = newRules.filter(function(r){{return r!==val;}});
  buildPresets('presets', newRules, 'toggleNew');
  renderTags('ruleTags', newRules, 'removeNew');
}}
function addCustom() {{
  var v = document.getElementById('customRule').value.trim();
  if(!v || newRules.indexOf(v)>=0) return;
  newRules.push(v);
  document.getElementById('customRule').value = '';
  buildPresets('presets', newRules, 'toggleNew');
  renderTags('ruleTags', newRules, 'removeNew');
}}

async function createInvite() {{
  var name = document.getElementById('name').value.trim();
  if(!name) {{ alert('Naziv je obavezan'); return; }}
  var note = document.getElementById('note').value.trim();
  try {{
    var r = await _api('POST', '/invite', {{name, note, rules: newRules}});
    if(r.status === 401) {{ promptToken(); return; }}
    var d = await r.json();
    document.getElementById('tokenValue').textContent = d.token;
    document.getElementById('certNotice').style.display = 'none';
    document.getElementById('downloadBtn').style.display = 'none';
    document.getElementById('tokenModal').style.display = 'flex';
    document.getElementById('name').value = '';
    document.getElementById('note').value = '';
    newRules = [];
    buildPresets('presets', newRules, 'toggleNew');
    renderTags('ruleTags', newRules, 'removeNew');
    // Počni da pratiš pending odmah
    setTimeout(loadPending, 3000);
  }} catch(err) {{ alert('Greška: ' + err); }}
}}

async function createAgent() {{
  var name = document.getElementById('name').value.trim();
  if(!name) {{ alert('Naziv je obavezan'); return; }}
  var note = document.getElementById('note').value.trim();
  try {{
    var r = await _api('POST', '/token', {{name, note, rules: newRules}});
    if(r.status === 401) {{ promptToken(); return; }}
    var d = await r.json();

    document.getElementById('tokenValue').textContent = d.token;

    _lastBundle = null;
    var certNotice = document.getElementById('certNotice');
    var downloadBtn = document.getElementById('downloadBtn');
    if(d.cert_pem && d.key_pem && d.ca_pem) {{
      _lastBundle = {{cert_pem: d.cert_pem, key_pem: d.key_pem, ca_pem: d.ca_pem, token: d.token, name}};
      certNotice.style.display = 'block';
      downloadBtn.style.display = 'inline-block';
    }} else {{
      certNotice.style.display = 'none';
      downloadBtn.style.display = 'none';
    }}

    document.getElementById('tokenModal').style.display = 'flex';
    document.getElementById('name').value = '';
    document.getElementById('note').value = '';
    newRules = [];
    buildPresets('presets', newRules, 'toggleNew');
    renderTags('ruleTags', newRules, 'removeNew');
  }} catch(err) {{ alert('Greška: ' + err); }}
}}

function _escHtml(s) {{
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}}

async function loadPending() {{
  try {{
    var r = await _api('GET', '/pending');
    if(r.status !== 200) return;
    var list = await r.json();
    var card = document.getElementById('pendingCard');
    var tbody = document.getElementById('pendingTable');
    if(!list.length) {{ card.style.display = 'none'; return; }}
    card.style.display = '';
    var rows = '<tr><th>Naziv</th><th>HWID (prvih 16)</th><th>Kreiran</th><th></th></tr>';
    list.forEach(function(a) {{
      var hwid = a.hwid ? _escHtml(a.hwid.substring(0,16)) + '…' : '<em style="color:#4b5270">čeka konekciju</em>';
      var canApprove = !!a.hwid;
      rows += '<tr>' +
        '<td>' + _escHtml(a.name) + '</td>' +
        '<td><code style="font-size:12px">' + hwid + '</code></td>' +
        '<td style="color:#4b5270;font-size:12px">' + _escHtml(a.created_at||'') + '</td>' +
        '<td>' + (canApprove
          ? '<button class="btn" style="padding:4px 14px;font-size:12px" data-token="' + _escHtml(a.token) + '" onclick="approveAgent(this.dataset.token)">✓ Odobri</button>'
          : '<span style="color:#4b5270;font-size:12px">čeka…</span>') +
        ' <button class="btn-ghost" style="padding:4px 10px;font-size:12px;color:#f87171" data-token="' + _escHtml(a.token) + '" onclick="revoke(this.dataset.token)">✕</button>' +
        '</td>' +
      '</tr>';
    }});
    tbody.innerHTML = rows;
  }} catch(e) {{}}
}}

async function approveAgent(token) {{
  try {{
    var r = await _api('POST', '/' + token + '/approve', {{}});
    if(r.status === 401) {{ promptToken(); return; }}
    var d = await r.json();
    if(d.ok) {{
      alert('Agent odobren! HWID: ' + d.hwid);
      loadPending();
      location.reload();
    }} else {{
      alert('Greška pri odobrenju');
    }}
  }} catch(e) {{ alert('Greška: ' + e); }}
}}

// Polling pending na 10s
setInterval(loadPending, 10000);
loadPending();

// ── Bundle download ───────────────────────────────────────────────────────────

function downloadBundle(token) {{
  if(token) {{
    // Download CA cert za postojećeg agenta
    var a = document.createElement('a');
    a.href = _apiUrl('/'+token+'/bundle');
    a.download = token.substring(0,8)+'_ca.pem';
    a.click();
    return;
  }}
  // Download kompletnog bundle-a odmah po kreiranju (jedina šansa za key)
  if(!_lastBundle) return;
  var content = [
    '# ferret bundle',
    '# Agent: ' + _lastBundle.name,
    '# VAŽNO: Sačuvaj privatni ključ — ne čuva se na serveru!',
    '',
    '# === CA SERTIFIKAT ===',
    _lastBundle.ca_pem.trim(),
    '',
    '# === KLIJENTSKI SERTIFIKAT ===',
    _lastBundle.cert_pem.trim(),
    '',
    '# === PRIVATNI KLJUČ (ČUVAJ TAJNIM) ===',
    _lastBundle.key_pem.trim(),
  ].join('\\n');
  var blob = new Blob([content], {{type: 'application/x-pem-file'}});
  var a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = (_lastBundle.name.replace(/\\s+/g,'_') || 'agent') + '_bundle.pem';
  a.click();
  showToast('Bundle preuzet — čuvaj privatni ključ tajnim!');
}}

// ── Izmena pravila ────────────────────────────────────────────────────────────

function openEdit(token) {{
  editToken = token;
  var rulesRaw = document.querySelector('tr[data-token="'+token+'"]')?.dataset.rules || '[]';
  try {{ editRules = JSON.parse(rulesRaw); }} catch(e) {{ editRules = []; }}
  buildPresets('editPresets', editRules, 'toggleEdit');
  renderTags('editRuleTags', editRules, 'removeEdit');
  document.getElementById('editModal').style.display = 'flex';
}}
function toggleEdit(btn, val) {{
  var i = editRules.indexOf(val);
  if(i >= 0) {{ editRules.splice(i,1); btn.classList.remove('active'); }}
  else        {{ editRules.push(val);  btn.classList.add('active'); }}
  renderTags('editRuleTags', editRules, 'removeEdit');
}}
function removeEdit(val) {{
  editRules = editRules.filter(function(r){{return r!==val;}});
  buildPresets('editPresets', editRules, 'toggleEdit');
  renderTags('editRuleTags', editRules, 'removeEdit');
}}
function addEditCustom() {{
  var v = document.getElementById('editCustomRule').value.trim();
  if(!v || editRules.indexOf(v)>=0) return;
  editRules.push(v);
  document.getElementById('editCustomRule').value = '';
  buildPresets('editPresets', editRules, 'toggleEdit');
  renderTags('editRuleTags', editRules, 'removeEdit');
}}
async function saveRules() {{
  try {{
    var r = await _api('PATCH', '/'+editToken+'/rules', {{rules: editRules}});
    if(!r.ok) throw new Error(await r.text());
    closeModal('editModal');
    showToast('Pravila sačuvana');
    setTimeout(() => location.reload(), 800);
  }} catch(err) {{ alert('Greška: ' + err); }}
}}

// ── Ostalo ────────────────────────────────────────────────────────────────────

async function revoke(token) {{
  if(!confirm('Revokuj ovaj token? Agent se više neće moći konektovati.')) return;
  await _api('DELETE', '/'+token);
  location.reload();
}}

function downloadInstaller(token, os) {{
  var a = document.createElement('a');
  a.href = _apiUrl('/'+token+'/installer?os='+os);
  a.download = '';
  a.click();
  showToast(os === 'linux' ? 'Linux installer preuzet — sudo bash install.sh' : 'Windows installer preuzet — PowerShell -ExecutionPolicy Bypass -File install.ps1');
}}

function copyText(text) {{
  navigator.clipboard.writeText(text.trim()).then(() => showToast('Kopirano!'));
}}

function closeModal(id) {{
  document.getElementById(id).style.display = 'none';
}}

function closeTokenModal() {{
  _lastBundle = null;
  closeModal('tokenModal');
  location.reload();
}}

function showToast(msg) {{
  var t = document.getElementById('toast');
  t.textContent = msg; t.style.display = 'block';
  clearTimeout(t._t); t._t = setTimeout(() => t.style.display = 'none', 3500);
}}

function showLogin() {{
  document.getElementById('loginOverlay').style.display = 'flex';
  setTimeout(() => document.getElementById('loginInput').focus(), 100);
}}

function hideLogin() {{
  document.getElementById('loginOverlay').style.display = 'none';
}}

async function doLogin() {{
  var tok = document.getElementById('loginInput').value.trim();
  if (!tok) return;
  var r = await fetch(_apiUrl('/auth'), {{headers:{{'Authorization':'Bearer '+tok}}}});
  if (r.ok) {{
    localStorage.setItem('adminToken', tok);
    hideLogin();
    location.reload();
  }} else {{
    document.getElementById('loginErr').style.display = 'block';
  }}
}}

document.getElementById('loginInput').addEventListener('keydown', function(e) {{
  if (e.key === 'Enter') doLogin();
}});

function _apiUrl(path) {{
  return location.pathname.replace('/ui','') + path;
}}

function _api(method, path, body) {{
  return fetch(_apiUrl(path), {{
    method,
    headers: {{
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + (localStorage.getItem('adminToken') || '')
    }},
    body: body ? JSON.stringify(body) : undefined
  }}).then(r => {{
    if (r.status === 401) {{ showLogin(); throw new Error('Unauthorized'); }}
    return r;
  }});
}}

// Klik na token ćeliju → kopiraj pun token
document.querySelectorAll('.token-cell').forEach(el => {{
  el.addEventListener('click', () => copyText(el.title));
}});

if (!localStorage.getItem('adminToken')) showLogin();
</script>
</body>
</html>"""


def _esc(s: str) -> str:
    return str(s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
