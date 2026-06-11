"""Web SMS UI — HTML stranica za pregled i slanje SMS-a iz browser-a."""

_FAVICON = "data:image/png;base64,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"


def render_html(modem: str = "") -> str:
    m = modem or "—"
    return f"""<!DOCTYPE html>
<html lang="sr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Asterisk SMS</title>
<link rel="icon" type="image/png" href="{_FAVICON}">
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0f1117;color:#e2e4ed;height:100vh;display:flex;flex-direction:column;overflow:hidden}}
header{{background:#151821;border-bottom:1px solid #252840;padding:12px 20px;display:flex;align-items:center;gap:10px;flex-shrink:0}}
header h1{{font-size:14px;font-weight:600;letter-spacing:.5px}}
.hstatus{{margin-left:auto;display:flex;align-items:center;gap:7px;font-size:12px;color:#8b93a7}}
.dot{{width:7px;height:7px;border-radius:50%;background:#8b93a7;transition:background .3s}}
.dot.ok{{background:#22c55e}}.dot.err{{background:#ef4444}}
.layout{{flex:1;display:grid;grid-template-columns:220px 1fr 300px;overflow:hidden}}
.contacts{{background:#151821;border-right:1px solid #252840;display:flex;flex-direction:column;overflow:hidden}}
.contacts-head{{padding:12px 14px;border-bottom:1px solid #252840;font-size:10px;font-weight:600;letter-spacing:1.5px;color:#8b93a7;text-transform:uppercase;flex-shrink:0}}
.contact-list{{flex:1;overflow-y:auto}}
.contact-item{{padding:10px 14px;cursor:pointer;border-left:3px solid transparent;border-bottom:1px solid #1a1d27;transition:background .1s}}
.contact-item:hover{{background:#1e2235}}
.contact-item.active{{background:#1e2235;border-left-color:#3b5bdb}}
.contact-name{{font-size:13px;font-weight:500;color:#e2e4ed;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
.contact-num{{font-size:10px;color:#4b5270;margin-top:1px}}
.contact-preview{{font-size:11px;color:#8b93a7;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin-top:2px}}
.contact-time{{font-size:10px;color:#4b5270;margin-top:2px}}
.chat{{display:flex;flex-direction:column;overflow:hidden;background:#0f1117}}
.chat-head{{padding:12px 16px;border-bottom:1px solid #252840;display:flex;align-items:center;gap:10px;flex-shrink:0;background:#151821}}
.chat-name{{font-size:14px;font-weight:500}}
.chat-sub{{font-size:11px;color:#8b93a7;margin-top:1px}}
.chat-empty{{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:8px;color:#4b5270}}
.chat-empty svg{{width:36px;height:36px;opacity:.3}}
.chat-messages{{flex:1;overflow-y:auto;padding:14px 16px;display:flex;flex-direction:column;gap:8px}}
.bubble-wrap{{display:flex;flex-direction:column}}
.bubble-wrap.out{{align-items:flex-end}}
.bubble-wrap.in{{align-items:flex-start}}
.bubble{{max-width:75%;padding:9px 13px;border-radius:12px;font-size:13px;line-height:1.5;word-break:break-word}}
.bubble.in{{background:#1e2235;border-bottom-left-radius:3px;color:#e2e4ed}}
.bubble.out{{background:#1e3a8a;border-bottom-right-radius:3px;color:#bfdbfe}}
.bubble-time{{font-size:10px;color:#4b5270;margin-top:3px;padding:0 2px}}
.chat-input{{padding:12px 16px;border-top:1px solid #252840;display:flex;flex-direction:column;gap:8px;flex-shrink:0;background:#151821}}
.chat-input textarea{{background:#1e2235;border:1px solid #2d3354;border-radius:8px;color:#e2e4ed;font-family:inherit;font-size:13px;padding:9px 12px;resize:none;height:70px;line-height:1.5;outline:none;transition:border-color .15s}}
.chat-input textarea:focus{{border-color:#3b5bdb}}
.chat-input-row{{display:flex;align-items:center;gap:8px}}
.char-info{{font-size:11px;color:#8b93a7;flex:1}}
.chat-send-btn{{padding:8px 18px;background:#3b5bdb;color:#fff;border:none;border-radius:7px;font-family:inherit;font-size:13px;cursor:pointer;display:flex;align-items:center;gap:6px;transition:background .15s;white-space:nowrap}}
.chat-send-btn:hover{{background:#2f4ac0}}
.chat-send-btn:disabled{{opacity:.5;cursor:not-allowed}}
.new-sms{{background:#151821;border-left:1px solid #252840;display:flex;flex-direction:column;overflow-y:auto}}
.new-sms-head{{padding:12px 16px;border-bottom:1px solid #252840;font-size:10px;font-weight:600;letter-spacing:1.5px;color:#8b93a7;text-transform:uppercase;flex-shrink:0}}
.new-sms-body{{padding:16px;display:flex;flex-direction:column;gap:12px;flex:1}}
label{{display:block;font-size:10px;color:#8b93a7;margin-bottom:4px;letter-spacing:.5px;text-transform:uppercase}}
input[type=text],input[type=tel],textarea{{width:100%;background:#1e2235;border:1px solid #2d3354;border-radius:7px;color:#e2e4ed;font-family:inherit;font-size:13px;padding:8px 11px;outline:none;transition:border-color .15s}}
input:focus,textarea:focus{{border-color:#3b5bdb}}
.bar-bg{{height:3px;background:#252840;border-radius:2px;overflow:hidden;margin-top:4px}}
.bar-fill{{height:100%;width:0%;background:#3b5bdb;border-radius:2px;transition:width .08s,background .08s}}
.new-send-btn{{padding:9px;background:#3b5bdb;color:#fff;border:none;border-radius:7px;font-family:inherit;font-size:13px;cursor:pointer;display:flex;align-items:center;justify-content:center;gap:7px;transition:background .15s}}
.new-send-btn:hover{{background:#2f4ac0}}
.new-send-btn:disabled{{opacity:.5;cursor:not-allowed}}
.toast{{padding:8px 12px;border-radius:7px;font-size:12px;display:none;margin-top:4px}}
.toast.ok{{background:#052e16;color:#86efac;border:1px solid #166534}}
.toast.err{{background:#2d0a0a;color:#fca5a5;border:1px solid #991b1b}}
.new-sms-foot{{padding:14px 16px;border-top:1px solid #252840;margin-top:auto}}
.modem-tag{{display:inline-flex;align-items:center;gap:5px;background:#1e2235;border:1px solid #2d3354;border-radius:5px;padding:5px 9px;font-size:11px;color:#8b93a7}}
.modem-tag strong{{color:#e2e4ed}}
::-webkit-scrollbar{{width:4px}}::-webkit-scrollbar-track{{background:transparent}}::-webkit-scrollbar-thumb{{background:#252840;border-radius:2px}}
</style>
</head>
<body>
<header>
  <img src="{_FAVICON}" style="width:28px;height:28px;object-fit:contain;flex-shrink:0" alt="">
  <h1>Asterisk SMS</h1>
  <div class="hstatus">
    <div class="dot" id="dot"></div>
    <span id="statusTxt">proverava se...</span>
  </div>
</header>
<div class="layout">
  <div class="contacts">
    <div class="contacts-head">Kontakti <span id="totalBadge" style="font-weight:400;color:#4b5270"></span></div>
    <div class="contact-list" id="contactList"></div>
  </div>
  <div class="chat" id="chatPanel">
    <div class="chat-empty" id="chatEmpty">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
      <p>Izaberi kontakt za prikaz konverzacije</p>
    </div>
    <div class="chat-head" id="chatHead" style="display:none">
      <div>
        <div class="chat-name" id="chatName"></div>
        <div class="chat-sub" id="chatSub"></div>
      </div>
    </div>
    <div class="chat-messages" id="chatMessages" style="display:none"></div>
    <div class="chat-input" id="chatInput" style="display:none">
      <textarea id="chatMsg" maxlength="160" placeholder="Ukucaj poruku..."></textarea>
      <div class="chat-input-row">
        <div class="char-info"><span id="chatCharTxt">0 / 160</span></div>
        <button class="chat-send-btn" id="chatSendBtn" onclick="sendChat()">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
          Pošalji
        </button>
      </div>
    </div>
  </div>
  <div class="new-sms">
    <div class="new-sms-head">Novi SMS</div>
    <div class="new-sms-body">
      <div>
        <label>Broj primaoca</label>
        <input type="tel" id="number" placeholder="npr. 0601234567" autocomplete="off">
      </div>
      <div>
        <label>Poruka</label>
        <textarea id="msg" maxlength="160" placeholder="Ukucaj poruku..." style="height:90px;resize:none"></textarea>
        <div class="bar-bg"><div class="bar-fill" id="barFill"></div></div>
        <div style="text-align:right;margin-top:3px;font-size:11px;color:#8b93a7"><span id="charTxt">0 / 160</span></div>
      </div>
      <button class="new-send-btn" id="sendBtn" onclick="doSend()">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
        Pošalji
      </button>
      <div class="toast" id="toast"></div>
    </div>
    <div class="new-sms-foot">
      <div class="modem-tag">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="5" y="2" width="14" height="20" rx="2"/><line x1="12" y1="18" x2="12" y2="18"/></svg>
        GSM: <strong>{m}</strong>
      </div>
    </div>
  </div>
</div>
<script>
var allMsgs=[], activeContact=null;
function esc(s){{return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}}
function escAttr(s){{return esc(s).replace(/'/g,'&#39;');}}
function normalizeNum(num){{
  if(!num) return num;
  num=String(num).trim();
  if(num.startsWith('06')||num.startsWith('07')) return '+381'+num.substring(1);
  return num;
}}
function buildContacts(msgs){{
  var map={{}};
  msgs.forEach(function(m){{
    var num=normalizeNum(m.number);
    if(!map[num]) map[num]={{num:num,name:m.name,msgs:[],last:null}};
    if(m.name&&m.name!==num&&m.name!==m.number) map[num].name=m.name;
    map[num].msgs.push(m);
    if(!map[num].last||m.ts>map[num].last.ts) map[num].last=m;
  }});
  return Object.values(map).sort(function(a,b){{return b.last.ts.localeCompare(a.last.ts);}});
}}
function renderContacts(contacts){{
  var el=document.getElementById('contactList');
  document.getElementById('totalBadge').textContent='('+contacts.length+')';
  if(!contacts.length){{el.innerHTML='<div style="padding:20px;text-align:center;color:#4b5270;font-size:12px">Nema poruka</div>';return;}}
  el.innerHTML=contacts.map(function(c){{
    var preview=esc(c.last.body.substring(0,35))+(c.last.body.length>35?'...':'');
    var active=activeContact===c.num?'active':'';
    var dir=c.last.dir==='out'?'→ ':'';
    var hasName=c.name&&c.name!==c.num;
    var displayName=hasName?esc(c.name):esc(c.num);
    var numLine=hasName?'<div class="contact-num">'+esc(c.num)+'</div>':'';
    return '<div class="contact-item '+active+'" data-num="'+escAttr(c.num)+'">'+
      '<div class="contact-name">'+displayName+'</div>'+numLine+
      '<div class="contact-preview">'+dir+preview+'</div>'+
      '<div class="contact-time">'+esc(c.last.ts)+'</div></div>';
  }}).join('');
}}
function openContact(num){{
  activeContact=num;
  document.getElementById('chatEmpty').style.display='none';
  document.getElementById('chatHead').style.display='flex';
  document.getElementById('chatMessages').style.display='flex';
  document.getElementById('chatInput').style.display='flex';
  var contacts=buildContacts(allMsgs);
  var contact=contacts.find(function(c){{return c.num===num;}});
  var hasName=contact&&contact.name&&contact.name!==num;
  document.getElementById('chatName').textContent=hasName?contact.name:num;
  document.getElementById('chatSub').textContent=hasName?num:'';
  var msgs=allMsgs.filter(function(m){{return normalizeNum(m.number)===num;}});
  msgs.sort(function(a,b){{return a.ts.localeCompare(b.ts);}});
  var el=document.getElementById('chatMessages');
  el.innerHTML=msgs.map(function(m){{
    return '<div class="bubble-wrap '+m.dir+'"><div class="bubble '+m.dir+'">'+esc(m.body)+'</div>'+
      '<div class="bubble-time">'+esc(m.ts)+'</div></div>';
  }}).join('');
  el.scrollTop=el.scrollHeight;
  document.getElementById('number').value=num;
  renderContacts(buildContacts(allMsgs));
}}
document.getElementById('msg').addEventListener('input',function(){{
  var n=this.value.length,pct=Math.round(n/160*100);
  document.getElementById('barFill').style.width=pct+'%';
  document.getElementById('barFill').style.background=n>=160?'#ef4444':n>=130?'#f59e0b':'#3b5bdb';
  document.getElementById('charTxt').textContent=n+' / 160';
}});
document.getElementById('chatMsg').addEventListener('input',function(){{
  document.getElementById('chatCharTxt').textContent=this.value.length+' / 160';
}});
async function sendChat(){{
  if(!activeContact) return;
  var m=document.getElementById('chatMsg').value.trim();
  if(!m) return;
  var btn=document.getElementById('chatSendBtn');btn.disabled=true;
  try{{
    var r=await fetch('/api/sms/send',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{number:activeContact,message:m}})}});
    var d=await r.json();
    if(d.ok){{document.getElementById('chatMsg').value='';document.getElementById('chatCharTxt').textContent='0 / 160';await loadInbox();openContact(activeContact);}}
    else alert('Greška: '+(d.error||'Nepoznata greška'));
  }}catch(e){{alert('Greška konekcije');}}
  btn.disabled=false;
}}
async function doSend(){{
  var num=document.getElementById('number').value.trim();
  var m=document.getElementById('msg').value.trim();
  if(!num||!m){{showToast('Unesite broj i poruku.','err');return;}}
  var btn=document.getElementById('sendBtn');btn.disabled=true;
  try{{
    var r=await fetch('/api/sms/send',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{number:num,message:m}})}});
    var d=await r.json();
    if(d.ok){{showToast('Poslato na '+num,'ok');document.getElementById('msg').value='';document.getElementById('barFill').style.width='0%';document.getElementById('charTxt').textContent='0 / 160';await loadInbox();openContact(normalizeNum(num));}}
    else showToast(d.error||'Greška','err');
  }}catch(e){{showToast('Greška konekcije','err');}}
  btn.disabled=false;
}}
async function loadInbox(){{
  try{{
    var r=await fetch('/api/sms');
    var data=await r.json();
    allMsgs=data;
    renderContacts(buildContacts(data));
    if(activeContact) openContact(activeContact);
    document.getElementById('dot').className='dot ok';
    document.getElementById('statusTxt').textContent=data.length+' poruka';
  }}catch(e){{
    document.getElementById('dot').className='dot err';
    document.getElementById('statusTxt').textContent='Server nedostupan';
  }}
}}
function showToast(txt,type){{
  var t=document.getElementById('toast');t.textContent=txt;t.className='toast '+type;t.style.display='block';
  clearTimeout(t._t);t._t=setTimeout(function(){{t.style.display='none';}},4500);
}}
document.addEventListener('click',function(e){{
  var item=e.target.closest('[data-num]');
  if(item) openContact(item.getAttribute('data-num'));
}});
loadInbox();
setInterval(loadInbox,12000);
</script>
</body>
</html>"""
