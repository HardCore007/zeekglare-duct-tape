/* ZeekGlare shared widgets — Active Scans, System Health, Quick Actions.
   Loaded on Xpl03tEr and Misc dashboards; main Intelligence dashboard has its
   own richer copies already, so this script no-ops there. */
(function(){
  if (window.__zgWidgetsLoaded) return;
  window.__zgWidgetsLoaded = true;

  // Skip on main dashboard (which has its own widgets)
  if (document.getElementById('hw-tab') || document.getElementById('sw-tab')) return;

  var CSS = [
    '@keyframes zgwPulse{0%,100%{opacity:1}50%{opacity:.35}}',
    '@keyframes zgwFabIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}',
    '.zgw-tray{position:fixed;right:0;z-index:499;display:flex;align-items:stretch;font-family:Inter,system-ui,sans-serif}',
    '.zgw-tab{width:28px;min-height:90px;background:#1a1d2e;border:1px solid #2a2f45;border-right:none;border-radius:8px 0 0 8px;cursor:pointer;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:6px;padding:8px 0;box-shadow:-2px 0 12px rgba(0,0,0,.35);transition:background .2s}',
    '.zgw-tab:hover{background:#242947}',
    '.zgw-tab .zgw-lbl{writing-mode:vertical-rl;text-orientation:mixed;font-size:9px;font-weight:600;color:#94a3b8;letter-spacing:1px}',
    '.zgw-dot{width:8px;height:8px;border-radius:50%}',
    '.zgw-body{width:0;overflow:hidden;transition:width .32s cubic-bezier(.4,0,.2,1)}',
    '.zgw-card{background:#1a1d2e;border:1px solid #2a2f45;border-right:none;box-shadow:-4px 0 24px rgba(0,0,0,.35);height:100%;display:flex;flex-direction:column}',
    '.zgw-head{display:flex;align-items:center;gap:8px;padding:12px 14px 8px;border-bottom:1px solid #2a2f45;user-select:none}',
    '.zgw-head .zgw-title{font-size:12px;font-weight:600;color:#e6e8f0;flex:1}',
    '.zgw-head .zgw-badge{font-size:10px;padding:2px 8px;border-radius:3px;font-weight:600;background:rgba(148,163,184,.15);color:#94a3b8}',
    '.zgw-head .zgw-close{background:none;border:none;color:#94a3b8;cursor:pointer;padding:2px;border-radius:3px;display:flex;align-items:center}',
    '.zgw-head .zgw-close:hover{color:#e6e8f0}',
    '#zgw-sw-body{padding:8px 10px 12px;overflow-y:auto;max-height:340px;font-size:11px}',
    '.zgw-empty{text-align:center;color:#64748b;padding:20px 8px;font-size:11px}',
    '.zgw-scan{background:#0f1220;border:1px solid #2a2f45;border-left-width:3px;border-radius:4px;padding:7px 9px;margin-bottom:6px}',
    '#zgw-hw-body{display:grid;grid-template-columns:1fr 1fr;gap:6px;font-size:11px;padding:10px 14px}',
    '#zgw-hw-body .k{color:#94a3b8}',
    '#zgw-hw-body .v{color:#e6e8f0;text-align:right;font-family:"JetBrains Mono",monospace}',
    '#zgw-hw-dots{display:flex;gap:3px;flex-wrap:wrap;padding:0 14px 12px}',
    '#zgw-hw-dots div{width:8px;height:8px;border-radius:2px}',
    '#zgw-fab{position:fixed;bottom:22px;right:22px;z-index:600;display:flex;flex-direction:column-reverse;align-items:flex-end;gap:8px}',
    '#zgw-fab-btn{width:48px;height:48px;border-radius:50%;background:linear-gradient(135deg,#6366f1,#8b5cf6);border:none;color:#fff;cursor:pointer;box-shadow:0 4px 20px rgba(99,102,241,.45);display:flex;align-items:center;justify-content:center;transition:transform .15s}',
    '#zgw-fab-btn:hover{transform:scale(1.06)}',
    '#zgw-fab-actions{display:none;flex-direction:column;gap:6px;align-items:flex-end}',
    '#zgw-fab-actions.open{display:flex}',
    '.zgw-fab-a{display:flex;align-items:center;gap:10px;cursor:pointer;animation:zgwFabIn .2s ease;text-decoration:none}',
    '.zgw-fab-a span{font-size:11px;color:#e6e8f0;background:#1a1d2e;border:1px solid #2a2f45;padding:6px 10px;border-radius:6px;box-shadow:0 2px 10px rgba(0,0,0,.3)}',
    '.zgw-fab-ic{width:36px;height:36px;border-radius:50%;color:#fff;display:flex;align-items:center;justify-content:center;font-size:16px;box-shadow:0 4px 14px rgba(0,0,0,.4)}'
  ].join('\n');

  var st = document.createElement('style'); st.textContent = CSS; document.head.appendChild(st);

  // ── Active Scans tray ───────────────────────────────────────────────────
  var scansWrap = document.createElement('div');
  scansWrap.className = 'zgw-tray';
  scansWrap.id = 'zgw-scans';
  scansWrap.style.top = 'calc(50% + 120px)';
  scansWrap.innerHTML =
    '<div class="zgw-tab" id="zgw-sw-tab" title="Active Scans">' +
      '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#6366f1" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>' +
      '<span class="zgw-dot" id="zgw-sw-dot" style="background:#64748b;box-shadow:0 0 6px #64748b"></span>' +
      '<span class="zgw-lbl">SCANS</span>' +
    '</div>' +
    '<div class="zgw-body" id="zgw-sw-body-wrap">' +
      '<div class="zgw-card" style="width:280px">' +
        '<div class="zgw-head">' +
          '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#6366f1" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>' +
          '<span class="zgw-title">Active Scans</span>' +
          '<span class="zgw-badge" id="zgw-sw-badge">0</span>' +
          '<button class="zgw-close" id="zgw-sw-close"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg></button>' +
        '</div>' +
        '<div id="zgw-sw-body">' +
          '<div id="zgw-sw-empty" class="zgw-empty">No active scans</div>' +
          '<div id="zgw-sw-list"></div>' +
        '</div>' +
      '</div>' +
    '</div>';
  document.body.appendChild(scansWrap);

  // ── System Health tray ──────────────────────────────────────────────────
  var hwWrap = document.createElement('div');
  hwWrap.className = 'zgw-tray';
  hwWrap.id = 'zgw-health';
  hwWrap.style.top = '50%';
  hwWrap.style.transform = 'translateY(-50%)';
  hwWrap.innerHTML =
    '<div class="zgw-tab" id="zgw-hw-tab" title="System Health">' +
      '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#22c55e" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>' +
      '<span class="zgw-dot" style="background:#22c55e;box-shadow:0 0 6px #22c55e"></span>' +
      '<span class="zgw-lbl">HEALTH</span>' +
    '</div>' +
    '<div class="zgw-body" id="zgw-hw-body-wrap">' +
      '<div class="zgw-card" style="width:240px">' +
        '<div class="zgw-head">' +
          '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#22c55e" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>' +
          '<span class="zgw-title">System Health</span>' +
          '<span class="zgw-badge" id="zgw-hw-badge" style="background:rgba(34,197,94,.15);color:#22c55e">…</span>' +
          '<button class="zgw-close" id="zgw-hw-close"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg></button>' +
        '</div>' +
        '<div id="zgw-hw-body">' +
          '<div class="k">Tools Ready</div><div class="v" id="zgw-hw-tools">–/–</div>' +
          '<div class="k">Disk Free</div><div class="v" id="zgw-hw-disk">–</div>' +
          '<div class="k">Sessions</div><div class="v" id="zgw-hw-ses">–</div>' +
          '<div class="k">Uptime</div><div class="v" id="zgw-hw-up">–</div>' +
        '</div>' +
        '<div id="zgw-hw-dots"></div>' +
      '</div>' +
    '</div>';
  document.body.appendChild(hwWrap);

  // ── Quick Actions FAB ───────────────────────────────────────────────────
  var fab = document.createElement('div');
  fab.id = 'zgw-fab';
  fab.innerHTML =
    '<button id="zgw-fab-btn" title="Quick Actions">' +
      '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>' +
    '</button>' +
    '<div id="zgw-fab-actions">' +
      '<a class="zgw-fab-a" href="/"><span>Intelligence</span><div class="zgw-fab-ic" style="background:#6366f1">&#127760;</div></a>' +
      '<a class="zgw-fab-a" href="/xploiter/"><span>Xpl03tEr</span><div class="zgw-fab-ic" style="background:#ef4444">&#9889;</div></a>' +
      '<a class="zgw-fab-a" href="/misc/"><span>Misc Tools</span><div class="zgw-fab-ic" style="background:#2dd4bf">&#128736;</div></a>' +
      '<a class="zgw-fab-a" href="/#sessions"><span>Sessions</span><div class="zgw-fab-ic" style="background:#22c55e">&#128190;</div></a>' +
      '<a class="zgw-fab-a" href="/watchdog" target="_blank"><span>WatchDog</span><div class="zgw-fab-ic" style="background:#f59e0b">&#128065;</div></a>' +
      '<a class="zgw-fab-a" href="/logout"><span>Sign Out</span><div class="zgw-fab-ic" style="background:#64748b">&#128682;</div></a>' +
    '</div>';
  document.body.appendChild(fab);

  // ── Tray collapse behaviour ─────────────────────────────────────────────
  function setTray(bodyId, tabId, open, width){
    document.getElementById(bodyId).style.width = open ? width + 'px' : '0';
    try { localStorage.setItem(tabId + '_open', open ? '1' : '0'); } catch(e) {}
  }
  var swOpen = (localStorage.getItem('zgw-sw-tab_open') || '1') === '1';
  var hwOpen = (localStorage.getItem('zgw-hw-tab_open') || '1') === '1';
  setTray('zgw-sw-body-wrap', 'zgw-sw-tab', swOpen, 280);
  setTray('zgw-hw-body-wrap', 'zgw-hw-tab', hwOpen, 240);
  document.getElementById('zgw-sw-tab').addEventListener('click', function(){ swOpen = !swOpen; setTray('zgw-sw-body-wrap', 'zgw-sw-tab', swOpen, 280); });
  document.getElementById('zgw-hw-tab').addEventListener('click', function(){ hwOpen = !hwOpen; setTray('zgw-hw-body-wrap', 'zgw-hw-tab', hwOpen, 240); });
  document.getElementById('zgw-sw-close').addEventListener('click', function(e){ e.stopPropagation(); swOpen = false; setTray('zgw-sw-body-wrap', 'zgw-sw-tab', false, 280); });
  document.getElementById('zgw-hw-close').addEventListener('click', function(e){ e.stopPropagation(); hwOpen = false; setTray('zgw-hw-body-wrap', 'zgw-hw-tab', false, 240); });

  // ── FAB toggle ──────────────────────────────────────────────────────────
  var fabBtn = document.getElementById('zgw-fab-btn');
  var fabAct = document.getElementById('zgw-fab-actions');
  fabBtn.addEventListener('click', function(e){ e.stopPropagation(); fabAct.classList.toggle('open'); });
  document.addEventListener('click', function(){ fabAct.classList.remove('open'); });

  // ── API: health ─────────────────────────────────────────────────────────
  function fmtElapsed(s){ s = Math.max(0, s|0); if(s<60) return s+'s'; if(s<3600) return Math.floor(s/60)+'m '+(s%60)+'s'; return Math.floor(s/3600)+'h '+Math.floor((s%3600)/60)+'m'; }
  function esc(s){ return String(s||'').replace(/[&<>"]/g, function(c){ return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]; }); }

  async function loadHealth(){
    try {
      var r = await fetch('/api/tools/health', {credentials:'same-origin'});
      if (!r.ok) throw new Error(r.status);
      var h = await r.json();
      document.getElementById('zgw-hw-tools').textContent = h.tools_installed + '/' + h.tools_total;
      document.getElementById('zgw-hw-disk').textContent = h.disk_free_gb + ' GB';
      document.getElementById('zgw-hw-ses').textContent = h.sessions_saved;
      var up = h.uptime_s || 0;
      var uh = Math.floor(up/3600), um = Math.floor((up%3600)/60);
      document.getElementById('zgw-hw-up').textContent = uh > 0 ? uh+'h '+um+'m' : um+'m';
      var pct = h.tools_installed / Math.max(1, h.tools_total);
      var badge = document.getElementById('zgw-hw-badge');
      if (pct >= 0.85) { badge.textContent = 'Healthy'; badge.style.background = 'rgba(34,197,94,.15)'; badge.style.color = '#22c55e'; }
      else if (pct >= 0.5) { badge.textContent = 'Partial'; badge.style.background = 'rgba(245,158,11,.15)'; badge.style.color = '#f59e0b'; }
      else { badge.textContent = 'Limited'; badge.style.background = 'rgba(239,68,68,.15)'; badge.style.color = '#ef4444'; }
      var dots = document.getElementById('zgw-hw-dots');
      dots.innerHTML = (h.tools || []).map(function(t){ return '<div title="'+esc(t.name)+' — '+(t.installed?'installed':'missing')+'" style="background:'+(t.installed?'#22c55e':'#ef4444')+';opacity:'+(t.installed?'.75':'.4')+'"></div>'; }).join('');
    } catch(e) { /* silent */ }
  }

  var SW_COLORS = {wpscan:'#3b82f6',threatblitz:'#ef4444',fuzzer:'#f59e0b',ports:'#22d3ee',paramhawk:'#a855f7',crawler:'#10b981',sudomy:'#f472b6',cve:'#dc2626',ipmapper:'#0ea5e9',jsanalysis:'#eab308',recon_extra:'#8b5cf6',asn:'#6366f1',domain:'#2dd4bf',recon:'#10b981',dns:'#f59e0b'};

  async function loadScans(){
    try {
      var r = await fetch('/api/scans/active', {credentials:'same-origin'});
      if (!r.ok) throw new Error(r.status);
      var d = await r.json();
      var list = document.getElementById('zgw-sw-list');
      var empty = document.getElementById('zgw-sw-empty');
      var badge = document.getElementById('zgw-sw-badge');
      var dot   = document.getElementById('zgw-sw-dot');
      var scans = d.scans || [];
      badge.textContent = scans.length;
      if (scans.length === 0) {
        badge.style.background = 'rgba(148,163,184,.15)'; badge.style.color = '#94a3b8';
        dot.style.background = '#64748b'; dot.style.boxShadow = '0 0 6px #64748b';
        empty.style.display = 'block'; list.innerHTML = ''; return;
      }
      badge.style.background = 'rgba(99,102,241,.18)'; badge.style.color = '#6366f1';
      dot.style.background = '#6366f1'; dot.style.boxShadow = '0 0 8px #6366f1';
      empty.style.display = 'none';
      list.innerHTML = scans.map(function(s){
        var color = SW_COLORS[s.tool] || SW_COLORS[s.source] || '#6366f1';
        var tool = (s.tool || s.source || '').toUpperCase();
        var status = (s.status || 'running');
        var prog = (typeof s.progress === 'number') ? ' '+Math.round(s.progress)+'%' : '';
        var user = s.username ? ' · '+esc(s.username) : '';
        var mode = s.mode ? ' · '+esc(s.mode) : '';
        return '<div class="zgw-scan" style="border-left-color:'+color+'">' +
          '<div style="display:flex;align-items:center;gap:6px;margin-bottom:3px">' +
            '<span style="font-size:9px;font-weight:700;letter-spacing:.5px;color:'+color+'">'+esc(tool)+'</span>' +
            '<span style="flex:1"></span>' +
            '<span style="font-size:10px;color:#94a3b8;font-family:\'JetBrains Mono\',monospace">'+fmtElapsed(s.elapsed_s)+'</span>' +
            '<span style="width:6px;height:6px;border-radius:50%;background:'+color+';box-shadow:0 0 6px '+color+';animation:zgwPulse 1.4s ease-in-out infinite"></span>' +
          '</div>' +
          '<div style="font-size:10px;color:#e6e8f0;word-break:break-all;line-height:1.35">'+esc(s.target || '(no target)')+'</div>' +
          '<div style="font-size:9px;color:#64748b;margin-top:2px">' +
            '<span style="padding:1px 6px;background:'+color+'22;color:'+color+';border-radius:3px;text-transform:uppercase;letter-spacing:.5px;font-weight:600">'+esc(status)+prog+'</span>' +
            (mode||user ? '<span style="margin-left:6px">'+(mode+user).replace(/^ · /,'')+'</span>' : '') +
          '</div>' +
        '</div>';
      }).join('');
    } catch(e) { /* silent */ }
  }

  loadHealth(); loadScans();
  setInterval(loadHealth, 300000);
  setInterval(loadScans, 4000);
})();
