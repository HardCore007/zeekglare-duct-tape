/* zgMultiSelect — turns a native <select multiple> (or a select upgraded with
   data-multi) into a compact checkbox dropdown.
   Usage:
     <select id="x" data-multi="true" data-all-label="All types">
       <option value="a">Apples</option>
       <option value="b" selected>Bananas</option>
     </select>
     zgMS.upgrade('#x', { onChange: function(vals){...} });
   API:
     zgMS.upgrade(selectorOrEl, opts)
     zgMS.getValues(selectorOrEl)      -> array
     zgMS.setValues(selectorOrEl, arr) -> void (fires change)
*/
(function(){
  if (window.zgMS) return;

  var CSS = [
    '.zgms{position:relative;display:inline-flex;vertical-align:middle;font:inherit;font-size:12px}',
    '.zgms-btn{display:inline-flex;align-items:center;gap:6px;cursor:pointer;font:inherit;font-size:12px;text-align:left;line-height:1.2;font-family:inherit}',
    '.zgms-btn:hover{border-color:var(--accent,#6366f1)}',
    '.zgms-btn .zgms-lbl{flex:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;min-width:0}',
    '.zgms-btn .zgms-caret{flex-shrink:0;opacity:.5;margin-left:2px}',
    '.zgms-btn .zgms-count{flex-shrink:0;font-size:10px;padding:0 5px;border-radius:8px;background:rgba(99,102,241,.18);color:var(--accent,#6366f1);font-weight:600;line-height:1.4}',
    '.zgms-pop{position:absolute;top:calc(100% + 4px);left:0;min-width:180px;max-width:320px;width:max-content;background:var(--bg2,#0f1220);border:1px solid var(--b2,#2a2f45);border-radius:6px;box-shadow:0 8px 24px rgba(0,0,0,.5);z-index:10050;padding:6px;display:none;max-height:300px;overflow:auto}',
    '.zgms.open .zgms-pop{display:block}',
    '.zgms-search{width:100%;background:var(--bg3,#1a1d2e);border:1px solid var(--b1,#242842);border-radius:4px;color:var(--t1,#e6e8f0);padding:5px 8px;font:inherit;font-size:11px;margin-bottom:4px;box-sizing:border-box}',
    '.zgms-row{display:flex;align-items:center;gap:8px;padding:5px 6px;border-radius:3px;cursor:pointer;color:var(--t2,#cbd5e1);font-size:12px;user-select:none}',
    '.zgms-row:hover{background:var(--bg3,#1a1d2e)}',
    '.zgms-row input{accent-color:var(--accent,#6366f1);margin:0;flex-shrink:0}',
    '.zgms-row.all{border-bottom:1px solid var(--b1,#242842);margin-bottom:4px;padding-bottom:7px;color:var(--t1,#e6e8f0);font-weight:600}',
    '.zgms-row .zgms-lbl-txt{flex:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}',
    '.zgms-row .zgms-swatch{width:8px;height:8px;border-radius:2px;flex-shrink:0}'
  ].join('\n');
  var st = document.createElement('style'); st.textContent = CSS; document.head.appendChild(st);

  function resolve(el){ return typeof el === 'string' ? document.querySelector(el) : el; }
  function getOptions(sel){
    return Array.prototype.map.call(sel.options, function(o){
      return { value: o.value, label: o.textContent, selected: o.selected, color: o.getAttribute('data-color') };
    });
  }

  function upgrade(target, opts){
    var sel = resolve(target);
    if (!sel || sel._zgMs) return;
    opts = opts || {};
    sel.multiple = true;
    sel.style.display = 'none';
    var allLabel = sel.getAttribute('data-all-label') || opts.allLabel || 'All';

    var wrap = document.createElement('div'); wrap.className = 'zgms';
    var btn  = document.createElement('button'); btn.type = 'button'; btn.className = 'zgms-btn';
    // Copy the original <select>'s inline styling so the button blends in with neighbouring native selects.
    if (sel.style.cssText) btn.style.cssText = sel.style.cssText + ';cursor:pointer;display:inline-flex;align-items:center;gap:6px';
    btn.innerHTML = '<span class="zgms-lbl">'+allLabel+'</span><span class="zgms-count" style="display:none">0</span><svg class="zgms-caret" width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="6 9 12 15 18 9"/></svg>';
    var pop  = document.createElement('div'); pop.className = 'zgms-pop';
    var search = document.createElement('input'); search.className = 'zgms-search'; search.placeholder = 'Filter…'; search.type = 'text';
    var rows = document.createElement('div');
    pop.appendChild(search); pop.appendChild(rows);
    wrap.appendChild(btn); wrap.appendChild(pop);
    sel.parentNode.insertBefore(wrap, sel.nextSibling);
    sel._zgMs = wrap;

    function currentValues(){
      return Array.prototype.filter.call(sel.options, function(o){ return o.selected && o.value !== ''; }).map(function(o){ return o.value; });
    }

    function render(filter){
      var options = getOptions(sel);
      var hasAllOpt = options.some(function(o){ return o.value === ''; });
      var f = (filter||'').toLowerCase();
      rows.innerHTML = '';
      if (hasAllOpt) {
        var allRow = document.createElement('label'); allRow.className = 'zgms-row all';
        var allCb = document.createElement('input'); allCb.type = 'checkbox';
        var checkedCount = currentValues().length;
        allCb.checked = checkedCount === 0;
        allCb.addEventListener('change', function(){
          Array.prototype.forEach.call(sel.options, function(o){ o.selected = false; });
          allCb.checked = true;
          updateBtn(); fire();
          render(search.value);
        });
        var allTxt = document.createElement('span'); allTxt.className = 'zgms-lbl-txt'; allTxt.textContent = allLabel;
        allRow.appendChild(allCb); allRow.appendChild(allTxt);
        rows.appendChild(allRow);
      }
      options.filter(function(o){ return o.value !== ''; }).forEach(function(o){
        if (f && o.label.toLowerCase().indexOf(f) < 0) return;
        var row = document.createElement('label'); row.className = 'zgms-row';
        var cb = document.createElement('input'); cb.type = 'checkbox'; cb.value = o.value; cb.checked = o.selected;
        cb.addEventListener('change', function(){
          var opt = Array.prototype.find.call(sel.options, function(x){ return x.value === o.value; });
          if (opt) opt.selected = cb.checked;
          updateBtn(); fire(); render(search.value);
        });
        row.appendChild(cb);
        if (o.color) { var sw = document.createElement('span'); sw.className = 'zgms-swatch'; sw.style.background = o.color; row.appendChild(sw); }
        var txt = document.createElement('span'); txt.className = 'zgms-lbl-txt'; txt.textContent = o.label;
        row.appendChild(txt);
        rows.appendChild(row);
      });
    }

    function updateBtn(){
      var vals = currentValues();
      var lbl = btn.querySelector('.zgms-lbl');
      var cnt = btn.querySelector('.zgms-count');
      if (vals.length === 0) {
        lbl.textContent = allLabel;
        cnt.style.display = 'none';
      } else if (vals.length === 1) {
        var o = Array.prototype.find.call(sel.options, function(x){ return x.value === vals[0]; });
        lbl.textContent = o ? o.textContent : vals[0];
        cnt.style.display = 'none';
      } else {
        lbl.textContent = vals.length + ' selected';
        cnt.textContent = vals.length;
        cnt.style.display = '';
      }
    }

    function fire(){
      sel.dispatchEvent(new Event('change', { bubbles: true }));
      if (typeof opts.onChange === 'function') opts.onChange(currentValues());
    }

    btn.addEventListener('click', function(e){
      e.stopPropagation();
      var was = wrap.classList.contains('open');
      document.querySelectorAll('.zgms.open').forEach(function(w){ w.classList.remove('open'); });
      if (!was) {
        wrap.classList.add('open'); search.value = ''; render(''); search.focus();
        // Flip pop if it would overflow right edge
        pop.style.left = '0'; pop.style.right = 'auto';
        var r = pop.getBoundingClientRect();
        if (r.right > window.innerWidth - 8) { pop.style.left = 'auto'; pop.style.right = '0'; }
      }
    });
    search.addEventListener('input', function(){ render(search.value); });
    search.addEventListener('click', function(e){ e.stopPropagation(); });
    document.addEventListener('click', function(e){ if (!wrap.contains(e.target)) wrap.classList.remove('open'); });

    updateBtn();
    render('');

    // Observe external changes to the native select
    sel.addEventListener('zgms:refresh', function(){ updateBtn(); render(search.value); });
  }

  function getValues(target){
    var sel = resolve(target); if (!sel) return [];
    return Array.prototype.filter.call(sel.options, function(o){ return o.selected && o.value !== ''; }).map(function(o){ return o.value; });
  }

  function setValues(target, arr){
    var sel = resolve(target); if (!sel) return;
    var set = {}; (arr || []).forEach(function(v){ set[v] = true; });
    Array.prototype.forEach.call(sel.options, function(o){ o.selected = !!set[o.value]; });
    sel.dispatchEvent(new Event('zgms:refresh'));
    sel.dispatchEvent(new Event('change', { bubbles: true }));
  }

  function upgradeAll(root){
    (root || document).querySelectorAll('select[data-multi="true"]').forEach(function(s){ upgrade(s); });
  }

  window.zgMS = { upgrade: upgrade, upgradeAll: upgradeAll, getValues: getValues, setValues: setValues };
  document.addEventListener('DOMContentLoaded', function(){ upgradeAll(); });
})();
