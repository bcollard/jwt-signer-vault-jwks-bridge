/* jwks-bridge site behaviour, shared by every page. No dependencies.
   Each block is independent and returns early when its elements are absent. */

/* theme toggle: auto -> light -> dark -> auto. The stored choice is applied
   by an inline snippet in <head> so the page never flashes the wrong theme. */
(function () {
  var root = document.documentElement;
  var btn = document.getElementById('themeToggle');
  if (!btn) return;
  btn.addEventListener('click', function () {
    var cur = root.getAttribute('data-theme') || 'auto';
    var next = cur === 'auto' ? 'light' : cur === 'light' ? 'dark' : 'auto';
    root.setAttribute('data-theme', next);
    btn.title = 'Theme: ' + next;
    try {
      if (next === 'auto') localStorage.removeItem('jwksb-theme');
      else localStorage.setItem('jwksb-theme', next);
    } catch (e) {}
  });
  btn.title = 'Theme: ' + (root.getAttribute('data-theme') || 'auto');
})();

/* latest release in the nav. The page ships the version current when it was
   generated; this refreshes it from the GitHub API, cached for an hour so
   browsing the docs costs one request (the API allows 60 per hour per IP). */
(function () {
  var el = document.getElementById('navVersion');
  if (!el || !window.fetch) return;
  var KEY = 'jwksb-release', TTL = 3600 * 1000;
  function show(tag) { if (tag) { el.textContent = tag; el.title = 'Latest release: ' + tag; } }
  try {
    var cached = JSON.parse(sessionStorage.getItem(KEY) || 'null');
    if (cached && Date.now() - cached.at < TTL) { show(cached.tag); return; }
  } catch (e) {}
  fetch('https://api.github.com/repos/bcollard/jwt-signer-vault-jwks-bridge/releases/latest', { headers: { Accept: 'application/vnd.github+json' } })
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(function (d) {
      if (!d || !d.tag_name) return;
      show(d.tag_name);
      try { sessionStorage.setItem(KEY, JSON.stringify({ tag: d.tag_name, at: Date.now() })); } catch (e) {}
    })
    .catch(function () {});
})();

/* docs sidebar: open on desktop, collapsed behind "Documentation menu" on phones */
(function () {
  var sb = document.getElementById('docsSidebar');
  if (sb && window.matchMedia('(min-width: 881px)').matches) sb.open = true;
})();

/* heading anchors: hover link icon on every h2/h3 with an id, click copies the URL */
(function () {
  var ICON = '<svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true"><path fill="currentColor" d="M7.775 3.275a.75.75 0 0 0 1.06 1.06l1.25-1.25a2 2 0 1 1 2.83 2.83l-2.5 2.5a2 2 0 0 1-2.83 0 .75.75 0 0 0-1.06 1.06 3.5 3.5 0 0 0 4.95 0l2.5-2.5a3.5 3.5 0 0 0-4.95-4.95l-1.25 1.25Zm-1.06 9.45a.75.75 0 0 0-1.06-1.06l-1.25 1.25a2 2 0 1 1-2.83-2.83l2.5-2.5a2 2 0 0 1 2.83 0 .75.75 0 0 0 1.06-1.06 3.5 3.5 0 0 0-4.95 0l-2.5 2.5a3.5 3.5 0 1 0 4.95 4.95l1.25-1.25Z"/></svg>';
  document.querySelectorAll('.docs-prose h2[id], .docs-prose h3[id]').forEach(function (h) {
    var a = document.createElement('a');
    a.className = 'anchor-link';
    a.href = '#' + h.id;
    a.setAttribute('aria-label', 'Copy link to this section');
    a.innerHTML = ICON;
    a.addEventListener('click', function (e) {
      e.preventDefault();
      var url = location.origin + location.pathname + '#' + h.id;
      if (history.replaceState) history.replaceState(null, '', '#' + h.id);
      var done = function () {
        a.classList.add('copied');
        setTimeout(function () { a.classList.remove('copied'); }, 1400);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(url).then(done, done);
      else done();
    });
    h.appendChild(a);
  });
})();

/* docs search over the prebuilt heading index (docs/search-index.js).
   Entry pages are relative to docs/docs/, which is where the search box lives. */
(function () {
  var input = document.getElementById('docsSearch');
  var list = document.getElementById('docsSearchResults');
  if (!input || !list) return;
  var index = window.JWKSB_DOCS_INDEX || [];
  var active = -1;

  function links() { return Array.prototype.slice.call(list.querySelectorAll('a')); }
  function close() { list.hidden = true; list.innerHTML = ''; active = -1; }
  function setActive(i) {
    var ls = links();
    if (!ls.length) return;
    if (ls[active]) ls[active].classList.remove('active');
    active = (i + ls.length) % ls.length;
    ls[active].classList.add('active');
    ls[active].scrollIntoView({ block: 'nearest' });
  }
  /* punctuation is ignored, so "pkcs12" finds "PKCS#12" and "force" finds "--force" */
  function norm(s) { return s.toLowerCase().replace(/[^a-z0-9\s]+/g, ''); }
  function score(e, words) {
    var t = norm(e.text), hay = norm(e.text + ' ' + e.title + ' ' + e.section);
    for (var i = 0; i < words.length; i++) if (hay.indexOf(words[i]) === -1) return -1;
    return (t.indexOf(words[0]) === 0 ? 0 : t.indexOf(words[0]) !== -1 ? 1 : 2) + (e.anchor ? 0.5 : 0);
  }
  function search() {
    var q = norm(input.value).trim();
    if (!q) { close(); return; }
    var words = q.split(/\s+/);
    var hits = index
      .map(function (e) { return { e: e, s: score(e, words) }; })
      .filter(function (h) { return h.s >= 0; })
      .sort(function (a, b) { return a.s - b.s; })
      .slice(0, 8);
    list.innerHTML = '';
    active = -1;
    if (!hits.length) {
      list.innerHTML = '<li class="r-none">No matching section</li>';
      list.hidden = false;
      return;
    }
    hits.forEach(function (h) {
      var m = h.e, li = document.createElement('li'), a = document.createElement('a');
      a.href = m.page + (m.anchor ? '#' + m.anchor : '');
      a.innerHTML = '<span class="r-title"></span><span class="r-path"></span>';
      a.querySelector('.r-title').textContent = m.text;
      a.querySelector('.r-path').textContent = !m.anchor ? 'Page' : (m.section && m.section !== m.text ? m.title + ' › ' + m.section : m.title);
      li.appendChild(a);
      list.appendChild(li);
    });
    list.hidden = false;
  }
  input.addEventListener('input', search);
  input.addEventListener('focus', search);
  input.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') { input.value = ''; close(); input.blur(); return; }
    if (e.key === 'ArrowDown' && !list.hidden) { e.preventDefault(); setActive(active + 1); return; }
    if (e.key === 'ArrowUp' && !list.hidden) { e.preventDefault(); setActive(active - 1); return; }
    if (e.key === 'Enter') {
      var ls = links(), t = ls[active] || ls[0];
      if (t) { e.preventDefault(); location.href = t.getAttribute('href'); }
    }
  });
  document.addEventListener('click', function (e) { if (e.target !== input && !list.contains(e.target)) list.hidden = true; });
  document.addEventListener('keydown', function (e) {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); input.focus(); input.select(); }
  });
})();

/* copy buttons: <button class="copy-btn" data-copy="text"> */
(function () {
  document.querySelectorAll('.copy-btn[data-copy]').forEach(function (b) {
    b.addEventListener('click', function () {
      var reset = function () { setTimeout(function () { b.textContent = 'Copy'; }, 1400); };
      if (!navigator.clipboard) return;
      navigator.clipboard.writeText(b.getAttribute('data-copy')).then(function () { b.textContent = 'Copied'; reset(); });
    });
  });
})();

/* full-screen viewer for <a class="zoomable" href="image"><img></a>.
   Pinch or ctrl+wheel zooms around the pointer, scroll or drag pans, +/-/0 keys, Esc closes.
   The image is resized (not CSS-scaled) so SVGs stay sharp at any zoom. */
(function () {
  var links = document.querySelectorAll('a.zoomable');
  if (!links.length) return;
  var viewer = document.createElement('div');
  viewer.className = 'zoom-viewer';
  viewer.hidden = true;
  viewer.setAttribute('role', 'dialog');
  viewer.setAttribute('aria-modal', 'true');
  viewer.innerHTML = '<div class="zoom-bar"><span class="zoom-level"></span>' +
    '<button type="button" data-z="out" aria-label="Zoom out">\u2212</button>' +
    '<button type="button" data-z="fit" aria-label="Fit to screen">Fit</button>' +
    '<button type="button" data-z="in" aria-label="Zoom in">+</button>' +
    '<button type="button" data-z="close" aria-label="Close">\u2715</button></div>' +
    '<div class="zoom-stage"><img alt=""></div>';
  document.body.appendChild(viewer);
  var stage = viewer.querySelector('.zoom-stage');
  var img = stage.querySelector('img');
  var level = viewer.querySelector('.zoom-level');
  var natW = 1, natH = 1, fit = 1, scale = 1, opener = null;

  function apply(next, cx, cy) {
    next = Math.min(Math.max(next, fit * 0.5), 8);
    // keep the point under (cx, cy) in place
    var r = stage.getBoundingClientRect();
    cx = cx === undefined ? r.width / 2 : cx - r.left;
    cy = cy === undefined ? r.height / 2 : cy - r.top;
    var fx = (stage.scrollLeft + cx) / (natW * scale), fy = (stage.scrollTop + cy) / (natH * scale);
    scale = next;
    img.style.width = Math.round(natW * scale) + 'px';
    img.style.height = Math.round(natH * scale) + 'px';
    stage.scrollLeft = fx * natW * scale - cx;
    stage.scrollTop = fy * natH * scale - cy;
    level.textContent = Math.round(scale * 100) + '%';
  }
  function fitScale() {
    var r = stage.getBoundingClientRect();
    return Math.min((r.width - 32) / natW, (r.height - 24) / natH);
  }
  function open(href, alt, a) {
    opener = a;
    img.alt = alt || '';
    viewer.hidden = false;
    document.documentElement.style.overflow = 'hidden';
    img.onload = function () {
      natW = img.naturalWidth || 1200; natH = img.naturalHeight || 800;
      fit = fitScale(); scale = fit; apply(fit);
    };
    img.src = href;
    viewer.querySelector('[data-z="close"]').focus();
  }
  function close() {
    viewer.hidden = true;
    document.documentElement.style.overflow = '';
    if (opener) opener.focus();
  }
  links.forEach(function (a) {
    a.addEventListener('click', function (e) {
      if (e.metaKey || e.ctrlKey || e.shiftKey) return; // let new-tab clicks through
      e.preventDefault();
      var i = a.querySelector('img');
      open(a.getAttribute('href'), i && i.alt, a);
    });
  });
  viewer.addEventListener('click', function (e) {
    var z = e.target.getAttribute && e.target.getAttribute('data-z');
    if (z === 'in') apply(scale * 1.25);
    else if (z === 'out') apply(scale / 1.25);
    else if (z === 'fit') apply(fit);
    else if (z === 'close' || e.target === stage) close();
  });
  // trackpad pinch arrives as ctrl+wheel; plain scrolling pans natively
  stage.addEventListener('wheel', function (e) {
    if (!e.ctrlKey && !e.metaKey) return;
    e.preventDefault();
    apply(scale * Math.exp(-e.deltaY * 0.01), e.clientX, e.clientY);
  }, { passive: false });
  document.addEventListener('keydown', function (e) {
    if (viewer.hidden) return;
    if (e.key === 'Escape') close();
    else if (e.key === '+' || e.key === '=') apply(scale * 1.25);
    else if (e.key === '-') apply(scale / 1.25);
    else if (e.key === '0') apply(fit);
  });
  window.addEventListener('resize', function () { if (!viewer.hidden) fit = fitScale(); });

  // drag to pan with one pointer, pinch to zoom with two
  var pts = {}, last = null, pinch = 0, moved = false;
  stage.addEventListener('pointerdown', function (e) {
    pts[e.pointerId] = e; stage.setPointerCapture(e.pointerId);
    stage.classList.add('dragging'); last = e; moved = false;
  });
  stage.addEventListener('pointermove', function (e) {
    if (!pts[e.pointerId]) return;
    pts[e.pointerId] = e;
    var ids = Object.keys(pts);
    if (ids.length === 2) {
      var a = pts[ids[0]], b = pts[ids[1]];
      var d = Math.hypot(a.clientX - b.clientX, a.clientY - b.clientY);
      if (pinch) apply(scale * d / pinch, (a.clientX + b.clientX) / 2, (a.clientY + b.clientY) / 2);
      pinch = d; moved = true;
    } else if (last) {
      stage.scrollLeft -= e.clientX - last.clientX;
      stage.scrollTop -= e.clientY - last.clientY;
      if (Math.abs(e.clientX - last.clientX) + Math.abs(e.clientY - last.clientY) > 0) moved = true;
      last = e;
    }
  });
  function up(e) {
    delete pts[e.pointerId];
    if (Object.keys(pts).length < 2) pinch = 0;
    if (!Object.keys(pts).length) { stage.classList.remove('dragging'); last = null; }
  }
  stage.addEventListener('pointerup', up);
  stage.addEventListener('pointercancel', up);
  // a click on the backdrop closes, but not the end of a drag
  stage.addEventListener('click', function (e) { if (moved) e.stopPropagation(); }, true);
})();
