/* app.js — Shared utilities for BugCopilot frontend */

const API = {
  async get(path) {
    const r = await fetch(`/api${path}`);
    if (!r.ok) throw new Error(`API error ${r.status}: ${await r.text()}`);
    return r.json();
  },
  async post(path, body) {
    const r = await fetch(`/api${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!r.ok) throw new Error(`API error ${r.status}: ${await r.text()}`);
    return r.json();
  },
  async put(path, body) {
    const r = await fetch(`/api${path}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!r.ok) throw new Error(`API error ${r.status}: ${await r.text()}`);
    return r.json();
  },
  async delete(path) {
    const r = await fetch(`/api${path}`, { method: 'DELETE' });
    if (!r.ok) throw new Error(`API error ${r.status}: ${await r.text()}`);
    return r.json();
  },
};

// ── Toast notifications ────────────────────────────────────────────────────────
function toast(message, type = 'info', duration = 3500) {
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    document.body.appendChild(container);
  }
  const icons = { success: '✅', error: '❌', info: 'ℹ️' };
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.innerHTML = `<span>${icons[type] || 'ℹ️'}</span><span>${message}</span>`;
  container.appendChild(el);
  setTimeout(() => {
    el.style.opacity = '0';
    el.style.transform = 'translateX(20px)';
    el.style.transition = 'all 0.3s ease';
    setTimeout(() => el.remove(), 300);
  }, duration);
}

// ── Sidebar / Active nav ───────────────────────────────────────────────────────
function markActiveNav() {
  const path = window.location.pathname.replace(/\/$/, '') || '/';
  document.querySelectorAll('.nav-link').forEach(link => {
    const href = link.getAttribute('href') || '';
    const match = href === path || (path !== '/' && href !== '/' && path.startsWith(href));
    link.classList.toggle('active', match);
  });
}

// ── Load scope badge in sidebar ────────────────────────────────────────────────
async function loadScopeBadge() {
  const badge = document.getElementById('scope-badge');
  if (!badge) return;
  try {
    const scope = await API.get('/scope/active');
    if (scope && scope.authorized) {
      badge.querySelector('.value').textContent = scope.program_name || 'Active';
      badge.querySelector('.label').textContent = `${scope.platform || 'Scope'} · Active`;
      badge.classList.remove('unauthorized');
    } else if (scope) {
      badge.querySelector('.value').textContent = scope.program_name;
      badge.querySelector('.label').textContent = 'Not authorized';
      badge.classList.add('unauthorized');
    } else {
      badge.querySelector('.value').textContent = 'No scope set';
      badge.querySelector('.label').textContent = 'Set up scope first';
      badge.classList.add('unauthorized');
    }
  } catch (e) {
    badge.querySelector('.value').textContent = 'Error loading';
    badge.classList.add('unauthorized');
  }
}

// ── Severity utilities ─────────────────────────────────────────────────────────
function severityBadge(sev) {
  const map = {
    Critical: 'badge-critical',
    High: 'badge-high',
    Medium: 'badge-medium',
    Low: 'badge-low',
    Informational: 'badge-info',
    Info: 'badge-info',
  };
  return `<span class="badge ${map[sev] || 'badge-info'}">${sev}</span>`;
}

function statusChip(status) {
  return `<span class="status-chip chip-${status}">${status}</span>`;
}

function scoreClass(score) {
  if (score >= 7) return 'score-high';
  if (score >= 4) return 'score-medium';
  return 'score-low';
}

// ── Copy to clipboard ──────────────────────────────────────────────────────────
function copyText(text, btn) {
  navigator.clipboard.writeText(text).then(() => {
    const orig = btn.textContent;
    btn.textContent = 'Copied!';
    btn.style.color = 'var(--accent)';
    setTimeout(() => { btn.textContent = orig; btn.style.color = ''; }, 1500);
  }).catch(() => toast('Copy failed', 'error'));
}

function addCopyButtons() {
  document.querySelectorAll('pre:not(.has-copy)').forEach(pre => {
    pre.classList.add('has-copy');
    const wrapper = document.createElement('div');
    wrapper.className = 'code-block-wrapper';
    pre.parentNode.insertBefore(wrapper, pre);
    wrapper.appendChild(pre);
    const btn = document.createElement('button');
    btn.className = 'copy-btn';
    btn.textContent = 'Copy';
    btn.addEventListener('click', () => copyText(pre.textContent, btn));
    wrapper.appendChild(btn);
  });
}

// ── Pill input component ───────────────────────────────────────────────────────
function initPillInput(wrapperId, hiddenInputId) {
  const wrapper = document.getElementById(wrapperId);
  const hidden = document.getElementById(hiddenInputId);
  if (!wrapper || !hidden) return;

  const pills = [];
  const textInput = wrapper.querySelector('.pill-input');

  function renderPills() {
    wrapper.querySelectorAll('.pill').forEach(p => p.remove());
    pills.forEach((val, idx) => {
      const pill = document.createElement('span');
      pill.className = 'pill';
      pill.innerHTML = `${escapeHtml(val)}<span class="remove-pill" data-idx="${idx}">×</span>`;
      wrapper.insertBefore(pill, textInput);
    });
    hidden.value = JSON.stringify(pills);
  }

  function addPill(val) {
    val = val.trim();
    if (val && !pills.includes(val)) {
      pills.push(val);
      renderPills();
    }
  }

  textInput.addEventListener('keydown', e => {
    if (e.key === 'Enter' || e.key === ',') {
      e.preventDefault();
      addPill(textInput.value);
      textInput.value = '';
    }
    if (e.key === 'Backspace' && !textInput.value && pills.length) {
      pills.pop();
      renderPills();
    }
  });

  textInput.addEventListener('blur', () => {
    if (textInput.value.trim()) {
      addPill(textInput.value);
      textInput.value = '';
    }
  });

  wrapper.addEventListener('click', e => {
    if (e.target.classList.contains('remove-pill')) {
      const idx = parseInt(e.target.dataset.idx);
      pills.splice(idx, 1);
      renderPills();
    }
    textInput.focus();
  });

  return { pills, addPill };
}

// ── Tabs ───────────────────────────────────────────────────────────────────────
function initTabs(containerSelector) {
  document.querySelectorAll(containerSelector || '.tabs').forEach(tabBar => {
    tabBar.querySelectorAll('.tab-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const target = btn.dataset.tab;
        // Deactivate all in this group
        const parent = tabBar.parentElement;
        tabBar.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        parent.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        // Activate clicked
        btn.classList.add('active');
        const content = parent.querySelector(`[data-tab-content="${target}"]`);
        if (content) content.classList.add('active');
      });
    });
  });
}

// ── Confirm dialog ──────────────────────────────────────────────────────────────
function confirm(message) {
  return window.confirm(message);
}

// ── Date formatting ────────────────────────────────────────────────────────────
function fmtDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
}
function fmtDateTime(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}
function fmtCurrency(n) {
  return n >= 1000 ? `$${(n/1000).toFixed(1)}k` : `$${n}`;
}

// ── Escape HTML ────────────────────────────────────────────────────────────────
function escapeHtml(str) {
  const d = document.createElement('div');
  d.appendChild(document.createTextNode(str));
  return d.innerHTML;
}

// ── Auto-resize textarea ───────────────────────────────────────────────────────
function autoResize(el) {
  el.style.height = 'auto';
  el.style.height = Math.min(el.scrollHeight, 300) + 'px';
}

// ── Init on page load ──────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  markActiveNav();
  loadScopeBadge();
  initTabs();
  addCopyButtons();
});
