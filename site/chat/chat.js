/* readtheplan AI project guide — chat client.
   CSP-safe external module. Rendering is escape-first: agent replies pass
   through escapeHtml before limited markdown formatting is applied. */
"use strict";

const API = '/api/chat';
let history = [];

function escapeHtml(text) {
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function renderSafeMarkdown(text) {
  let rendered = escapeHtml(text);
  rendered = rendered.replace(/```(\w*)\n([\s\S]*?)```/g, '<pre><code>$2</code></pre>');
  rendered = rendered.replace(/`([^`]+)`/g, '<code>$1</code>');
  rendered = rendered.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
  rendered = rendered.replace(/\[([^\]]+)\]\(([^)]+)\)/g, (_match, label, href) => {
    try {
      const parsed = new URL(href);
      if (!['http:', 'https:'].includes(parsed.protocol)) return label;
      return `<a href="${escapeHtml(parsed.href)}" target="_blank" rel="noopener noreferrer">${label}</a>`;
    } catch {
      return label;
    }
  });
  return rendered.replace(/\n/g, '<br>');
}

function addMsg(role, text) {
  const div = document.createElement('div');
  div.className = 'msg ' + role;
  if (role === 'agent') {
    div.innerHTML = renderSafeMarkdown(text);
  } else {
    div.textContent = text;
  }
  document.getElementById('messages').appendChild(div);
  document.getElementById('messages').scrollTop = document.getElementById('messages').scrollHeight;
  return div;
}

function showTyping() {
  const div = document.createElement('div');
  div.className = 'typing';
  div.id = 'typing-indicator';
  div.textContent = '▋ thinking...';
  document.getElementById('messages').appendChild(div);
  document.getElementById('messages').scrollTop = document.getElementById('messages').scrollHeight;
}

function hideTyping() {
  const el = document.getElementById('typing-indicator');
  if (el) el.remove();
}

async function send() {
  const input = document.getElementById('userInput');
  const btn = document.getElementById('sendBtn');
  const err = document.getElementById('error');
  const text = input.value.trim();
  if (!text) return;

  input.value = '';
  btn.disabled = true;
  err.replaceChildren();
  err.style.display = 'none';
  document.getElementById('suggestions').style.display = 'none';

  const userMessage = addMsg('user', text);
  history.push({ role: 'user', content: text });
  showTyping();

  try {
    const resp = await fetch(API, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ messages: history.slice(-10) })
    });
    const isJson = (resp.headers.get('Content-Type') || '').includes('application/json');
    const data = isJson ? await resp.json() : {};
    if (!resp.ok) {
      const retryAfter = resp.headers.get('Retry-After');
      const message = resp.status === 429
        ? `Too many requests. Try again${retryAfter ? ` in ${retryAfter} seconds` : ' shortly'}.`
        : (data.reply || data.error || `The AI service is temporarily unavailable (HTTP ${resp.status}).`);
      throw new Error(message);
    }
    hideTyping();
    const reply = data.reply || "Sorry, I couldn't process that. Try rephrasing?";
    addMsg('agent', reply);
    history.push({ role: 'assistant', content: reply });
  } catch (e) {
    hideTyping();
    err.append(document.createTextNode(e.message || 'Connection error — try again in a moment.'));
    const retry = document.createElement('button');
    retry.type = 'button';
    retry.textContent = 'Retry';
    retry.addEventListener('click', () => {
      userMessage.remove();
      input.value = text;
      send();
    });
    err.appendChild(retry);
    err.style.display = 'block';
    // Remove the user message from history so retry works
    history.pop();
  } finally {
    btn.disabled = false;
    input.focus();
  }
}

/* Wiring is guarded so the module can also be loaded by the contract tests
   outside a browser. */
if (typeof document !== 'undefined') {
  document.getElementById('sendBtn').addEventListener('click', send);
  document.getElementById('userInput').addEventListener('keydown', (event) => {
    if (event.key === 'Enter') send();
  });
  document.querySelectorAll('.suggestion[data-ask]').forEach((button) => {
    button.addEventListener('click', () => {
      document.getElementById('userInput').value = button.getAttribute('data-ask');
      send();
    });
  });
}
