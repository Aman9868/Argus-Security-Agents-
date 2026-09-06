// =========================================================================
// CYBER AI COPILOT INTERFACE MODULE
// =========================================================================

let copilotWidgetActive = false;
let copilotFontSize = 13;

function getCopilotFeed() {
  return document.getElementById('copilotFeed') || document.getElementById('copilotMessages');
}

function adjustCopilotFontSize(delta) {
  copilotFontSize = Math.min(18, Math.max(10, copilotFontSize + delta));
  const feed = getCopilotFeed();
  if (feed) {
    feed.style.fontSize = `${copilotFontSize}px`;
  }
}

function toggleCopilotWidget() {
  const widget = document.getElementById('copilotWidget');
  const launcher = document.getElementById('copilotLauncherBtn');
  if (!widget) return;

  copilotWidgetActive = !copilotWidgetActive;
  if (copilotWidgetActive) {
    widget.classList.add('active');
    if (launcher) launcher.classList.add('hidden');
    const input = document.getElementById('copilotInput');
    if (input) {
      setTimeout(() => input.focus(), 150);
    }
  } else {
    widget.classList.remove('active');
    if (launcher) launcher.classList.remove('hidden');
  }
}

function toggleWidgetWide() {
  const widget = document.getElementById('copilotWidget');
  if (widget) widget.classList.toggle('widget-wide');
}

function toggleWidgetFullscreen() {
  const widget = document.getElementById('copilotWidget');
  if (widget) widget.classList.toggle('widget-fullscreen');
}

function safeEscapeHtml(str) {
  if (typeof escapeHtml === 'function') return escapeHtml(str);
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function formatCopilotMarkdown(text) {
  if (!text) return '';
  if (typeof marked !== 'undefined' && typeof marked.parse === 'function') {
    return marked.parse(text);
  }
  let escaped = safeEscapeHtml(text);
  escaped = escaped.replace(/```([\s\S]*?)```/g, '<pre class="mockup-code-block"><code>$1</code></pre>');
  escaped = escaped.replace(/`([^`]+)`/g, '<code class="inline-code">$1</code>');
  escaped = escaped.replace(/\*\*([^\*]+)\*\*/g, '<strong>$1</strong>');
  escaped = escaped.replace(/\*([^\*]+)\*/g, '<em>$1</em>');
  escaped = escaped.replace(/\n/g, '<br/>');
  return escaped;
}

function copyCardText(btn) {
  const card = btn.closest('.copilot-card');
  if (!card) return;
  const text = card.innerText || card.textContent;
  navigator.clipboard.writeText(text).then(() => {
    const orig = btn.innerHTML;
    btn.innerHTML = '<i class="fa-solid fa-check" style="color: var(--neon-green);"></i>';
    setTimeout(() => { btn.innerHTML = orig; }, 1500);
  }).catch(() => {});
}

function openCardInModal(btn) {
  const card = btn.closest('.copilot-card');
  if (!card) return;
  const modal = document.getElementById('copilotBriefingModal');
  const body = document.getElementById('briefingModalContent') || document.getElementById('briefingModalBody');
  if (modal) {
    if (body) body.innerHTML = card.innerHTML;
    modal.classList.add('active');
  }
}

function appendCopilotMessage(role, text) {
  const feed = getCopilotFeed();
  if (!feed) return;

  const now = new Date();
  const timeStr = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

  const card = document.createElement('div');
  card.className = 'copilot-card';

  if (role === 'user') {
    card.style.borderColor = 'rgba(0, 229, 255, 0.4)';
    card.style.background = 'rgba(0, 229, 255, 0.05)';
    card.innerHTML = `
      <div class="copilot-card-header">
        <div style="color: var(--neon-cyan); font-weight: 700; display: flex; align-items: center; gap: 6px; font-size: 0.8rem;">
          <i class="fa-solid fa-user-shield"></i> Security Analyst
        </div>
        <span class="copilot-timestamp">${timeStr}</span>
      </div>
      <div style="font-size: 0.84rem; color: #ffffff; line-height: 1.5; font-weight: 600;">
        ${safeEscapeHtml(text)}
      </div>
    `;
  } else {
    card.innerHTML = `
      <div class="copilot-card-header">
        <div class="copilot-tag-ai"><i class="fa-solid fa-brain"></i> AI Agent Response</div>
        <div style="display: flex; align-items: center; gap: 4px;">
          <button class="card-action-icon-btn" onclick="copyCardText(this)" title="Copy text"><i class="fa-regular fa-copy"></i></button>
          <button class="card-action-icon-btn" onclick="openCardInModal(this)" title="Expand in modal reader"><i class="fa-solid fa-up-right-from-square"></i></button>
          <span class="copilot-timestamp">${timeStr}</span>
        </div>
      </div>
      <div class="copilot-markdown-body">
        ${formatCopilotMarkdown(text)}
      </div>
    `;
  }

  feed.appendChild(card);
  feed.scrollTop = feed.scrollHeight;
}

async function sendCopilot() {
  const input = document.getElementById('copilotInput');
  if (!input) return;
  const query = input.value.trim();
  if (!query) return;

  appendCopilotMessage('user', query);
  input.value = '';

  const feed = getCopilotFeed();
  if (!feed) return;

  const loadingDiv = document.createElement('div');
  loadingDiv.className = 'copilot-card';
  loadingDiv.id = 'copilotThinkingBubble';
  loadingDiv.style.borderColor = 'rgba(0, 229, 255, 0.3)';
  loadingDiv.innerHTML = `
    <div style="display: flex; align-items: center; gap: 10px; color: var(--neon-cyan); font-size: 0.82rem; font-family: var(--font-mono);">
      <i class="fa-solid fa-circle-notch fa-spin"></i>
      <span>Reasoning with LangGraph Multi-Agent Runtime...</span>
    </div>
  `;
  feed.appendChild(loadingDiv);
  feed.scrollTop = feed.scrollHeight;

  try {
    let resp = await fetch('/api/chat/message', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: query, session_id: 'default' })
    });

    if (resp.status === 404) {
      // Fallback to /api/chat
      resp = await fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: query, session_id: 'default' })
      });
    }

    const bubble = document.getElementById('copilotThinkingBubble');
    if (bubble) bubble.remove();

    if (resp.ok) {
      const data = await resp.json();
      appendCopilotMessage('assistant', data.response || data.message || 'Analysis complete.');
    } else {
      appendCopilotMessage('assistant', 'Security Guardrails intercepted this request or backend error occurred.');
    }
  } catch (err) {
    const bubble = document.getElementById('copilotThinkingBubble');
    if (bubble) bubble.remove();
    appendCopilotMessage('assistant', 'Connection error to AI Copilot API: ' + err.message);
  }
}

function quickCopilotQuery(promptText) {
  const input = document.getElementById('copilotInput');
  if (!input) return;

  let finalQuery = promptText;
  // If a node is currently selected on the canvas, contextualize the query!
  if (window.selectedGraphNode && window.selectedGraphNode.title) {
    const nodeLabel = window.selectedGraphNode.title;
    const lowerPrompt = promptText.toLowerCase();

    if (lowerPrompt.includes('summarize')) {
      finalQuery = `Summarize threat entity "${nodeLabel}" and its blast radius across the incident infrastructure`;
    } else if (lowerPrompt.includes('c2')) {
      finalQuery = `Explain C2 communication and beaconing patterns for entity "${nodeLabel}"`;
    } else if (lowerPrompt.includes('d3fend') || lowerPrompt.includes('mitigation')) {
      finalQuery = `Detail MITRE D3FEND defensive mitigations and counter-measures for "${nodeLabel}"`;
    } else if (lowerPrompt.includes('osint')) {
      finalQuery = `Analyze full OSINT attack surface and threat footprint for "${nodeLabel}"`;
    } else if (lowerPrompt.includes('firewall') || lowerPrompt.includes('rule')) {
      finalQuery = `Generate iptables and nftables perimeter containment firewall rules to block "${nodeLabel}"`;
    }
  }

  input.value = finalQuery;
  if (!copilotWidgetActive) toggleCopilotWidget();
  sendCopilot();
}

// Bind send button and Enter key listeners
function bindCopilotEventListeners() {
  const sendBtn = document.getElementById('copilotSendBtn');
  if (sendBtn) {
    sendBtn.onclick = (e) => {
      e.preventDefault();
      sendCopilot();
    };
  }
  const input = document.getElementById('copilotInput');
  if (input) {
    input.onkeydown = (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendCopilot();
      }
    };
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', bindCopilotEventListeners);
} else {
  bindCopilotEventListeners();
}

window.sendCopilot = sendCopilot;
window.quickCopilotQuery = quickCopilotQuery;
window.toggleCopilotWidget = toggleCopilotWidget;
window.adjustCopilotFontSize = adjustCopilotFontSize;
window.toggleWidgetWide = toggleWidgetWide;
window.toggleWidgetFullscreen = toggleWidgetFullscreen;
window.copyCardText = copyCardText;
window.openCardInModal = openCardInModal;
