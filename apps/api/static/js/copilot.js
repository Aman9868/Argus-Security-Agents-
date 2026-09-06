// =========================================================================
// CYBER AI COPILOT INTERFACE MODULE
// =========================================================================

let copilotWidgetActive = false;
let copilotFontSize = 13;

function adjustCopilotFontSize(delta) {
  copilotFontSize = Math.min(18, Math.max(10, copilotFontSize + delta));
  const messagesBox = document.getElementById('copilotMessages');
  if (messagesBox) {
    messagesBox.style.fontSize = `${copilotFontSize}px`;
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
    if (input) input.focus();
  } else {
    widget.classList.remove('active');
    if (launcher) launcher.classList.remove('hidden');
  }
}

function toggleWidgetWide() {
  const widget = document.getElementById('copilotWidget');
  if (widget) widget.classList.toggle('wide-mode');
}

function toggleWidgetFullscreen() {
  const widget = document.getElementById('copilotWidget');
  if (widget) widget.classList.toggle('fullscreen-mode');
}

function formatCopilotMarkdown(text) {
  if (!text) return '';
  let escaped = escapeHtml(text);

  escaped = escaped.replace(/```([\s\S]*?)```/g, '<pre><code>$1</code></pre>');
  escaped = escaped.replace(/`([^`]+)`/g, '<code class="inline-code">$1</code>');
  escaped = escaped.replace(/\*\*([^\*]+)\*\*/g, '<strong>$1</strong>');
  escaped = escaped.replace(/\*([^\*]+)\*/g, '<em>$1</em>');
  escaped = escaped.replace(/\n/g, '<br/>');
  return escaped;
}

function appendCopilotMessage(role, text) {
  const messagesBox = document.getElementById('copilotMessages');
  if (!messagesBox) return;

  const msgDiv = document.createElement('div');
  msgDiv.className = `copilot-msg ${role === 'user' ? 'user-msg' : 'agent-msg'}`;

  const avatarDiv = document.createElement('div');
  avatarDiv.className = 'msg-avatar';
  avatarDiv.innerHTML = role === 'user'
    ? '<i class="fa-solid fa-user-shield"></i>'
    : '<i class="fa-solid fa-robot"></i>';

  const bodyDiv = document.createElement('div');
  bodyDiv.className = 'msg-body';
  bodyDiv.innerHTML = formatCopilotMarkdown(text);

  msgDiv.appendChild(avatarDiv);
  msgDiv.appendChild(bodyDiv);
  messagesBox.appendChild(msgDiv);
  messagesBox.scrollTop = messagesBox.scrollHeight;
}

async function sendCopilot() {
  const input = document.getElementById('copilotInput');
  if (!input) return;
  const query = input.value.trim();
  if (!query) return;

  appendCopilotMessage('user', query);
  input.value = '';

  const messagesBox = document.getElementById('copilotMessages');
  const loadingDiv = document.createElement('div');
  loadingDiv.className = 'copilot-msg agent-msg';
  loadingDiv.id = 'copilotThinkingBubble';
  loadingDiv.innerHTML = `
    <div class="msg-avatar"><i class="fa-solid fa-robot"></i></div>
    <div class="msg-body"><i class="fa-solid fa-spinner fa-spin"></i> Reasoning with LangGraph supervisor...</div>
  `;
  messagesBox.appendChild(loadingDiv);
  messagesBox.scrollTop = messagesBox.scrollHeight;

  try {
    const resp = await fetch('/api/chat/message', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: query, session_id: 'default' })
    });
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
    appendCopilotMessage('assistant', 'Connection error to AI Copilot API.');
  }
}

function quickCopilotQuery(promptText) {
  const input = document.getElementById('copilotInput');
  if (input) {
    input.value = promptText;
    if (!copilotWidgetActive) toggleCopilotWidget();
    sendCopilot();
  }
}
