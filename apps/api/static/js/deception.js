// =========================================================================
// CHAMELEON DECEPTION & HONEYTOKENS MODULE
// =========================================================================

async function deployChameleonTrap(trapType) {
  const ioc = (document.getElementById('searchInput') ? document.getElementById('searchInput').value.trim() : '') || 'update-microsoft-security.com';
  try {
    const resp = await fetch('/api/deception/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        trap_type: trapType || 'AWS_KEY',
        target_ioc: ioc,
        context: 'Active SOC Incident Decoy'
      })
    });
    if (!resp.ok) throw new Error('Failed to generate trap');
    const trap = await resp.json();

    renderSingleDeceptionTrap(trap, true);

    if (typeof copilotWidgetActive !== 'undefined' && !copilotWidgetActive) toggleCopilotWidget();
    if (typeof appendCopilotMessage === 'function') {
      appendCopilotMessage('assistant', `**Chameleon Honeytoken Armed**\n\nSuccessfully deployed deceptive decoy **${escapeHtml(trap.trap_name)}** (${trap.trap_type}). Monitoring for unauthorized reconnaissance probes.`);
    }

  } catch (err) {
    console.error('Deploy trap error:', err);
    alert('Deception trap error: ' + err.message);
  }
}

async function loadDeceptionTraps() {
  try {
    const resp = await fetch('/api/deception/traps');
    if (!resp.ok) return;
    const data = await resp.json();
    const container = document.getElementById('deceptionTrapsList');
    if (!container) return;
    container.innerHTML = '';
    (data.traps || []).forEach(t => renderSingleDeceptionTrap(t, false));
  } catch (err) {
    console.warn('Could not load deception traps:', err);
  }
}

function renderSingleDeceptionTrap(t, prepend) {
  const container = document.getElementById('deceptionTrapsList');
  if (!container) return;
  const row = document.createElement('div');
  row.className = 'deception-trap-card';
  row.id = `trap-row-${t.id}`;
  row.style.cssText = 'background: #081122; border: 1px solid rgba(0, 229, 255, 0.2); border-radius: 8px; padding: 10px; margin-bottom: 8px; display: flex; flex-direction: column; gap: 6px;';

  const isTripped = t.status === 'TRIPPED';
  const statusColor = isTripped ? '#ff3366' : '#00e676';

  row.innerHTML = `
    <div style="display: flex; align-items: center; justify-content: space-between;">
      <span style="font-size: 11px; font-weight: 800; color: #ffffff;"><i class="fa-solid fa-honey-pot" style="color: #f59e0b; margin-right: 5px;"></i> ${escapeHtml(t.trap_name)}</span>
      <span style="font-size: 9px; font-weight: 800; color: ${statusColor}; background: ${statusColor}18; border: 1px solid ${statusColor}40; padding: 2px 6px; border-radius: 4px;">${escapeHtml(t.status)}</span>
    </div>
    <div style="font-size: 9.5px; color: #94a3b8; font-family: monospace; word-break: break-all; background: #030712; padding: 4px 6px; border-radius: 4px;">${escapeHtml(t.trap_value)}</div>
    <div style="display: flex; align-items: center; justify-content: space-between; margin-top: 4px;">
      <span style="font-size: 8.5px; color: #64748b;">${escapeHtml(t.lure_context || 'Armed')}</span>
      <button onclick="simulateTrapTrip('${t.id}')" style="background: rgba(255, 51, 102, 0.15); color: #ff3366; border: 1px solid rgba(255, 51, 102, 0.35); border-radius: 4px; padding: 3px 7px; font-size: 8.5px; font-weight: 700; cursor: pointer;">
        <i class="fa-solid fa-crosshairs"></i> Simulate Trip
      </button>
    </div>
  `;

  if (prepend && container.firstChild) {
    container.insertBefore(row, container.firstChild);
  } else {
    container.appendChild(row);
  }
}

async function simulateTrapTrip(trapId) {
  try {
    const resp = await fetch('/api/deception/simulate-trip', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ trap_id: trapId, intruder_ip: '185.220.101.45' })
    });
    if (!resp.ok) throw new Error('Simulation failed');
    const data = await resp.json();

    const trapCard = document.getElementById(`trap-row-${trapId}`);
    if (trapCard) trapCard.style.borderColor = '#ff3366';

    alert(`🚨 ADVERSARY INTRUSION DETECTED!\n\nIP: ${data.alert.intruder_ip}\nTrap: ${data.trap.trap_name}\n\nPerimeter containment (Quarantine) has been automatically enforced.`);

    if (typeof checkContainmentStatus === 'function') checkContainmentStatus(data.alert.intruder_ip);
    loadDeceptionTraps();

  } catch (err) {
    console.error('Simulate trip error:', err);
  }
}

document.addEventListener('DOMContentLoaded', () => {
  loadDeceptionTraps();
});
