// =========================================================================
// ADVERSARIAL ARENA CLIENT MODULE (RED VS. BLUE SELF-PLAY)
// =========================================================================

if (typeof escapeHtml !== 'function') {
  window.escapeHtml = function(str) {
    if (!str) return '';
    return String(str).replace(/[&<>"']/g, function(m) {
      return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' })[m];
    });
  };
}

let lastSynthesizedSigmaRules = [];

function openArenaModal() {
  openModal('arenaModal');
}

async function runAdversarialDuel() {
  const personaSelect = document.getElementById('arenaPersonaSelect');
  const postureSelect = document.getElementById('arenaPostureSelect');
  const btn = document.getElementById('btnLaunchDuel');
  
  const adversary = personaSelect ? personaSelect.value : 'APT29';
  const defensePosture = postureSelect ? postureSelect.value : 'Balanced SOC';

  const origBtnHtml = btn ? btn.innerHTML : '';
  if (btn) {
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> <span>Emulating Duel...</span>';
    btn.disabled = true;
  }

  const redStream = document.getElementById('arenaRedStream');
  const blueStream = document.getElementById('arenaBlueStream');
  if (redStream) redStream.innerHTML = '<div style="color: #ff3366; font-size: 0.8rem;"><i class="fa-solid fa-circle-notch fa-spin"></i> Red Agent orchestrating attack kill-chain...</div>';
  if (blueStream) blueStream.innerHTML = '<div style="color: #00e5ff; font-size: 0.8rem;"><i class="fa-solid fa-circle-notch fa-spin"></i> Blue Agent correlating telemetry & calculating TTD...</div>';

  try {
    const resp = await fetch('/api/arena/simulate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        adversary: adversary,
        defense_posture: defensePosture
      })
    });

    if (!resp.ok) throw new Error('Simulation failed');
    const data = await resp.json();

    lastSynthesizedSigmaRules = data.sigma_rules || [];

    // Update Scoreboard
    const redScoreEl = document.getElementById('arenaRedScore');
    const blueScoreEl = document.getElementById('arenaBlueScore');
    const detRateEl = document.getElementById('arenaDetectionRate');
    const avgTtdEl = document.getElementById('arenaAvgTtd');
    const statusSummary = document.getElementById('arenaStatusSummary');

    if (redScoreEl) redScoreEl.textContent = `${data.red_score} PTS`;
    if (blueScoreEl) blueScoreEl.textContent = `${data.blue_score} PTS`;
    if (detRateEl) detRateEl.textContent = `${data.detection_rate}%`;
    if (avgTtdEl) avgTtdEl.textContent = `${data.avg_ttd_ms} ms`;
    if (statusSummary) statusSummary.textContent = data.summary;

    // Clear and animate round-by-round stream
    if (redStream) redStream.innerHTML = '';
    if (blueStream) blueStream.innerHTML = '';

    (data.rounds || []).forEach((r, idx) => {
      setTimeout(() => {
        // Render Red Card
        if (redStream) {
          const redCard = document.createElement('div');
          redCard.style.cssText = 'background: #08030a; border: 1px solid rgba(255, 51, 102, 0.4); border-radius: 8px; padding: 12px; display: flex; flex-direction: column; gap: 6px; box-shadow: 0 0 15px rgba(255, 51, 102, 0.1); animation: fadeIn 0.3s ease;';
          redCard.innerHTML = `
            <div style="display: flex; align-items: center; justify-content: space-between;">
              <span style="font-size: 10px; font-weight: 800; color: #ff3366; text-transform: uppercase;">ROUND ${r.round_number}: ${escapeHtml(r.stage_name)}</span>
              <span style="font-size: 9px; background: rgba(255, 51, 102, 0.15); color: #ff3366; border: 1px solid rgba(255, 51, 102, 0.4); padding: 1px 6px; border-radius: 4px; font-weight: 700;">${escapeHtml(r.mitre_id)}</span>
            </div>
            <div style="font-size: 11px; font-weight: 700; color: #ffffff;">${escapeHtml(r.technique)}</div>
            <div style="font-size: 9.5px; color: #cbd5e1;">${escapeHtml(r.red_agent.action)}</div>
            <div style="font-size: 8.8px; font-family: monospace; background: #030105; padding: 4px 8px; border-radius: 4px; color: #f43f5e; word-break: break-all;">
              <i class="fa-solid fa-terminal" style="margin-right: 4px;"></i> ${escapeHtml(r.red_agent.telemetry)}
            </div>
          `;
          redStream.appendChild(redCard);
        }

        // Render Blue Card
        if (blueStream) {
          const blueCard = document.createElement('div');
          const isDetected = r.blue_agent.status.includes('DETECTED');
          const borderColor = isDetected ? 'rgba(0, 230, 118, 0.4)' : 'rgba(245, 158, 11, 0.4)';
          const statusBg = isDetected ? 'rgba(0, 230, 118, 0.15)' : 'rgba(245, 158, 11, 0.15)';
          const statusColor = isDetected ? '#00e676' : '#f59e0b';

          blueCard.style.cssText = `background: #030b14; border: 1px solid ${borderColor}; border-radius: 8px; padding: 12px; display: flex; flex-direction: column; gap: 6px; box-shadow: 0 0 15px rgba(0, 229, 255, 0.1); animation: fadeIn 0.3s ease;`;
          blueCard.innerHTML = `
            <div style="display: flex; align-items: center; justify-content: space-between;">
              <span style="font-size: 10px; font-weight: 800; color: ${statusColor};">${escapeHtml(r.blue_agent.status)}</span>
              <span style="font-size: 9px; background: rgba(0, 229, 255, 0.15); color: #00e5ff; border: 1px solid rgba(0, 229, 255, 0.4); padding: 1px 6px; border-radius: 4px; font-weight: 700;">TTD: ${r.blue_agent.ttd_ms} ms</span>
            </div>
            <div style="font-size: 9.5px; color: #94a3b8;">${escapeHtml(r.blue_agent.containment)}</div>
            <div style="background: #020710; border: 1px solid rgba(0, 229, 255, 0.15); border-radius: 4px; padding: 6px 8px;">
              <div style="font-size: 8.5px; font-weight: 800; color: #38bdf8; margin-bottom: 3px; display: flex; align-items: center; justify-content: space-between;">
                <span><i class="fa-solid fa-code"></i> Synthesized Sigma Rule</span>
                <span style="font-size: 7.5px; color: #64748b;">Confidence: ${(r.blue_agent.confidence * 100).toFixed(0)}%</span>
              </div>
              <pre style="margin: 0; font-size: 8px; color: #a5f3fc; font-family: monospace; white-space: pre-wrap;">${escapeHtml(r.blue_agent.sigma_rule)}</pre>
            </div>
          `;
          blueStream.appendChild(blueCard);
        }
      }, idx * 300);
    });

  } catch (err) {
    console.error('Arena duel error:', err);
    alert('Adversarial Duel issue: ' + err.message);
  } finally {
    if (btn) {
      btn.innerHTML = origBtnHtml;
      btn.disabled = false;
    }
  }
}

function copyArenaSigmaRules() {
  if (!lastSynthesizedSigmaRules || lastSynthesizedSigmaRules.length === 0) {
    alert('No Sigma rules available. Run a duel first.');
    return;
  }
  const combined = lastSynthesizedSigmaRules.join('\n---\n');
  navigator.clipboard.writeText(combined).then(() => {
    alert(`Copied ${lastSynthesizedSigmaRules.length} synthesized Sigma rules to clipboard!`);
  }).catch(() => {
    alert('Unable to copy to clipboard.');
  });
}
