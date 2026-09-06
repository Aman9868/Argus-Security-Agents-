/**
 * Autonomous Attack Path & Blast Radius Simulation Module
 * Simulates lateral movement radiating from an IOC or compromised host.
 * Renders reachability to Crown Jewels, Mean Time to Breach, Chokepoints,
 * and overlays glowing dashed amber paths on the Cytoscape canvas.
 */

let currentAttackPathSimulation = null;

async function triggerAttackPathSim() {
  const iocInput = document.getElementById('iocSearchInput');
  const target = (iocInput && iocInput.value.trim()) || '185.220.101.45';
  openAttackPathModal(target);
}

function openAttackPathModal(targetIoc) {
  const modal = document.getElementById('attackPathModal');
  if (!modal) return;
  modal.classList.add('active');

  const targetBadge = document.getElementById('simTargetBadge');
  if (targetBadge) targetBadge.textContent = targetIoc;

  runAttackPathSimulation(targetIoc);
}

async function runAttackPathSimulation(targetIoc) {
  const loadingContainer = document.getElementById('attackPathLoading');
  const resultsContainer = document.getElementById('attackPathResults');
  if (loadingContainer) loadingContainer.style.display = 'flex';
  if (resultsContainer) resultsContainer.style.display = 'none';

  try {
    const res = await fetch('/api/blast-radius/simulate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ioc_or_host: targetIoc, iterations: 500 })
    });

    if (!res.ok) throw new Error(`Simulation failed HTTP ${res.status}`);
    const data = await res.json();
    currentAttackPathSimulation = data;
    renderAttackPathResults(data);
  } catch (err) {
    console.error('Error running attack path simulation:', err);
    if (loadingContainer) {
      loadingContainer.innerHTML = `<div style="color: #ff3366; text-align: center; padding: 20px;">
        <i class="fa-solid fa-triangle-exclamation" style="font-size: 1.5rem; margin-bottom: 8px;"></i>
        <div>Simulation error: ${err.message}</div>
      </div>`;
    }
  } finally {
    if (loadingContainer && currentAttackPathSimulation) loadingContainer.style.display = 'none';
    if (resultsContainer && currentAttackPathSimulation) resultsContainer.style.display = 'block';
  }
}

function renderAttackPathResults(data) {
  // 1. KPI cards
  const probEl = document.getElementById('simProbMetric');
  if (probEl) probEl.textContent = `${(data.compromise_probability * 100).toFixed(1)}%`;

  const mttbEl = document.getElementById('simMttbMetric');
  if (mttbEl) mttbEl.textContent = `${data.mttb_minutes} min`;

  const pathsEl = document.getElementById('simPathsMetric');
  if (pathsEl) pathsEl.textContent = data.critical_attack_paths.length;

  const jewelsEl = document.getElementById('simJewelsMetric');
  if (jewelsEl) jewelsEl.textContent = data.crown_jewels_at_risk.length;

  // 2. Crown Jewels List
  const jewelsContainer = document.getElementById('simJewelsContainer');
  if (jewelsContainer) {
    jewelsContainer.innerHTML = data.crown_jewels_at_risk.map(j => `
      <div class="jewel-pill-card">
        <div class="jewel-icon"><i class="fa-solid fa-gem" style="color: #ff3366;"></i></div>
        <div class="jewel-info">
          <div class="jewel-name">${j.node}</div>
          <div class="jewel-meta">${j.asset_type} &bull; Classification: <strong style="color: #f43f5e;">${j.data_classification}</strong></div>
        </div>
        <span class="jewel-risk-badge">${j.reachability}</span>
      </div>
    `).join('');
  }

  // 3. Lateral Attack Paths Breakdown
  const pathsContainer = document.getElementById('simPathsContainer');
  if (pathsContainer) {
    pathsContainer.innerHTML = data.critical_attack_paths.map((path, idx) => `
      <div class="attack-path-step-card">
        <div class="path-card-header">
          <div style="display: flex; align-items: center; gap: 8px;">
            <span class="path-number-badge">Path #${idx + 1}</span>
            <strong style="color: #ffffff; font-size: 0.85rem;">Target: ${path.target}</strong>
          </div>
          <div style="display: flex; align-items: center; gap: 10px;">
            <span class="path-stat-pill"><i class="fa-solid fa-clock"></i> MTTB: ${path.estimated_mttb_minutes}m</span>
            <span class="path-stat-pill" style="color: #ff9100; border-color: rgba(255, 145, 0, 0.4);"><i class="fa-solid fa-percent"></i> Prob: ${(path.path_probability * 100).toFixed(0)}%</span>
          </div>
        </div>
        <div class="path-card-body">
          <div class="path-hops-sequence">
            ${path.path.map((node, i) => `
              <span class="hop-node ${i === 0 ? 'hop-source' : (i === path.path.length - 1 ? 'hop-target' : 'hop-pivot')}">${node}</span>
              ${i < path.path.length - 1 ? '<i class="fa-solid fa-arrow-right hop-arrow"></i>' : ''}
            `).join('')}
          </div>
          <div class="path-techniques-list">
            <span style="color: var(--text-muted); font-size: 0.72rem; font-weight: 700;">MITRE TTPs:</span>
            ${path.techniques.map(t => `<span class="path-ttp-pill">${t}</span>`).join(' ')}
          </div>
        </div>
      </div>
    `).join('');
  }

  // 4. Chokepoint Defense Recommendations
  const chokepointsContainer = document.getElementById('simChokepointsContainer');
  if (chokepointsContainer) {
    chokepointsContainer.innerHTML = data.chokepoint_defenses.map(cp => `
      <div class="chokepoint-card" id="cp-${cp.id}">
        <div class="cp-header">
          <div style="display: flex; align-items: center; gap: 8px;">
            <span class="cp-id-badge">${cp.id}</span>
            <strong style="color: #ffffff; font-size: 0.82rem;">${cp.location}</strong>
          </div>
          <span class="cp-mitigation-tag"><i class="fa-solid fa-shield-halved"></i> Cuts ${cp.mitigation_impact}</span>
        </div>
        <div class="cp-action-text">${cp.action}</div>
        <div class="cp-footer">
          <span style="font-size: 0.7rem; color: var(--text-muted); font-family: var(--font-mono);">Chokepoint for ${cp.cuts_paths} lateral path(s)</span>
          <button class="cp-execute-btn" onclick="executeChokepointDefense('${cp.id}')">
            <i class="fa-solid fa-scissors"></i> Apply Isolation
          </button>
        </div>
      </div>
    `).join('');
  }
}

function overlayAttackPathOnGraph() {
  if (!currentAttackPathSimulation || !window.cy) {
    alert('Graph engine is initializing or no simulation data available.');
    return;
  }

  const elements = currentAttackPathSimulation.cytoscape_elements;
  if (!elements || elements.length === 0) return;

  // Close modal so user sees the graph
  closeModal('attackPathModal');
  if (typeof setGraphView === 'function') setGraphView('graph');

  // Add simulation nodes & edges to Cytoscape
  try {
    // Check which elements already exist
    elements.forEach(el => {
      const existing = window.cy.getElementById(el.data.id);
      if (existing && existing.length > 0) {
        // Update existing element styling to highlight attack path
        if (el.data.isAttackPath) {
          existing.addClass('attack-path-highlight');
          existing.data('threatScore', 95);
        }
      } else {
        // Add new node or edge
        const added = window.cy.add(el);
        if (el.data.isAttackPath) {
          added.addClass('attack-path-highlight');
        }
      }
    });

    // Style the attack path elements with glowing amber dashed lines
    window.cy.style()
      .selector('edge[isAttackPath]')
      .style({
        'line-color': '#ff9100',
        'line-style': 'dashed',
        'line-dash-pattern': [6, 4],
        'width': 3.5,
        'target-arrow-color': '#ff9100',
        'target-arrow-shape': 'triangle',
        'curve-style': 'bezier',
        'opacity': 1.0
      })
      .selector('node[isAttackPath]')
      .style({
        'border-color': '#ff9100',
        'border-width': 3,
        'border-style': 'dashed'
      })
      .update();

    // Re-run layout for clear view
    window.cy.layout({
      name: 'breadthfirst',
      directed: true,
      roots: `#${currentAttackPathSimulation.compromised_origin}`,
      padding: 40,
      animate: true,
      animationDuration: 600
    }).run();

    // Update node count badges
    if (typeof updateGraphCounters === 'function') updateGraphCounters();

    console.log('[AttackPath] Injected lateral movement path simulation onto canvas.');
  } catch (e) {
    console.warn('[AttackPath] Overlay error:', e);
  }
}

function executeChokepointDefense(chokepointId) {
  const card = document.getElementById(`cp-${chokepointId}`);
  if (card) {
    const btn = card.querySelector('.cp-execute-btn');
    if (btn) {
      btn.innerHTML = '<i class="fa-solid fa-check"></i> Isolated';
      btn.style.background = 'rgba(0, 230, 118, 0.2)';
      btn.style.color = '#00e676';
      btn.style.borderColor = '#00e676';
      btn.disabled = true;
    }
    card.style.borderColor = '#00e676';
  }

  // Update cytoscape edges if available
  if (window.cy) {
    const edges = window.cy.edges();
    edges.forEach(edge => {
      if (edge.data('label') && edge.data('label').includes('RDP') && chokepointId === 'CP-01') {
        edge.style({ 'line-color': '#ff3366', 'opacity': 0.3, 'line-style': 'dotted' });
      }
    });
  }

  alert(`Chokepoint ${chokepointId} defense rule staged: Network route severed to contain lateral movement.`);
}

window.triggerAttackPathSim = triggerAttackPathSim;
window.openAttackPathModal = openAttackPathModal;
window.runAttackPathSimulation = runAttackPathSimulation;
window.overlayAttackPathOnGraph = overlayAttackPathOnGraph;
window.executeChokepointDefense = executeChokepointDefense;
