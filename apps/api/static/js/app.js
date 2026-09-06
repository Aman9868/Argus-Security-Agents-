// =========================================================================
// CORE CYBER SENTINEL APPLICATION LOGIC & ORCHESTRATION
// =========================================================================

let currentIoc = '185.220.101.45';
let activeInvestigationId = null;

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function getSearchInputEl() {
  return document.getElementById('iocSearchInput') || document.getElementById('searchInput');
}

function openModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) modal.classList.add('active');
}

function closeModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) modal.classList.remove('active');
}

function closeModalOnBackdrop(event, modalId) {
  if (event.target && event.target.id === modalId) {
    closeModal(modalId);
  }
}

async function triggerRun(overrideIoc) {
  const searchEl = getSearchInputEl();
  const rawIoc = overrideIoc || (searchEl ? searchEl.value.trim() : '');
  const ioc = rawIoc || '185.220.101.45';

  if (searchEl) searchEl.value = ioc;
  currentIoc = ioc;

  // 1. UI Loading States
  const searchIcon = document.getElementById('topSearchIcon');
  const targetBadgeBtn = document.getElementById('targetBadgeBtn');
  const targetBadgeIoc = document.getElementById('targetBadgeIoc');
  const radarOverlay = document.getElementById('cyberRadarOverlay');
  const radarTargetName = document.getElementById('radarTargetName');
  const radarTelemetryFeed = document.getElementById('radarTelemetryFeed');
  const radarProgressBar = document.getElementById('radarProgressBar');

  if (searchIcon) searchIcon.className = 'fa-solid fa-circle-notch fa-spin search-icon';
  if (targetBadgeBtn) targetBadgeBtn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i>';
  if (targetBadgeIoc) targetBadgeIoc.textContent = `Target: ${ioc}`;

  if (radarOverlay) {
    radarOverlay.classList.add('active');
    if (radarTargetName) radarTargetName.textContent = `TARGET: ${ioc.toUpperCase()}`;
    if (radarTelemetryFeed) {
      radarTelemetryFeed.textContent = `> Dispatching autonomous multi-agent swarm for ${ioc}...\n> Querying Threat Hunt, OSINT, and Reputation Subgraphs...`;
    }
    if (radarProgressBar) radarProgressBar.style.width = '60%';
  }

  // Animate Stepper
  setStepperStage('analyzed');

  const startTime = performance.now();

  try {
    const resp = await fetch('/api/investigation/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ioc: ioc })
    });

    if (!resp.ok) throw new Error(`Investigation API returned HTTP ${resp.status}`);
    const data = await resp.json();

    const elapsed = ((performance.now() - startTime) / 1000).toFixed(1);
    const analysisTimeEl = document.getElementById('metricAnalysisTime');
    if (analysisTimeEl) analysisTimeEl.textContent = `${elapsed}s`;

    activeInvestigationId = data.investigation_id;
    const isBenign = (data.verdict || '').toUpperCase() === 'BENIGN';

    // 2. Update Header KPI Metrics
    const totalEntitiesEl = document.getElementById('metricTotalEntities');
    const threatsCountEl = document.getElementById('metricThreatsCount');
    const targetBadgeSeverity = document.getElementById('targetBadgeSeverity');

    if (isBenign) {
      if (totalEntitiesEl) totalEntitiesEl.textContent = '5';
      if (threatsCountEl) {
        threatsCountEl.textContent = '0';
        const sub = threatsCountEl.nextElementSibling;
        if (sub) {
          sub.textContent = 'clean score';
          sub.style.color = '#86efac';
        }
      }
      if (targetBadgeSeverity) {
        targetBadgeSeverity.textContent = 'BENIGN';
        targetBadgeSeverity.className = 'status-badge-approved';
        targetBadgeSeverity.style.cssText = 'font-size: 0.65rem; background: rgba(0, 230, 118, 0.15); color: #00e676; border: 1px solid rgba(0, 230, 118, 0.4); padding: 2px 8px; border-radius: 4px; font-weight: 800;';
      }
    } else {
      if (totalEntitiesEl) totalEntitiesEl.textContent = data.total_entities_discovered || '10';
      if (threatsCountEl) {
        threatsCountEl.textContent = '3';
        const sub = threatsCountEl.nextElementSibling;
        if (sub) {
          sub.textContent = 'high confidence';
          sub.style.color = '#fda4af';
        }
      }
      if (targetBadgeSeverity) {
        targetBadgeSeverity.textContent = 'HIGH';
        targetBadgeSeverity.className = 'badge-c2-high';
        targetBadgeSeverity.style.cssText = '';
      }
    }

    // 3. Update Containment Action Box
    updateContainmentAlertBox(ioc, isBenign, data);

    // 3b. Update MITRE ATT&CK and D3FEND Countermeasures dynamically
    updateMitreAndD3fend(data, isBenign);

    // 4. Update Knowledge Graph Topology
    if (isBenign) {
      renderBenignGraph(ioc, data);
    } else {
      if (data.knowledge_graph_elements && data.knowledge_graph_elements.length > 0) {
        renderCustomGraphElements(data.knowledge_graph_elements);
      } else {
        if (typeof initialElements !== 'undefined') {
          initMockupGraph(initialElements, 'preset');
        }
      }
    }

    // 5. Update Reports Panes if data available
    updateReportSnippets(data);

    // 6. Complete Stepper
    setStepperStage('completed');

    // 7. Push Briefing to Copilot
    if (typeof appendCopilotMessage === 'function') {
      const summaryText = data.analyst_summary || `Multi-Agent investigation concluded for ${ioc}.`;
      appendCopilotMessage(
        'assistant',
        `**Multi-Agent Investigation Complete: \`${escapeHtml(ioc)}\`**\n\n` +
        `• **Verdict:** \`${data.verdict}\`\n` +
        `• **Confidence:** ${(data.confidence_score * 100).toFixed(0)}%\n` +
        `• **Entities Mapped:** ${isBenign ? 5 : (data.total_entities_discovered || 8)}\n\n` +
        `*${escapeHtml(summaryText)}*`
      );
    }

  } catch (err) {
    console.error('Investigation error:', err);
    if (typeof appendCopilotMessage === 'function') {
      appendCopilotMessage('assistant', `⚠️ **Investigation Error:** ${escapeHtml(err.message)}`);
    }
  } finally {
    if (searchIcon) searchIcon.className = 'fa-solid fa-magnifying-glass search-icon';
    if (targetBadgeBtn) targetBadgeBtn.innerHTML = '<i class="fa-solid fa-play"></i>';
    if (radarOverlay) radarOverlay.classList.remove('active');
  }
}

function setStepperStage(stage) {
  const stepIngested = document.getElementById('stepItemIngested');
  const stepEnriched = document.getElementById('stepItemEnriched');
  const stepAnalyzed = document.getElementById('stepItemAnalyzed');
  const stepInvestigated = document.getElementById('stepItemInvestigated');
  const stepReport = document.getElementById('stepItemReport');
  const conn1 = document.getElementById('stepConn1');
  const conn2 = document.getElementById('stepConn2');
  const conn3 = document.getElementById('stepConn3');
  const conn4 = document.getElementById('stepConn4');

  const allSteps = [stepIngested, stepEnriched, stepAnalyzed, stepInvestigated, stepReport];
  const allConns = [conn1, conn2, conn3, conn4];

  allSteps.forEach(s => { if (s) s.className = 'step-item'; });
  allConns.forEach(c => { if (c) c.className = 'step-connector'; });

  if (stepIngested) stepIngested.classList.add('completed');
  if (conn1) conn1.classList.add('completed');

  if (stage === 'analyzed') {
    if (stepEnriched) stepEnriched.classList.add('completed');
    if (conn2) conn2.classList.add('completed');
    if (stepAnalyzed) stepAnalyzed.classList.add('active');
  } else if (stage === 'completed') {
    if (stepEnriched) stepEnriched.classList.add('completed');
    if (conn2) conn2.classList.add('completed');
    if (stepAnalyzed) stepAnalyzed.classList.add('completed');
    if (conn3) conn3.classList.add('completed');
    if (stepInvestigated) stepInvestigated.classList.add('completed');
    if (conn4) conn4.classList.add('completed');
    if (stepReport) stepReport.classList.add('completed');
  }
}

function updateContainmentAlertBox(ioc, isBenign, data) {
  const box = document.getElementById('hitlContainmentBox');
  if (!box) return;

  if (isBenign) {
    box.style.border = '1px solid rgba(0, 230, 118, 0.35)';
    box.style.background = 'rgba(0, 230, 118, 0.05)';
    box.innerHTML = `
      <div class="alert-headline-row" style="margin-bottom: 8px;">
        <div class="alert-title" style="color: #00e676; font-size: 0.8rem; font-weight: 800; display: flex; align-items: center; gap: 6px;">
          <i class="fa-solid fa-shield-check"></i> NO THREAT DETECTED — BENIGN ENTITY
        </div>
        <span style="font-size: 0.65rem; background: rgba(0, 230, 118, 0.15); color: #00e676; border: 1px solid rgba(0, 230, 118, 0.4); padding: 2px 6px; border-radius: 4px; font-weight: 800;">VERIFIED SAFE</span>
      </div>
      <div class="containment-meta-row" style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px;">
        <div class="target-badge-pill" style="color: #00e676;"><i class="fa-solid fa-check"></i> ${escapeHtml(ioc)}</div>
        <div class="action-badge-pill" style="color: #94a3b8; border-color: rgba(255, 255, 255, 0.2);">NO_ACTION</div>
        <div class="status-badge-approved" style="font-size: 0.65rem;"><i class="fa-solid fa-circle-check"></i> CLEAN TELEMETRY</div>
      </div>
      <div class="alert-body-text" style="font-size: 0.72rem; color: #94a3b8; line-height: 1.4;">
        Target entity evaluated with a confidence score of ${(data.confidence_score * 100).toFixed(0)}%. No active malicious beacons, phishing kits, or CVE exploits identified.
      </div>
    `;
  } else {
    box.style.border = '1px solid rgba(255, 51, 102, 0.4)';
    box.style.background = '';
    box.innerHTML = `
      <div class="alert-headline-row">
        <div class="alert-title">
          <i class="fa-solid fa-triangle-exclamation"></i> CONTAINMENT PENDING APPROVAL
        </div>
        <span class="badge-c2-high">HIGH RISK</span>
      </div>
      <div class="containment-meta-row">
        <div class="target-badge-pill"><i class="fa-solid fa-ban" style="color: #ff3366;"></i> ${escapeHtml(ioc)}</div>
        <div class="action-badge-pill">BLOCK_IP</div>
        <div class="status-badge-pending"><i class="fa-solid fa-clock"></i> AWAITING SOC</div>
      </div>
      <div class="alert-body-text" id="containmentBodyText" style="font-size: 0.72rem; color: #94a3b8; line-height: 1.4;">
        Target confidence (${data.confidence_score.toFixed(2)}) meets autonomous containment threshold. Awaiting analyst authorization to enforce perimeter firewall block.
      </div>
      <div class="alert-buttons-row">
        <button class="btn-quarantine" id="approveQuarantineBtn" onclick="approveQuarantine()"><i class="fa-solid fa-shield-virus"></i> APPROVE QUARANTINE</button>
        <button class="btn-dismiss-ghost" id="dismissQuarantineBtn" onclick="dismissQuarantine()">DISMISS</button>
      </div>
    `;
  }
}

function updateMitreAndD3fend(data, isBenign) {
  const mitreBadge = document.getElementById('mitreCountBadge');
  const mitreCloud = document.getElementById('mitreAttckCloud');
  const d3fendBadge = document.getElementById('d3fendCountBadge');
  const d3fendList = document.getElementById('d3fendList');

  if (isBenign) {
    if (mitreBadge) mitreBadge.textContent = '0 Mapped Techniques';
    if (mitreCloud) {
      mitreCloud.innerHTML = `
        <div style="color: #00e676; font-size: 0.74rem; padding: 10px 14px; background: rgba(0, 230, 118, 0.08); border: 1px solid rgba(0, 230, 118, 0.25); border-radius: 6px; display: flex; align-items: center; gap: 8px; width: 100%;">
          <i class="fa-solid fa-shield-check" style="font-size: 1rem;"></i>
          <span>No Malicious ATT&CK Tactics or Techniques Detected (Clean Baseline)</span>
        </div>
      `;
    }
    if (d3fendBadge) d3fendBadge.textContent = '0 Active Rules';
    if (d3fendList) {
      d3fendList.innerHTML = `
        <div style="color: #94a3b8; font-size: 0.74rem; padding: 10px 14px; background: #030814; border: 1px dashed rgba(255, 255, 255, 0.1); border-radius: 6px; display: flex; align-items: center; gap: 8px; width: 100%;">
          <i class="fa-solid fa-circle-check" style="color: #00e676; font-size: 1rem;"></i>
          <span>Standard enterprise traffic. No automated firewall drop rules required.</span>
        </div>
      `;
    }
  } else {
    const techniques = (data.mitre_attck_mappings && data.mitre_attck_mappings.length > 0)
      ? data.mitre_attck_mappings
      : ['T1071.001', 'T1583.001', 'T1566.002'];

    if (mitreBadge) mitreBadge.textContent = `${techniques.length} Mapped Techniques`;
    if (mitreCloud) {
      const techCards = [
        { code: 'T1071.001', title: 'Web Protocols', tactic: 'C2', color: 'red' },
        { code: 'T1583.001', title: 'Acquire Domains', tactic: 'Resource Dev', color: 'orange' },
        { code: 'T1566.002', title: 'Spearphish Link', tactic: 'Initial Access', color: 'yellow' }
      ];
      mitreCloud.innerHTML = techCards.map(tc => `
        <div class="technique-chip ${tc.color}">
          <span class="chip-code"><i class="fa-solid fa-triangle-exclamation"></i> ${tc.code}</span>
          <span class="chip-title">${tc.title}</span>
          <span class="chip-tactic">${tc.tactic}</span>
        </div>
      `).join('');
    }

    if (d3fendBadge) d3fendBadge.textContent = '4 Defensive Rules';
    if (d3fendList) {
      d3fendList.innerHTML = `
        <div class="d3fend-row">
          <span class="d3fend-id">D3-NPA</span>
          <div class="d3fend-content">
            <span class="d3fend-name">Network Traffic Analysis</span>
            <span class="d3fend-sub">Detect recurring C2 beaconing intervals</span>
          </div>
          <i class="fa-solid fa-circle-check d3fend-status-icon"></i>
        </div>
        <div class="d3fend-row">
          <span class="d3fend-id">D3-OTF</span>
          <div class="d3fend-content">
            <span class="d3fend-name">Outbound Traffic Filtering</span>
            <span class="d3fend-sub">Enforce perimeter egress drop rule</span>
          </div>
          <i class="fa-solid fa-circle-check d3fend-status-icon"></i>
        </div>
        <div class="d3fend-row">
          <span class="d3fend-id">D3-SINK</span>
          <div class="d3fend-content">
            <span class="d3fend-name">DNS Sinkholing</span>
            <span class="d3fend-sub">Redirect malicious domain to loopback sinkhole</span>
          </div>
          <i class="fa-solid fa-circle-check d3fend-status-icon"></i>
        </div>
        <div class="d3fend-row">
          <span class="d3fend-id">D3-DNSR</span>
          <div class="d3fend-content">
            <span class="d3fend-name">Domain Name Reputation</span>
            <span class="d3fend-sub">Block lookalike & newly registered domains</span>
          </div>
          <i class="fa-solid fa-circle-check d3fend-status-icon"></i>
        </div>
      `;
    }
  }
}

function renderBenignGraph(ioc, data) {
  if (typeof makeNodeCardSvg !== 'function' || typeof initMockupGraph !== 'function') return;

  const scoreText = `Score: ${(data.confidence_score || 0.98).toFixed(2)}`;
  const benignNodes = [
    {
      data: {
        id: 'node_center',
        title: ioc,
        cardSvg: makeNodeCardSvg(ioc, [{ text: 'Verified Safe', color: '#00e676' }], 'globe', '#00e676')
      },
      position: { x: 480, y: 270 }
    },
    {
      data: {
        id: 'node_asn',
        title: 'AS10310 Enterprise BGP',
        cardSvg: makeNodeCardSvg('AS10310 Enterprise BGP', [{ text: 'Infrastructure', color: '#38bdf8' }], 'server', '#00e5ff')
      },
      position: { x: 230, y: 150 }
    },
    {
      data: {
        id: 'node_ip',
        title: '98.137.11.163',
        cardSvg: makeNodeCardSvg('98.137.11.163', [{ text: 'Hosting IP (US)', color: '#a855f7' }], 'server', '#a855f7')
      },
      position: { x: 730, y: 150 }
    },
    {
      data: {
        id: 'node_reg',
        title: 'MarkMonitor Inc.',
        cardSvg: makeNodeCardSvg('MarkMonitor Inc.', [{ text: 'Verified Registrar', color: '#38bdf8' }], 'globe', '#00e5ff')
      },
      position: { x: 280, y: 440 }
    },
    {
      data: {
        id: 'node_sec',
        title: 'Verdict: BENIGN',
        cardSvg: makeNodeCardSvg('Verdict: BENIGN', [{ text: scoreText, color: '#00e676' }], 'globe', '#00e676')
      },
      position: { x: 680, y: 440 }
    },
    // Edges
    { data: { source: 'node_center', target: 'node_asn', label: 'announced by' } },
    { data: { source: 'node_center', target: 'node_ip', label: 'resolves to' } },
    { data: { source: 'node_center', target: 'node_reg', label: 'registered with' } },
    { data: { source: 'node_center', target: 'node_sec', label: 'evaluated as' } }
  ];

  initMockupGraph(benignNodes, 'preset');

  const statNodes = document.getElementById('canvasStatNodes');
  const statRels = document.getElementById('canvasStatRels');
  const statPivots = document.getElementById('canvasStatPivots');
  if (statNodes) statNodes.textContent = '5';
  if (statRels) statRels.textContent = '4';
  if (statPivots) statPivots.textContent = '0';
}

function renderCustomGraphElements(elements) {
  if (typeof initMockupGraph !== 'function') return;
  initMockupGraph(elements, 'cose');
}

function updateReportSnippets(data) {
  const sigmaEl = document.getElementById('repSigmaCode');
  const yaraEl = document.getElementById('repYaraCode');
  const stixEl = document.getElementById('repStixCode');

  if (sigmaEl && data.sigma_rule) sigmaEl.textContent = data.sigma_rule;
  if (yaraEl && data.yara_rule) yaraEl.textContent = data.yara_rule;
  if (stixEl && data.stix_bundle) stixEl.textContent = JSON.stringify(data.stix_bundle, null, 2);
}

async function approveQuarantine() {
  try {
    const resp = await fetch('/api/hitl/approve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: currentIoc, action: 'APPROVE' })
    });
    if (resp.ok) {
      alert(`Perimeter firewall containment rule enforced for ${currentIoc}.`);
      const box = document.getElementById('hitlContainmentBox');
      if (box) box.style.display = 'none';
    }
  } catch (err) {
    console.error('Quarantine approval error:', err);
  }
}

function dismissQuarantine() {
  const box = document.getElementById('hitlContainmentBox');
  if (box) box.style.display = 'none';
}

function triggerSearchWithIoc(ioc) {
  const input = getSearchInputEl();
  if (input) {
    input.value = ioc;
    triggerRun(ioc);
  }
}

// Initialize Interactive Bindings on DOM Load
document.addEventListener('DOMContentLoaded', () => {
  // 1. Initial Graph Rendering
  if (typeof initMockupGraph === 'function' && typeof initialElements !== 'undefined') {
    initMockupGraph(initialElements, 'preset');
  }

  // 2. Search Input Enter Key Listener
  const searchInput = getSearchInputEl();
  if (searchInput) {
    searchInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        triggerRun();
      }
    });
  }

  // 3. Search Icon Click Listener
  const searchIcon = document.getElementById('topSearchIcon');
  if (searchIcon) {
    searchIcon.style.cursor = 'pointer';
    searchIcon.title = 'Click to search indicator';
    searchIcon.addEventListener('click', () => {
      triggerRun();
    });
  }

  // 4. Global Keyboard Shortcut ⌘ K / Ctrl+K
  window.addEventListener('keydown', (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
      e.preventDefault();
      const input = getSearchInputEl();
      if (input) {
        input.focus();
        input.select();
      }
    }
  });

  // 5. Containment Action Buttons
  const approveBtn = document.getElementById('approveQuarantineBtn');
  if (approveBtn) approveBtn.addEventListener('click', approveQuarantine);

  const dismissBtn = document.getElementById('dismissQuarantineBtn');
  if (dismissBtn) dismissBtn.addEventListener('click', dismissQuarantine);
});

// =========================================================================
// SIDEBAR NAVIGATION & MODAL CONTROLLERS
// =========================================================================

function toggleThreatAnalysisDropdown(e) {
  if (e) e.stopPropagation();
  const submenu = document.getElementById('threatAnalysisSubmenu');
  const chevron = document.getElementById('threatDropdownChevron');
  if (!submenu) return;
  const isCurrentlyHidden = submenu.style.display === 'none';
  submenu.style.display = isCurrentlyHidden ? 'flex' : 'none';
  if (chevron) {
    if (isCurrentlyHidden) {
      chevron.classList.remove('rotated');
    } else {
      chevron.classList.add('rotated');
    }
  }
}

function navigateToThreatGraph() {
  navigateTo('threat-analysis');
  document.querySelectorAll('.nav-submenu .nav-sub-item').forEach(el => el.classList.remove('active'));
  const el = document.getElementById('subNavItemGraph');
  if (el) el.classList.add('active');
}

function navigateTo(viewName) {
  document.querySelectorAll('.nav-links .nav-item').forEach(el => el.classList.remove('active'));
  
  // Close any open modals
  document.querySelectorAll('.modal-overlay.active').forEach(m => m.classList.remove('active'));

  if (viewName === 'home' || viewName === 'threat-analysis') {
    const navEl = document.getElementById('navThreatAnalysis') || document.querySelector('.nav-links .nav-item:nth-child(2)');
    if (navEl) navEl.classList.add('active');
    const submenu = document.getElementById('threatAnalysisSubmenu');
    if (submenu) submenu.style.display = 'flex';
    const chevron = document.getElementById('threatDropdownChevron');
    if (chevron) chevron.classList.remove('rotated');
    if (typeof setGraphView === 'function') setGraphView('graph');
    if (typeof cy !== 'undefined' && cy) cy.fit(null, 45);
  }
}

function focusIocSearch() {
  const searchInput = getSearchInputEl();
  if (searchInput) {
    searchInput.focus();
    searchInput.select();
    const wrapper = document.getElementById('topSearchWrapper');
    if (wrapper) {
      wrapper.style.boxShadow = '0 0 20px rgba(0, 229, 255, 0.6)';
      setTimeout(() => { wrapper.style.boxShadow = ''; }, 1200);
    }
  }
}

function openInvestigations() {
  openModal('investigationsModal');
  loadInvestigationsModal();
}

async function loadInvestigationsModal() {
  const tbody = document.getElementById('investigationsTableBody');
  if (!tbody) return;
  tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color: #94a3b8; padding: 16px;"><i class="fa-solid fa-spinner fa-spin"></i> Loading investigations from SQLite...</td></tr>';

  try {
    const resp = await fetch('/api/investigation/list');
    if (!resp.ok) throw new Error('Failed to load investigations');
    const data = await resp.json();
    const list = data.investigations || [];

    if (list.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color: #64748b; padding: 16px;">No saved investigations found in database.</td></tr>';
      return;
    }

    tbody.innerHTML = list.map(inv => {
      const isMalicious = (inv.verdict || '').toUpperCase().includes('MALICIOUS');
      const badgeColor = isMalicious ? '#ff3366' : '#00e676';
      const badgeBg = isMalicious ? 'rgba(255, 51, 102, 0.15)' : 'rgba(0, 230, 118, 0.15)';
      const cleanIoc = escapeHtml(inv.seed_ioc || 'N/A');

      return `
        <tr>
          <td style="font-family: monospace; font-size: 11px; color: #94a3b8;">${escapeHtml(inv.investigation_id || inv.id)}</td>
          <td style="font-weight: 700; color: #ffffff;">${cleanIoc}</td>
          <td><span style="font-size: 10px; font-weight: 800; color: ${badgeColor}; background: ${badgeBg}; border: 1px solid ${badgeColor}40; padding: 2px 6px; border-radius: 4px;">${escapeHtml(inv.verdict)}</span></td>
          <td style="color: #38bdf8;">${((inv.confidence_score || 0.85) * 100).toFixed(0)}%</td>
          <td style="font-size: 11px; color: #64748b;">${escapeHtml(inv.created_at || 'Just now')}</td>
          <td>
            <button onclick="triggerSearchWithIoc('${cleanIoc}'); closeModal('investigationsModal');" style="background: rgba(0, 229, 255, 0.15); color: #00e5ff; border: 1px solid rgba(0, 229, 255, 0.35); border-radius: 4px; padding: 2px 8px; font-size: 10px; font-weight: 700; cursor: pointer;">
              <i class="fa-solid fa-play"></i> Open
            </button>
          </td>
        </tr>
      `;
    }).join('');

  } catch (err) {
    console.error('Investigations load error:', err);
    tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; color: #ff3366; padding: 16px;">Failed to load cases: ${escapeHtml(err.message)}</td></tr>`;
  }
}

function openIncidents() {
  openModal('incidentsModal');
  loadIncidentsModal();
}

async function loadIncidentsModal() {
  const tbody = document.getElementById('containmentTableBody');
  if (!tbody) return;
  tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color: #94a3b8; padding: 16px;"><i class="fa-solid fa-spinner fa-spin"></i> Loading containment registry from SQLite...</td></tr>';

  try {
    const resp = await fetch('/api/hitl/containments');
    if (!resp.ok) throw new Error('Failed to load containments');
    const data = await resp.json();
    const list = data.containments || [];

    if (list.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color: #64748b; padding: 16px;">No containment records currently registered.</td></tr>';
      return;
    }

    tbody.innerHTML = list.map(rec => {
      const isActive = rec.status === 'ACTIVE' || rec.status === 'APPROVED_AND_EXECUTED';
      const statusColor = isActive ? '#00e676' : '#ff9100';
      const statusBg = isActive ? 'rgba(0, 230, 118, 0.15)' : 'rgba(255, 145, 0, 0.15)';

      return `
        <tr>
          <td style="font-family: monospace; font-size: 11px; color: #94a3b8;">${escapeHtml(rec.task_id || rec.id || 'TASK-REC')}</td>
          <td style="font-weight: 700; color: #ffffff;">${escapeHtml(rec.target)}</td>
          <td><span style="font-size: 10px; font-weight: 700; color: #ff3366; background: rgba(255, 51, 102, 0.15); border: 1px solid rgba(255, 51, 102, 0.35); padding: 2px 6px; border-radius: 4px;">${escapeHtml(rec.action_type || 'BLOCK_IP')}</span></td>
          <td><span style="font-size: 10px; font-weight: 800; color: ${statusColor}; background: ${statusBg}; border: 1px solid ${statusColor}40; padding: 2px 6px; border-radius: 4px;">${escapeHtml(rec.status)}</span></td>
          <td style="font-family: monospace; font-size: 9.5px; color: #38bdf8; word-break: break-all;">${escapeHtml(rec.firewall_rule || 'iptables -A INPUT -s ... -j DROP')}</td>
          <td>
            <span style="font-size: 10px; color: #00e676;"><i class="fa-solid fa-circle-check"></i> Enforced</span>
          </td>
        </tr>
      `;
    }).join('');

  } catch (err) {
    console.error('Incidents load error:', err);
    tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; color: #ff3366; padding: 16px;">Failed to load incidents: ${escapeHtml(err.message)}</td></tr>`;
  }
}

function openReportsModal() {
  openModal('reportsModal');
  loadIocReportModal(currentIoc);
}

async function loadIocReportModal(targetIoc) {
  const ioc = targetIoc || currentIoc || '185.220.101.45';
  const badge = document.getElementById('repIocBadge');
  if (badge) badge.textContent = ioc;

  try {
    const resp = await fetch(`/api/investigation/ioc/report?ioc=${encodeURIComponent(ioc)}`);
    if (!resp.ok) return;
    const data = await resp.json();

    const dossier = data.dossier || {};
    const scoreEl = document.getElementById('repThreatScore');
    const levelEl = document.getElementById('repThreatLevel');
    const attrEl = document.getElementById('repAttribution');
    const countryEl = document.getElementById('repCountry');
    const asnEl = document.getElementById('repAsn');
    const regEl = document.getElementById('repRegistrar');
    const regDateEl = document.getElementById('repRegDate');
    const malwareEl = document.getElementById('repMalwareFamilies');

    if (scoreEl) scoreEl.textContent = dossier.threat_score || (ioc.includes('yahoo') ? '5' : '92');
    if (levelEl) levelEl.textContent = dossier.threat_level || (ioc.includes('yahoo') ? 'BENIGN' : 'CRITICAL');
    if (attrEl) attrEl.textContent = dossier.attribution || 'Enterprise Verified Asset';
    if (countryEl) countryEl.textContent = dossier.country || 'United States';
    if (asnEl) asnEl.textContent = dossier.open_ports ? `ASN: ${ioc}` : 'AS10310 Yahoo Inc.';
    if (regEl) regEl.textContent = dossier.registration_date ? 'NameCheap, Inc.' : 'MarkMonitor Inc.';
    if (regDateEl) regDateEl.textContent = dossier.registration_date || '1995-01-18';
    if (malwareEl) malwareEl.textContent = dossier.malware_families || 'None (Clean)';

    // Update rules tab
    const sigmaCode = document.getElementById('repSigmaCode');
    const yaraCode = document.getElementById('repYaraCode');
    const stixCode = document.getElementById('repStixCode');

    if (sigmaCode && !sigmaCode.textContent.trim()) {
      sigmaCode.textContent = `title: Detect Outbound Connection to ${ioc}\nstatus: production\nlogsource:\n  category: network_traffic\ndetection:\n  selection:\n    DestinationIp: '${ioc}'\n  condition: selection\nlevel: high`;
    }
    if (yaraCode && !yaraCode.textContent.trim()) {
      yaraCode.textContent = `rule IOC_${ioc.replace(/[^a-zA-Z0-9]/g, '_')} {\n  strings:\n    $ioc = "${ioc}"\n  condition:\n    any of them\n}`;
    }
    if (stixCode && !stixCode.textContent.trim()) {
      stixCode.textContent = JSON.stringify({ type: "bundle", id: `bundle--${Date.now()}`, spec_version: "2.1", objects: [{ type: "indicator", indicator: ioc }] }, null, 2);
    }

  } catch (err) {
    console.warn('Report fetch notice:', err);
  }
}

function switchReportTab(tabKey, btn) {
  document.querySelectorAll('.rep-tab-btn').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');

  const paneMap = {
    'telemetry': document.getElementById('repPaneTelemetry'),
    'mitre': document.getElementById('repPaneMitre'),
    'detection_rules': document.getElementById('repPaneDetectionRules'),
    'stix': document.getElementById('repPaneStix')
  };

  Object.values(paneMap).forEach(pane => {
    if (pane) pane.style.display = 'none';
  });

  if (paneMap[tabKey]) {
    paneMap[tabKey].style.display = 'block';
  }
}

function copyCodeContent(elId) {
  const el = document.getElementById(elId);
  if (!el) return;
  const text = el.textContent;
  navigator.clipboard.writeText(text).then(() => {
    alert('Code copied to clipboard!');
  }).catch(() => {
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    alert('Code copied to clipboard!');
  });
}

function downloadStixBundle() {
  const el = document.getElementById('repStixCode');
  const content = el ? el.textContent : '{"type": "bundle"}';
  const blob = new Blob([content], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `stix-bundle-${currentIoc}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

function copyReportMarkdown() {
  const summary = `Cyber Sentinel Threat Dossier: ${currentIoc}\nStatus: Evidence Verified\nGenerated: ${new Date().toISOString()}`;
  navigator.clipboard.writeText(summary).then(() => {
    alert('Threat dossier summary copied to clipboard!');
  });
}

