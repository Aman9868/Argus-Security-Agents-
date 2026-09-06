// =========================================================================
// THREAT INFRASTRUCTURE GRAPH & GRAPHRAG MODULE
// =========================================================================

let cy = null;
let currentLayout = 'preset';
let threatLeafletMap = null;
let threatMapMarkers = [];
let threatMapLines = [];

function makeNodeCardSvg(title, badges, iconType, glowColor) {
  const icons = {
    'globe': '<path d="M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zm6.93 6h-2.95a15.65 15.65 0 0 0-1.38-3.56A8.03 8.03 0 0 1 18.93 8zM12 4.07c.83 1.2 1.48 2.53 1.91 3.93h-3.82c.43-1.4 1.08-2.73 1.91-3.93zM4.26 14A7.95 7.95 0 0 1 4 12c0-.7.1-1.38.26-2h3.38c-.08.66-.14 1.32-.14 2 0 .68.06 1.34.14 2H4.26zm1.81 2h2.95c.36 1.28.84 2.48 1.38 3.56A8.03 8.03 0 0 1 6.07 16zm2.95-8H6.07a8.03 8.03 0 0 1 4.33-3.56A15.65 15.65 0 0 0 9.02 8zm2.98 11.93c-.83-1.2-1.48-2.53-1.91-3.93h3.82c-.43 1.4-1.08 2.73-1.91 3.93zM13.91 14h-3.82c-.08-.66-.14-1.32-.14-2 0-.68.06-1.34.14-2h3.82c.08.66.14 1.32.14 2 0 .68-.06 1.34-.14 2zm.71 5.56c.54-1.08 1.02-2.28 1.38-3.56h2.95a8.03 8.03 0 0 1-4.33 3.56zM16.36 14c.08-.66.14-1.32.14-2 0-.68-.06-1.34-.14-2h3.38c.16.62.26 1.3.26 2 0 .7-.1 1.38-.26 2h-3.38z" fill="#ffffff"/>',
    'server': '<path d="M4 4h16a2 2 0 0 1 2 2v3a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2zm0 9h16a2 2 0 0 1 2 2v3a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2v-3a2 2 0 0 1 2-2zm14-6a1 1 0 1 0 0-2 1 1 0 0 0 0 2zm-3 0a1 1 0 1 0 0-2 1 1 0 0 0 0 2zm3 9a1 1 0 1 0 0-2 1 1 0 0 0 0 2zm-3 0a1 1 0 1 0 0-2 1 1 0 0 0 0 2z" fill="#ffffff"/>',
    'user': '<path d="M12 12c2.7 0 4.8-2.1 4.8-4.8S14.7 2.4 12 2.4 7.2 4.5 7.2 7.2 9.3 12 12 12zm0 2.4c-3.2 0-9.6 1.6-9.6 4.8V21h19.2v-1.8c0-3.2-6.4-4.8-9.6-4.8z" fill="#ffffff"/>',
    'file': '<path d="M14 2H6c-1.1 0-2 .9-2 2v16c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z" fill="#ffffff"/>',
    'link': '<path d="M3.9 12c0-1.7 1.4-3.1 3.1-3.1h4V7H7c-2.8 0-5 2.2-5 5s2.2 5 5 5h4v-1.9H7c-1.7 0-3.1-1.4-3.1-3.1zM8 13h8v-2H8v2zm9-6h-4v1.9h4c1.7 0 3.1 1.4 3.1 3.1s-1.4 3.1-3.1 3.1h-4V17h4c2.8 0 5-2.2 5-5s-2.2-5-5-5z" fill="#ffffff"/>'
  };

  const path = icons[iconType] || icons['globe'];
  const glow = glowColor || '#00e5ff';
  const cleanGlow = glow.replace('#', '');
  const displayTitle = title.length > 25 ? title.substring(0, 23) + '..' : title;

  let badgeList = Array.isArray(badges) ? badges : [{ text: badges || 'INDICATOR', color: glow }];
  let badgesSvg = '';

  if (badgeList.length === 1) {
    const b = badgeList[0];
    badgesSvg = `<rect x="30" y="56" width="100" height="15" rx="4.5" fill="${b.color}28" stroke="${b.color}" stroke-width="0.8"/>
    <text x="80" y="67" fill="${b.color}" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="7.4" font-weight="800" text-anchor="middle" letter-spacing="0.4">${b.text}</text>`;
  } else if (badgeList.length >= 2) {
    const b1 = badgeList[0];
    const b2 = badgeList[1];
    badgesSvg = `<rect x="15" y="56" width="62" height="15" rx="4.5" fill="${b1.color}28" stroke="${b1.color}" stroke-width="0.8"/>
    <text x="46" y="67" fill="${b1.color}" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="6.8" font-weight="800" text-anchor="middle">${b1.text}</text>
    <rect x="83" y="56" width="62" height="15" rx="4.5" fill="${b2.color}28" stroke="${b2.color}" stroke-width="0.8"/>
    <text x="114" y="67" fill="${b2.color}" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="6.8" font-weight="800" text-anchor="middle">${b2.text}</text>`;
  }

  const raw = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 160 80" width="160" height="80">
    <defs>
      <radialGradient id="halo_${iconType}_${cleanGlow}" cx="50%" cy="50%" r="50%">
        <stop offset="0%" stop-color="${glow}" stop-opacity="0.95"/>
        <stop offset="45%" stop-color="${glow}" stop-opacity="0.32"/>
        <stop offset="100%" stop-color="${glow}" stop-opacity="0"/>
      </radialGradient>
      <filter id="glow_${cleanGlow}" x="-20%" y="-20%" width="140%" height="140%">
        <feDropShadow dx="0" dy="2" stdDeviation="3.5" flood-color="${glow}" flood-opacity="0.5"/>
      </filter>
    </defs>
    
    <!-- Lower Pill Card -->
    <rect x="8" y="30" width="144" height="46" rx="11" fill="#04091a" stroke="${glow}" stroke-width="1.6" filter="url(#glow_${cleanGlow})"/>
    <text x="80" y="47" fill="#ffffff" font-family="'JetBrains Mono', monospace" font-size="8.8" font-weight="700" text-anchor="middle">${displayTitle}</text>
    ${badgesSvg}

    <!-- Top Circle Halo & Icon -->
    <circle cx="80" cy="18" r="21" fill="url(#halo_${iconType}_${cleanGlow})"/>
    <circle cx="80" cy="18" r="15.5" fill="#030714" stroke="${glow}" stroke-width="2.2"/>
    <g transform="translate(68.5, 6.5) scale(0.95)">${path}</g>
  </svg>`;

  return 'data:image/svg+xml;utf8,' + encodeURIComponent(raw);
}

const initialElements = [
  // 1. Center Core Malicious Domain
  {
    data: {
      id: 'node_center',
      title: 'update-microsoft-security.com',
      cardSvg: makeNodeCardSvg('update-microsoft-security.com', [{ text: 'Malicious', color: '#ff3366' }], 'globe', '#ff3366')
    },
    position: { x: 480, y: 270 }
  },
  // 2. Top Malicious IP
  {
    data: {
      id: 'node_ip_c2',
      title: '185.220.101.45',
      cardSvg: makeNodeCardSvg('185.220.101.45', [{ text: 'Malicious IP', color: '#ff3366' }], 'server', '#ff3366')
    },
    position: { x: 480, y: 80 }
  },
  // 3. Top-Left Lookalike Domain
  {
    data: {
      id: 'node_dom_lookalike',
      title: 'microsoft-secure.com',
      cardSvg: makeNodeCardSvg('microsoft-secure.com', [{ text: 'Lookalike Domain', color: '#c084fc' }], 'globe', '#a855f7')
    },
    position: { x: 190, y: 150 }
  },
  // 4. Left Threat Actor
  {
    data: {
      id: 'node_actor',
      title: 'APT29',
      cardSvg: makeNodeCardSvg('APT29', [{ text: 'Threat Actor', color: '#00e676' }, { text: 'TTP: T1566 →', color: '#ffab00' }], 'user', '#00e676')
    },
    position: { x: 140, y: 340 }
  },
  // 5. Bottom-Left Suspicious Domain
  {
    data: {
      id: 'node_dom_susp',
      title: 'login-microsoft365.com',
      cardSvg: makeNodeCardSvg('login-microsoft365.com', [{ text: 'Suspicious Domain', color: '#38bdf8' }], 'globe', '#00e5ff')
    },
    position: { x: 300, y: 460 }
  },
  // 6. Bottom-Right Hosting IP
  {
    data: {
      id: 'node_ip_host',
      title: '103.21.45.77',
      cardSvg: makeNodeCardSvg('103.21.45.77', [{ text: 'Hosting IP', color: '#ff3366' }, { text: 'Infrastructure', color: '#ff3366' }], 'server', '#ff3366')
    },
    position: { x: 670, y: 460 }
  },
  // 7. Right Malicious File
  {
    data: {
      id: 'node_file_macro',
      title: 'invoice.docx',
      cardSvg: makeNodeCardSvg('invoice.docx', [{ text: 'Malicious File', color: '#ff9100' }, { text: 'Macro', color: '#ffab00' }], 'file', '#ff9100')
    },
    position: { x: 830, y: 340 }
  },
  // 8. Top-Right Malicious URL
  {
    data: {
      id: 'node_url_mal',
      title: 'http://update-office.win',
      cardSvg: makeNodeCardSvg('http://update-office.win', [{ text: 'Malicious URL', color: '#e879f9' }], 'link', '#c084fc')
    },
    position: { x: 780, y: 150 }
  },
  // Edges
  { data: { source: 'node_ip_c2', target: 'node_center', label: 'delivers' } },
  { data: { source: 'node_ip_c2', target: 'node_dom_lookalike', label: 'resolves to' } },
  { data: { source: 'node_ip_c2', target: 'node_url_mal', label: 'resolves to' } },
  { data: { source: 'node_center', target: 'node_dom_lookalike', label: 'utilizes' } },
  { data: { source: 'node_center', target: 'node_url_mal', label: 'redirects to' } },
  { data: { source: 'node_center', target: 'node_file_macro', label: 'delivers' } },
  { data: { source: 'node_center', target: 'node_ip_host', label: 'communicates to' } },
  { data: { source: 'node_center', target: 'node_dom_susp', label: 'associated with' } },
  { data: { source: 'node_actor', target: 'node_center', label: 'associated with' } }
];

function initMockupGraph(elements, layoutName = 'preset') {
  const container = document.getElementById('cy');
  if (!container) return;

  const preparedElements = elements.map(el => {
    if (el.data && !el.data.source && !el.data.cardSvg) {
      const title = el.data.title || (el.data.label || el.data.id).split('\n')[0];
      const badge = el.data.badge || (el.data.label || '').split('\n')[1] || 'THREAT ENTITY';
      const color = el.data.color || '#00e5ff';
      el.data.cardSvg = makeNodeCardSvg(title, [{ text: badge, color: color }], el.data.type || 'globe', color);
    }
    return el;
  });

  const layoutConfigs = {
    preset: { name: 'preset', padding: 50, animate: true, animationDuration: 350 },
    cose: {
      name: 'cose',
      animate: true,
      nodeRepulsion: function() { return 1200000; },
      nodeOverlap: 20,
      idealEdgeLength: function() { return 180; },
      edgeElasticity: function() { return 100; },
      padding: 50,
      randomize: false
    },
    breadthfirst: { name: 'breadthfirst', directed: true, spacingFactor: 1.6, padding: 50, animate: true },
    concentric: {
      name: 'concentric',
      concentric: function(node) { return node.id() === 'node_center' ? 3 : 1; },
      levelWidth: function() { return 1; },
      padding: 60,
      animate: true
    }
  };

  cy = cytoscape({
    container: container,
    elements: preparedElements,
    style: [
      {
        selector: 'node',
        style: {
          'width': 154,
          'height': 78,
          'shape': 'round-rectangle',
          'background-image': 'data(cardSvg)',
          'background-fit': 'contain',
          'background-repeat': 'no-repeat',
          'background-color': 'transparent',
          'border-width': 0,
          'label': ''
        }
      },
      {
        selector: 'node:selected',
        style: { 'border-width': 0 }
      },
      {
        selector: 'edge',
        style: {
          'width': 1.8,
          'line-color': '#1a3a60',
          'target-arrow-color': '#38bdf8',
          'target-arrow-shape': 'triangle',
          'arrow-scale': 0.9,
          'curve-style': 'bezier',
          'label': 'data(label)',
          'font-size': '8px',
          'font-family': "'JetBrains Mono', monospace",
          'font-weight': 600,
          'color': '#7dd3fc',
          'text-rotation': 'autorotate',
          'text-background-color': '#040817',
          'text-background-opacity': 0.92,
          'text-background-padding': '3px',
          'text-background-shape': 'roundrectangle',
          'text-border-color': '#132847',
          'text-border-width': 0.8
        }
      }
    ],
    layout: layoutConfigs[layoutName] || layoutConfigs.preset
  });

  cy.on('tap', 'node', function(evt) {
    const node = evt.target;
    const data = node.data();
    const label = data.title || data.id;

    cy.elements().removeClass('selected-node');
    node.addClass('selected-node');

    if (typeof copilotWidgetActive !== 'undefined' && !copilotWidgetActive) {
      toggleCopilotWidget();
    }

    const input = document.getElementById('copilotInput');
    if (input) {
      input.value = `Analyze threat entity "${label}" and recommend containment`;
      input.focus();
    }
  });

  setTimeout(() => {
    if (cy) cy.fit(null, 45);
  }, 80);
}

function setLayout(name) {
  currentLayout = name;
  if (cy) {
    initMockupGraph(cy.elements().jsons(), name);
  }
}

function fitGraph() {
  if (cy) cy.fit(null, 45);
}

function zoomGraph(factor) {
  if (!cy) return;
  cy.zoom({
    level: cy.zoom() * factor,
    renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 }
  });
}

function centerGraph() {
  if (cy) cy.center();
}

function setGraphView(mode) {
  document.querySelectorAll('.graph-top-tab').forEach(t => t.classList.remove('active'));

  const tabMap = {
    graph: document.getElementById('tabGraph'),
    timeline: document.getElementById('tabTimeline'),
    ioc: document.getElementById('tabIoc'),
    network: document.getElementById('tabNetwork')
  };
  if (tabMap[mode]) tabMap[mode].classList.add('active');

  const cyDiv = document.getElementById('cy');
  const watermarkDiv = document.querySelector('.graph-world-map-watermark');
  const layoutDropdown = document.getElementById('graphLayoutDropdown');

  if (cyDiv) cyDiv.style.display = 'block';
  if (watermarkDiv) watermarkDiv.style.display = 'block';

  if (mode === 'graph') {
    if (layoutDropdown) layoutDropdown.value = 'preset';
    initMockupGraph(initialElements, 'preset');
  } else if (mode === 'timeline') {
    if (layoutDropdown) layoutDropdown.value = 'preset';
    const timelineElements = [
      { data: { id: 'evt1', title: 'Domain Registered', cardSvg: makeNodeCardSvg('update-microsoft-s[.]net', [{ text: '2026-09-01 04:12', color: '#38bdf8' }], 'globe', '#00e5ff') }, position: { x: 160, y: 260 } },
      { data: { id: 'evt2', title: 'C2 Server Active', cardSvg: makeNodeCardSvg('185.220.101.45', [{ text: '2026-09-03 11:20', color: '#ff9100' }], 'server', '#ff9100') }, position: { x: 400, y: 260 } },
      { data: { id: 'evt3', title: 'First Egress Beacon', cardSvg: makeNodeCardSvg('Port 443 / HTTPS', [{ text: '2026-09-04 14:22', color: '#ff3366' }], 'link', '#ff3366') }, position: { x: 640, y: 260 } },
      { data: { id: 'evt4', title: 'SOC AI Triage', cardSvg: makeNodeCardSvg('Threat Detected', [{ text: '2026-09-06 07:15', color: '#00e676' }], 'user', '#00e676') }, position: { x: 880, y: 260 } },
      { data: { source: 'evt1', target: 'evt2', label: 'precedes' } },
      { data: { source: 'evt2', target: 'evt3', label: 'triggers' } },
      { data: { source: 'evt3', target: 'evt4', label: 'correlated by' } }
    ];
    initMockupGraph(timelineElements, 'preset');
  } else if (mode === 'ioc') {
    if (layoutDropdown) layoutDropdown.value = 'preset';
    const iocElements = [
      { data: { id: 'root', title: 'Threat Cluster', cardSvg: makeNodeCardSvg('Threat Cluster', [{ text: 'High Confidence', color: '#ff3366' }], 'globe', '#ff3366') }, position: { x: 480, y: 270 } },
      { data: { id: 'ioc_ip', title: '185.220.101.45', cardSvg: makeNodeCardSvg('185.220.101.45', [{ text: 'IPv4 Indicator', color: '#ff3366' }], 'server', '#ff3366') }, position: { x: 260, y: 150 } },
      { data: { id: 'ioc_dom', title: 'update-microsoft-s[.]net', cardSvg: makeNodeCardSvg('update-microsoft-s[.]net', [{ text: 'FQDN Indicator', color: '#c084fc' }], 'globe', '#a855f7') }, position: { x: 700, y: 150 } },
      { data: { id: 'ioc_hash', title: 'invoice.docx', cardSvg: makeNodeCardSvg('invoice.docx', [{ text: 'Malicious File', color: '#ff9100' }, { text: 'Macro', color: '#ffab00' }], 'file', '#ff9100') }, position: { x: 480, y: 440 } },
      { data: { source: 'ioc_ip', target: 'root', label: 'C2 IP' } },
      { data: { source: 'ioc_dom', target: 'root', label: 'C2 Domain' } },
      { data: { source: 'ioc_hash', target: 'root', label: 'Dropped Payload' } }
    ];
    initMockupGraph(iocElements, 'preset');
  } else if (mode === 'network') {
    if (layoutDropdown) layoutDropdown.value = 'concentric';
    initMockupGraph(initialElements, 'concentric');
  }
}

async function triggerGraphRAGHunt(targetIoc) {
  const ioc = targetIoc || (document.getElementById('searchInput') ? document.getElementById('searchInput').value.trim() : '') || 'update-microsoft-security.com';
  const btn = document.getElementById('btnGraphRAGHunt');
  const origHtml = btn ? btn.innerHTML : '';
  if (btn) {
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> <span>Hunting...</span>';
    btn.disabled = true;
  }

  try {
    const resp = await fetch('/api/investigation/graphrag/hunt', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ root_ioc: ioc, max_hops: 3 })
    });
    if (!resp.ok) throw new Error('GraphRAG hunt failed');
    const data = await resp.json();

    const huntNodes = (data.discovered_nodes || []).map((n, idx) => {
      const isRoot = n.hop === 0;
      const color = n.risk === 'CRITICAL' ? '#ff3366' : (n.risk === 'HIGH' ? '#ff9100' : '#00e5ff');
      const iconType = n.type === 'ASN' ? 'server' : (n.type === 'DOMAIN' || n.type === 'ROOT_IOC' ? 'globe' : (n.type === 'ACTOR' ? 'user' : (n.type === 'FILE' ? 'file' : 'link')));

      const angle = (idx / Math.max(data.discovered_nodes.length, 1)) * 2 * Math.PI;
      const radius = isRoot ? 0 : 200 + (n.hop * 80);
      const px = Math.round(480 + radius * Math.cos(angle));
      const py = Math.round(270 + radius * Math.sin(angle));

      return {
        data: {
          id: n.id,
          title: n.title,
          cardSvg: makeNodeCardSvg(n.title, [{ text: `Hop ${n.hop} · ${n.type}`, color: color }], iconType, color)
        },
        position: { x: px, y: py }
      };
    });

    const huntEdges = (data.discovered_edges || []).map(e => ({
      data: { source: e.source, target: e.target, label: e.label }
    }));

    const combinedElements = [...huntNodes, ...huntEdges];
    initMockupGraph(combinedElements, 'cose');

    const statNodes = document.getElementById('canvasStatNodes');
    const statRels = document.getElementById('canvasStatRels');
    const statPivots = document.getElementById('canvasStatPivots');
    if (statNodes) statNodes.textContent = data.total_nodes || huntNodes.length;
    if (statRels) statRels.textContent = data.total_edges || huntEdges.length;
    if (statPivots) statPivots.textContent = data.critical_entities_count || 4;

    if (typeof copilotWidgetActive !== 'undefined' && !copilotWidgetActive) toggleCopilotWidget();
    if (typeof appendCopilotMessage === 'function') {
      appendCopilotMessage('assistant', `**GraphRAG Autonomous Hunt Completed**\n\nTraversed 3 hops radiating from \`${ioc}\`. Discovered **${data.total_nodes}** connected threat assets and **${data.critical_entities_count}** critical clusters.`);
    }

  } catch (err) {
    console.error('GraphRAG hunt error:', err);
    alert('GraphRAG Hunt issue: ' + err.message);
  } finally {
    if (btn) {
      btn.innerHTML = origHtml;
      btn.disabled = false;
    }
  }
}
