// =========================================================================
// CORE CYBER SENTINEL APPLICATION LOGIC & ORCHESTRATION
// =========================================================================

let currentIoc = 'update-microsoft-security.com';
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

async function triggerRun() {
  const searchInput = document.getElementById('searchInput');
  const ioc = searchInput ? searchInput.value.trim() : '';
  if (!ioc) return;

  currentIoc = ioc;
  const radarOverlay = document.getElementById('radarOverlay');
  if (radarOverlay) radarOverlay.classList.add('active');

  const stepperDots = document.querySelectorAll('.stepper-dot');
  stepperDots.forEach(d => d.classList.add('active'));

  try {
    const resp = await fetch('/api/investigation/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ioc: ioc })
    });

    if (!resp.ok) throw new Error('Investigation request failed');
    const data = await resp.json();

    const isBenign = (data.verdict || '').toUpperCase() === 'BENIGN';

    const graphNodes = [
      { data: { id: 'target_root', title: ioc, cardSvg: makeNodeCardSvg(ioc, [{ text: isBenign ? 'Verified' : 'Malicious', color: isBenign ? '#00e676' : '#ff3366' }], 'globe', isBenign ? '#00e676' : '#ff3366') }, position: { x: 480, y: 270 } },
      { data: { id: 'node_asn', title: 'AS32934 BGP Route', cardSvg: makeNodeCardSvg('AS32934 BGP Route', [{ text: 'Infrastructure', color: '#c084fc' }], 'server', '#a855f7') }, position: { x: 250, y: 150 } },
      { data: { id: 'node_geo', title: isBenign ? 'United States' : 'Frankfurt, DE', cardSvg: makeNodeCardSvg(isBenign ? 'United States' : 'Frankfurt, DE', [{ text: 'Hosting IP', color: '#a855f7' }], 'globe', '#a855f7') }, position: { x: 710, y: 150 } },
      { data: { id: 'node_reg', title: isBenign ? 'CSC Domains' : 'NameCheap, Inc.', cardSvg: makeNodeCardSvg(isBenign ? 'CSC Domains' : 'NameCheap', [{ text: 'Registrar', color: '#38bdf8' }], 'globe', '#00e5ff') }, position: { x: 300, y: 440 } },
      { data: { id: 'node_sec', title: 'Verdict: ' + (data.verdict || 'BENIGN'), cardSvg: makeNodeCardSvg('Verdict: ' + (data.verdict || 'BENIGN'), [{ text: 'Score: ' + (data.confidence_score || 0.95).toFixed(2), color: isBenign ? '#00e676' : '#ff9100' }], 'globe', isBenign ? '#00e676' : '#ff9100') }, position: { x: 660, y: 440 } },
      { data: { source: 'target_root', target: 'node_asn', label: 'announced by' } },
      { data: { source: 'target_root', target: 'node_geo', label: 'hosted at' } },
      { data: { source: 'target_root', target: 'node_reg', label: 'registered with' } },
      { data: { source: 'target_root', target: 'node_sec', label: 'evaluated as' } }
    ];

    initMockupGraph(graphNodes, 'preset');
    checkContainmentStatus(ioc);

  } catch (err) {
    console.error('Investigation error:', err);
  } finally {
    if (radarOverlay) radarOverlay.classList.remove('active');
    stepperDots.forEach(d => d.classList.remove('active'));
  }
}

async function checkContainmentStatus(ioc) {
  try {
    const resp = await fetch(`/api/hitl/status?target=${encodeURIComponent(ioc)}`);
    if (!resp.ok) return;
    const data = await resp.json();
    const box = document.getElementById('hitlContainmentBox');
    if (box) {
      box.style.display = data.is_quarantined ? 'none' : 'block';
    }
  } catch (err) {
    console.warn('Containment check error:', err);
  }
}

async function approveQuarantine() {
  try {
    const resp = await fetch('/api/hitl/approve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: currentIoc, action: 'APPROVE' })
    });
    if (resp.ok) {
      alert('Perimeter firewall isolation rule enforced.');
      checkContainmentStatus(currentIoc);
    }
  } catch (err) {
    console.error('Quarantine approval error:', err);
  }
}

function triggerSearchWithIoc(ioc) {
  const input = document.getElementById('searchInput');
  if (input) {
    input.value = ioc;
    triggerRun();
  }
}

document.addEventListener('DOMContentLoaded', () => {
  if (typeof initMockupGraph === 'function') {
    initMockupGraph(initialElements, 'preset');
  }
  const approveBtn = document.getElementById('approveQuarantineBtn');
  if (approveBtn) approveBtn.addEventListener('click', approveQuarantine);
  const dismissBtn = document.getElementById('dismissQuarantineBtn');
  if (dismissBtn) dismissBtn.addEventListener('click', () => {
    const box = document.getElementById('hitlContainmentBox');
    if (box) box.style.display = 'none';
  });
});
