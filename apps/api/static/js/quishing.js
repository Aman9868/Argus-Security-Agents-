/**
 * Autonomous Quishing & Advanced Phishing Analysis Client Module
 * Dissects QR payloads, unrolls redirect evasion chains, parses SPF/DKIM/DMARC headers,
 * fingerprints credential harvesters, and orchestrates tenant mailbox purges.
 */

let currentQuishingAnalysis = null;

async function openQuishingModal(sampleId = null) {
  const modal = document.getElementById('quishingModal');
  if (!modal) return;
  modal.classList.add('active');

  await loadQuishingSampleList(sampleId);

  // Reset to initial clean state: when not searched, show NO data
  currentQuishingAnalysis = null;
  const loadingContainer = document.getElementById('quishingLoading');
  const resultsContainer = document.getElementById('quishingResults');
  const emptyState = document.getElementById('quishingEmptyState');

  if (loadingContainer) loadingContainer.style.display = 'none';
  if (resultsContainer) resultsContainer.style.display = 'none';
  if (emptyState) emptyState.style.display = 'block';

  // Default to Live Dynamic Dissector tab so user can input custom items
  switchQuishingTab('custom');

  // If a specific sampleId was explicitly requested (not null), run it
  if (sampleId) {
    runQuishingAnalysis(sampleId);
  }
}

async function loadQuishingSampleList(selectedId) {
  const selectEl = document.getElementById('quishingSampleSelect');
  if (!selectEl) return;

  try {
    const res = await fetch('/api/phishing/samples');
    if (!res.ok) return;
    const data = await res.json();
    selectEl.innerHTML = data.samples.map((s, idx) => `
      <option value="${s.sample_id}" ${s.sample_id === selectedId || (!selectedId && idx === 0) ? 'selected' : ''}>
        ${s.has_qr_code ? '📷 [QUISH]' : '📧 [EMAIL]'} ${s.subject.slice(0, 36)}...
      </option>
    `).join('');
  } catch (err) {
    console.warn('Error loading phishing samples list:', err);
  }
}

async function runQuishingAnalysis(sampleId) {
  if (!sampleId) {
    const selectEl = document.getElementById('quishingSampleSelect');
    sampleId = selectEl ? selectEl.value : 'sample_quishing_m365';
  }

  const loadingContainer = document.getElementById('quishingLoading');
  const resultsContainer = document.getElementById('quishingResults');
  const emptyState = document.getElementById('quishingEmptyState');

  if (emptyState) emptyState.style.display = 'none';
  if (loadingContainer) loadingContainer.style.display = 'flex';
  if (resultsContainer) resultsContainer.style.display = 'none';

  try {
    const res = await fetch('/api/phishing/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sample_id: sampleId })
    });

    if (!res.ok) throw new Error(`Analysis failed HTTP ${res.status}`);
    const data = await res.json();
    currentQuishingAnalysis = data;
    renderQuishingResults(data);
  } catch (err) {
    console.error('Error running quishing analysis:', err);
    if (loadingContainer) {
      loadingContainer.innerHTML = `<div style="color: #ff3366; text-align: center; padding: 20px;">
        <i class="fa-solid fa-triangle-exclamation" style="font-size: 1.5rem; margin-bottom: 8px;"></i>
        <div>Analysis error: ${err.message}</div>
      </div>`;
    }
  } finally {
    if (loadingContainer && currentQuishingAnalysis) loadingContainer.style.display = 'none';
    if (resultsContainer && currentQuishingAnalysis) resultsContainer.style.display = 'block';
  }
}

function renderQuishingResults(data) {
  // 1. Verdict & Subject
  const verdictBadge = document.getElementById('quishingVerdictBadge');
  if (verdictBadge) {
    verdictBadge.textContent = data.verdict;
    if (data.risk_score >= 90) {
      verdictBadge.className = 'shortcut-badge tag-critical';
      verdictBadge.style.color = '#ff1744';
      verdictBadge.style.borderColor = '#ff1744';
    } else {
      verdictBadge.className = 'shortcut-badge tag-threat';
      verdictBadge.style.color = '#ff9100';
      verdictBadge.style.borderColor = '#ff9100';
    }
  }

  const subjEl = document.getElementById('quishSubject');
  if (subjEl) subjEl.textContent = data.subject;

  const senderEl = document.getElementById('quishSender');
  if (senderEl) senderEl.innerHTML = `<code>${escapeHtml(data.sender)}</code>`;

  const ipEl = document.getElementById('quishSenderIp');
  if (ipEl) ipEl.textContent = data.sender_ip || 'N/A';

  const recipEl = document.getElementById('quishRecipient');
  if (recipEl) recipEl.textContent = data.recipient;

  const homoEl = document.getElementById('quishHomoglyph');
  if (homoEl && data.headers) {
    if (data.headers.homograph_detected) {
      homoEl.innerHTML = `<span class="badge-critical"><i class="fa-solid fa-triangle-exclamation"></i> ${escapeHtml(data.headers.homograph_details)}</span>`;
    } else {
      homoEl.innerHTML = '<span class="badge-low"><i class="fa-solid fa-check"></i> Standard ASCII Domain</span>';
    }
  }

  // 2. Auth Badges (SPF / DKIM / DMARC)
  if (data.headers) {
    updateAuthPill('authSpfBox', 'authSpfVal', data.headers.spf ? data.headers.spf.status : 'NONE');
    updateAuthPill('authDkimBox', 'authDkimVal', data.headers.dkim ? data.headers.dkim.status : 'NONE');
    updateAuthPill('authDmarcBox', 'authDmarcVal', data.headers.dmarc ? data.headers.dmarc.status : 'NONE');

    const detailsEl = document.getElementById('authDetailsText');
    if (detailsEl) {
      const spfDetail = data.headers.spf ? data.headers.spf.details : '';
      const dmarcDetail = data.headers.dmarc ? data.headers.dmarc.details : '';
      detailsEl.textContent = `${spfDetail} | ${dmarcDetail}`;
    }
  }

  // 3. QR Section Visibility
  const qrSection = document.getElementById('quishQrSection');
  if (qrSection) {
    qrSection.style.display = data.has_qr_code ? 'block' : 'none';
  }
  const rawQrEl = document.getElementById('quishRawQrPayload');
  if (rawQrEl && data.qr_data) {
    rawQrEl.textContent = data.qr_data.raw_encoded_payload;
  }

  // 4. Redirect Chain
  const redirectContainer = document.getElementById('quishRedirectContainer');
  if (redirectContainer && data.redirect_chain) {
    redirectContainer.innerHTML = data.redirect_chain.map((hop, idx) => `
      <div class="redirect-hop-row">
        <div class="hop-badge">Hop #${hop.step || (idx + 1)}</div>
        <div class="hop-content">
          <div class="hop-url"><code>${escapeHtml(hop.url)}</code></div>
          <div class="hop-evasion"><i class="fa-solid fa-shield-virus" style="color: #ff9100;"></i> ${hop.evasion_technique}</div>
        </div>
        <span class="hop-status-code">${hop.status_code}</span>
      </div>
    `).join('');
  }

  // 5. Landing Page & Harvester
  if (data.landing_page_analysis) {
    const brandEl = document.getElementById('quishSpoofedBrand');
    if (brandEl) brandEl.textContent = data.landing_page_analysis.spoofed_brand;

    const fieldsContainer = document.getElementById('quishHarvestedFields');
    if (fieldsContainer && data.landing_page_analysis.harvested_fields) {
      fieldsContainer.innerHTML = data.landing_page_analysis.harvested_fields.map(f => `
        <span class="harvest-pill"><i class="fa-solid fa-key" style="color: #ff3366;"></i> ${f}</span>
      `).join('');
    }

    const c2Container = document.getElementById('quishC2Infra');
    if (c2Container && data.landing_page_analysis.hosted_infra) {
      const infra = data.landing_page_analysis.hosted_infra;
      const cert = data.landing_page_analysis.ssl_certificate || {};
      c2Container.innerHTML = `
        <div>Host IP: <strong style="color: var(--neon-cyan);">${infra.ip}</strong> (${infra.country}) &bull; ${infra.asn}</div>
        <div style="margin-top: 2px; color: var(--text-muted);">SSL: ${cert.issuer || 'N/A'} (Valid: ${cert.validity_days || 0}d)</div>
      `;
    }
  }

  // 6. Fleet Purge Status
  const exposedEl = document.getElementById('quishExposedMailboxes');
  if (exposedEl) exposedEl.textContent = `${data.affected_mailboxes_estimate || 24} Inboxes`;

  // Reset button state
  const purgeBtn = document.getElementById('btnExecuteFleetPurge');
  if (purgeBtn) {
    purgeBtn.innerHTML = '<i class="fa-solid fa-trash-can"></i> Purge Across Fleet Inboxes';
    purgeBtn.style.background = 'linear-gradient(135deg, rgba(255, 51, 102, 0.25), rgba(255, 23, 68, 0.35))';
    purgeBtn.style.color = '#ffffff';
    purgeBtn.disabled = false;
  }
}

function updateAuthPill(boxId, valId, statusVal) {
  const box = document.getElementById(boxId);
  const val = document.getElementById(valId);
  if (!box || !val) return;

  val.textContent = statusVal;
  if (statusVal === 'PASS') {
    box.className = 'auth-pill-item auth-pass';
  } else if (statusVal === 'SOFTFAIL' || statusVal === 'NONE') {
    box.className = 'auth-pill-item auth-warn';
  } else {
    box.className = 'auth-pill-item auth-fail';
  }
}

async function executeFleetMailboxPurge() {
  if (!currentQuishingAnalysis) return;

  const btn = document.getElementById('btnExecuteFleetPurge');
  if (btn) {
    btn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Purging inboxes...';
    btn.disabled = true;
  }

  try {
    const res = await fetch('/api/phishing/purge-fleet', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sample_id: currentQuishingAnalysis.sample_id })
    });

    if (!res.ok) throw new Error(`Purge failed HTTP ${res.status}`);
    const result = await res.json();

    if (btn) {
      btn.innerHTML = '<i class="fa-solid fa-check"></i> Purge Completed';
      btn.style.background = 'rgba(0, 230, 118, 0.2)';
      btn.style.borderColor = '#00e676';
      btn.style.color = '#00e676';
    }

    const purgeCard = document.getElementById('quishPurgeStatus');
    if (purgeCard) {
      purgeCard.style.borderColor = '#00e676';
      purgeCard.innerHTML = `
        <div style="display: flex; align-items: center; gap: 10px;">
          <div class="purge-icon" style="background: rgba(0, 230, 118, 0.15); color: #00e676;"><i class="fa-solid fa-shield-check"></i></div>
          <div>
            <strong style="color: #00e676; font-size: 0.85rem;">Tenant Quarantine Active — ${result.malicious_messages_purged} Messages Hard-Deleted</strong>
            <div style="font-size: 0.72rem; color: #cbd5e1; margin-top: 3px;">${result.actions_executed.join(' &bull; ')}</div>
          </div>
        </div>
      `;
    }

    alert(`Success: ${result.malicious_messages_purged} messages purged across enterprise tenant inboxes!`);
  } catch (err) {
    alert(`Fleet purge failed: ${err.message}`);
    if (btn) btn.disabled = false;
  }
}

function switchQuishingTab(tab) {
  const btnCatalog = document.getElementById('btnQuishTabCatalog');
  const btnCustom = document.getElementById('btnQuishTabCustom');
  const catalogSelect = document.getElementById('quishCatalogSelectorWrapper');
  const customDrawer = document.getElementById('quishCustomDrawer');

  if (tab === 'custom') {
    if (btnCustom) btnCustom.classList.add('active');
    if (btnCatalog) btnCatalog.classList.remove('active');
    if (catalogSelect) catalogSelect.style.display = 'none';
    if (customDrawer) customDrawer.style.display = 'block';
  } else {
    if (btnCatalog) btnCatalog.classList.add('active');
    if (btnCustom) btnCustom.classList.remove('active');
    if (catalogSelect) catalogSelect.style.display = 'flex';
    if (customDrawer) customDrawer.style.display = 'none';
  }
}

function fillQuishTemplate(type) {
  const input = document.getElementById('quishCustomTextInput');
  if (!input) return;

  if (type === 'homoglyph') {
    input.value = `From: IT Helpdesk <admin-notice@mіcrosoft-security-portal.com>\nSubject: Critical Account Security Re-authentication Required\nTo: finance-ops@enterprise-corp.com\nOrigin IP: 185.220.101.45\nURL: https://www.google.com/url?q=https://mіcrosoft-session-auth.xyz/sso/login`;
  } else if (type === 'okta') {
    input.value = `From: Okta System Notification <no-reply@okta-verify-sso.cloud>\nSubject: Your Corporate Okta FastPass Session Has Expired\nTo: devops-infra@enterprise-corp.com\nOrigin IP: 194.26.29.112\nURL: https://bit.ly/3xOktaFastPassRenewal`;
  } else if (type === 'wire') {
    input.value = `From: Global Treasury Services <wire-transfer@swift-payment-secure.biz>\nSubject: Action Required: Wire Transfer Approval Authorization #88209\nTo: accounts-payable@enterprise-corp.com\nOrigin IP: 45.142.214.88\nURL: https://auth-docu-vault.s3.amazonaws.com/login.html`;
  }
}

async function submitCustomQuishingDissection() {
  const input = document.getElementById('quishCustomTextInput');
  const text = input ? input.value.trim() : '';

  if (!text) {
    alert('Please enter email headers, a phishing URL, or a QR payload to dissect.');
    return;
  }

  const loadingContainer = document.getElementById('quishingLoading');
  const resultsContainer = document.getElementById('quishingResults');
  const emptyState = document.getElementById('quishingEmptyState');
  if (emptyState) emptyState.style.display = 'none';
  if (loadingContainer) loadingContainer.style.display = 'flex';
  if (resultsContainer) resultsContainer.style.display = 'none';

  try {
    const res = await fetch('/api/phishing/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sample_id: 'custom_input', custom_text: text })
    });

    if (!res.ok) throw new Error(`Custom analysis failed: HTTP ${res.status}`);
    const data = await res.json();
    currentQuishingAnalysis = data;
    renderQuishingResults(data);
  } catch (err) {
    console.error('Error dissecting custom input:', err);
    alert(`Dynamic analysis error: ${err.message}`);
  } finally {
    if (loadingContainer && currentQuishingAnalysis) loadingContainer.style.display = 'none';
    if (resultsContainer && currentQuishingAnalysis) resultsContainer.style.display = 'block';
  }
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

window.openQuishingModal = openQuishingModal;
window.loadQuishingSampleList = loadQuishingSampleList;
window.runQuishingAnalysis = runQuishingAnalysis;
window.executeFleetMailboxPurge = executeFleetMailboxPurge;
window.switchQuishingTab = switchQuishingTab;
window.fillQuishTemplate = fillQuishTemplate;
window.submitCustomQuishingDissection = submitCustomQuishingDissection;

