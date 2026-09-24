document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById(btn.dataset.tab).classList.add('active');
  });
});

function riskClass(level) {
  return level.toLowerCase();
}

function renderResult(container, data, metaLine) {
  container.classList.remove('hidden');
  const cls = riskClass(data.risk_level);

  const flagsHtml = data.flags.map(f => `<li>${escapeHtml(f)}</li>`).join('');

  container.innerHTML = `
    <div class="result-header ${cls}">
      <div>
        <div class="risk-badge ${cls}">${data.risk_level} Risk</div>
      </div>
      <div class="risk-score">Score: ${data.risk_score}/100</div>
    </div>
    <ul class="flags-list">${flagsHtml}</ul>
    ${metaLine ? `<div class="meta-line">${metaLine}</div>` : ''}
  `;
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

async function callApi(endpoint, payload) {
  const res = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Something went wrong');
  return data;
}

document.getElementById('urlBtn').addEventListener('click', async () => {
  const url = document.getElementById('urlInput').value.trim();
  const resultBox = document.getElementById('urlResult');
  if (!url) {
    alert('Please enter a URL to check.');
    return;
  }
  try {
    const data = await callApi('/api/check-url', { url });
    renderResult(resultBox, data, `Domain analyzed: ${escapeHtml(data.domain_analyzed)}`);
  } catch (err) {
    alert(err.message);
  }
});

document.getElementById('emailBtn').addEventListener('click', async () => {
  const sender = document.getElementById('emailSender').value.trim();
  const subject = document.getElementById('emailSubject').value.trim();
  const body = document.getElementById('emailBody').value.trim();
  const resultBox = document.getElementById('emailResult');

  if (!sender && !body) {
    alert('Please enter at least a sender email or message body.');
    return;
  }
  try {
    const data = await callApi('/api/check-email', { sender, subject, body });
    renderResult(resultBox, data, `Links scanned in body: ${data.links_scanned}`);
  } catch (err) {
    alert(err.message);
  }
});

document.getElementById('urlInput').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') document.getElementById('urlBtn').click();
});
