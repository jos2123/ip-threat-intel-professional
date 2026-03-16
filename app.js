async function analyzeIPs() {
  const input = document.getElementById('ipInput').value.trim();
  const loading = document.getElementById('loading');
  const results = document.getElementById('results');
  const btn = document.getElementById('analyzeBtn');

  if (!input) {
    showToast('Please enter at least one IP address', 'error');
    return;
  }

  const ips = input.split(/[\n,]/).map(ip => ip.trim()).filter(ip => ip);

  if (ips.length === 0) {
    showToast('No valid IP addresses found', 'error');
    return;
  }

  loading.style.display = 'block';
  results.style.display = 'none';
  btn.disabled = true;

  try {
    const promises = ips.map(ip => analyzeIP(ip));
    const allResults = await Promise.allSettled(promises);
    displayResults(allResults, ips);
  } catch (err) {
    showToast(err.message, 'error');
  } finally {
    loading.style.display = 'none';
    btn.disabled = false;
  }
}

async function analyzeIP(ip) {
  const response = await fetch(`/api/analyze-ip?ip=${ip}`);
  const data = await response.json();
  if (!response.ok) throw new Error(`${ip}: ${data.error}`);
  return data;
}

function displayResults(results, ips) {
  const resultsDiv = document.getElementById('results');
  
  let html = `
    <div class="results-header">
      <h2>Analysis Results (${ips.length} IPs)</h2>
      <button class="btn-export" onclick="generatePDF()">Export Report</button>
    </div>
  `;

  results.forEach((result, index) => {
    const ip = ips[index];
    
    if (result.status === 'fulfilled') {
      const data = result.value;
      
      if (data.reserved) {
        html += renderReservedIP(data);
      } else if (data.blocked) {
        html += renderBlockedIP(data);
      } else {
        html += renderAnalyzedIP(data);
      }
    } else {
      html += renderErrorIP(ip, result.reason.message);
    }
  });

  resultsDiv.innerHTML = html;
  resultsDiv.style.display = 'block';
  window.lastAnalysisResults = html;
}

function renderAnalyzedIP(data) {
  const level = data.reputation.riskLevel;
  const score = data.reputation.riskScore;
  
  return `
    <div class="ip-card">
      <div class="ip-card-header risk-${level}">
        <div class="ip-info">
          <span class="ip-address">${data.ip}</span>
          <span class="risk-badge ${level}">${level}</span>
        </div>
        <span class="risk-score">Score: ${score}/100</span>
      </div>
      
      <div class="ip-card-body">
        ${data.autoBlocked ? `
          <div class="reserved-notice">
            <h4>Auto-blocked</h4>
            <p>${data.autoBlocked.type === 'single' ? 'IP blocked' : 'Subnet blocked'}: ${data.autoBlocked.blocked}</p>
          </div>
        ` : ''}
        
        <div class="data-grid">
          <div class="data-card">
            <div class="data-card-title">Network Information</div>
            ${renderDataRows({
              'ASN': data.basic?.asn || 'N/A',
              'Organization': data.basic?.organization || 'N/A',
              'Country': data.basic?.country || 'N/A',
              'City': data.basic?.city || 'N/A'
            })}
          </div>

          ${data.intelligence?.cloudflare ? `
          <div class="data-card">
            <div class="data-card-title">Traffic Analysis (ASN ${data.intelligence.cloudflare.asn})</div>
            ${renderDataRows({
              'Bot Traffic': data.intelligence.cloudflare.bot + '%',
              'Human Traffic': data.intelligence.cloudflare.human + '%'
            })}
            <div class="data-row">
              <span class="data-label">Source</span>
              <span class="data-value">Cloudflare Radar</span>
            </div>
          </div>
          ` : ''}

          <div class="data-card">
            <div class="data-card-title">AbuseIPDB</div>
            ${data.reputation.abuseipdb ? renderDataRows({
              'Confidence Score': data.reputation.abuseipdb.score + '%',
              'Total Reports': data.reputation.abuseipdb.reports,
              'Whitelisted': data.reputation.abuseipdb.isWhitelisted ? 'Yes' : 'No'
            }) : '<p class="data-label">Data not available</p>'}
          </div>

          <div class="data-card">
            <div class="data-card-title">VirusTotal</div>
            ${data.reputation.virustotal ? renderDataRows({
              'Malicious': data.reputation.virustotal.malicious,
              'Harmless': data.reputation.virustotal.harmless
            }) : '<p class="data-label">Data not available</p>'}
          </div>

          <div class="data-card">
            <div class="data-card-title">Shodan Intelligence</div>
            ${renderDataRows({
              'Open Ports': data.intelligence?.shodan?.ports?.join(', ') || 'N/A'
            })}
          </div>
        </div>
      </div>

      <div class="ip-card-actions">
        <button class="btn-action danger" onclick="blockIP('${data.ip}')">Block IP (/32)</button>
        <button class="btn-action danger" onclick="blockRange100('${data.ip}')">Block /25</button>
        <button class="btn-action danger" onclick="blockSubnet('${data.ip}')">Block /24</button>
        ${data.basic?.asn ? `<button class="btn-action" onclick="blockASN('${data.basic.asn}')">Block ${data.basic.asn}</button>` : ''}
      </div>
    </div>
  `;
}

function renderBlockedIP(data) {
  return `
    <div class="ip-card">
      <div class="ip-card-header risk-blocked">
        <div class="ip-info">
          <span class="ip-address">${data.ip}</span>
          <span class="risk-badge blocked">Blocked</span>
        </div>
      </div>
      
      <div class="ip-card-body">
        <div class="reserved-notice">
          <h4>Block Information</h4>
          <p><strong>Reason:</strong> ${data.blockInfo.reason}</p>
          <p><strong>Range:</strong> ${data.blockInfo.range}</p>
        </div>
        
        <div class="data-grid">
          <div class="data-card">
            <div class="data-card-title">Network Information</div>
            ${renderDataRows({
              'ASN': data.basic?.asn || 'N/A',
              'Organization': data.basic?.organization || 'N/A',
              'Country': data.basic?.country || 'N/A',
              'City': data.basic?.city || 'N/A'
            })}
          </div>

          <div class="data-card">
            <div class="data-card-title">AbuseIPDB</div>
            ${data.reputation?.abuseipdb ? renderDataRows({
              'Confidence Score': data.reputation.abuseipdb.score + '%',
              'Total Reports': data.reputation.abuseipdb.reports
            }) : '<p class="data-label">Data not available</p>'}
          </div>

          <div class="data-card">
            <div class="data-card-title">Shodan Intelligence</div>
            ${renderDataRows({
              'Open Ports': data.intelligence?.shodan?.ports?.join(', ') || 'N/A'
            })}
          </div>
        </div>
      </div>
    </div>
  `;
}

function renderReservedIP(data) {
  return `
    <div class="ip-card">
      <div class="ip-card-header risk-reserved">
        <div class="ip-info">
          <span class="ip-address">${data.ip}</span>
          <span class="risk-badge reserved">${data.reservedType.replace('_', ' ')}</span>
        </div>
      </div>
      
      <div class="ip-card-body">
        <div class="reserved-notice">
          <h4>Reserved IP Address</h4>
          <p>${data.message}</p>
          <p><em>${data.note}</em></p>
        </div>
        
        <div class="data-grid">
          <div class="data-card">
            <div class="data-card-title">Classification</div>
            ${renderDataRows({
              'Type': data.reservedType.replace('_', ' ').toUpperCase(),
              'Status': 'Reserved/Private IP'
            })}
          </div>
        </div>
      </div>
    </div>
  `;
}

function renderErrorIP(ip, error) {
  return `
    <div class="ip-card">
      <div class="ip-card-header risk-high">
        <div class="ip-info">
          <span class="ip-address">${ip}</span>
          <span class="risk-badge high">Error</span>
        </div>
      </div>
      <div class="ip-card-body">
        <div class="reserved-notice">
          <h4>Analysis Failed</h4>
          <p>${error}</p>
        </div>
      </div>
    </div>
  `;
}

function renderDataRows(data) {
  return Object.entries(data).map(([key, value]) => `
    <div class="data-row">
      <span class="data-label">${key}</span>
      <span class="data-value">${value}</span>
    </div>
  `).join('');
}

function showToast(message, type = 'info') {
  const existing = document.querySelector('.toast');
  if (existing) existing.remove();

  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.textContent = message;
  document.body.appendChild(toast);

  setTimeout(() => toast.remove(), 4000);
}

document.getElementById('ipInput').addEventListener('keypress', (e) => {
  if (e.key === 'Enter' && e.ctrlKey) analyzeIPs();
});

async function blockIP(ip) {
  const reason = prompt('Block reason:', 'Malicious IP detected');
  if (!reason) return;
  
  try {
    const response = await fetch('/api/block-ip', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip, reason })
    });
    const result = await response.json();
    showToast(result.success ? `IP ${ip} blocked successfully` : `Error: ${result.error}`, result.success ? 'success' : 'error');
  } catch (error) {
    showToast(`Error: ${error.message}`, 'error');
  }
}

async function blockSubnet(ip) {
  const reason = prompt('Block reason for /24 subnet:', 'Malicious subnet detected');
  if (!reason) return;
  
  try {
    const response = await fetch('/api/block-subnet', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip, cidr: 24, reason })
    });
    const result = await response.json();
    showToast(`Subnet blocked: ${result.blocked}`, 'success');
  } catch (error) {
    showToast(`Error: ${error.message}`, 'error');
  }
}

async function blockRange100(ip) {
  const reason = prompt('Block reason for /25 range:', 'Malicious range detected');
  if (!reason) return;
  
  try {
    const response = await fetch('/api/block-100', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip, reason })
    });
    const result = await response.json();
    showToast(`Range blocked: ${result.blocked}`, 'success');
  } catch (error) {
    showToast(`Error: ${error.message}`, 'error');
  }
}

async function blockASN(asn) {
  const reason = prompt('Block reason for ASN:', `ASN ${asn} malicious activity`);
  if (!reason) return;
  
  try {
    const response = await fetch('/api/block-asn', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ asn, reason })
    });
    const result = await response.json();
    showToast(`ASN ${asn} blocked: ${result.count} CIDR ranges`, 'success');
  } catch (error) {
    showToast(`Error: ${error.message}`, 'error');
  }
}

async function showBlockedList() {
  try {
    const response = await fetch('/api/blocked-list');
    const blocked = await response.json();
    
    const resultsDiv = document.getElementById('results');
    let html = `
      <div class="results-header">
        <h2>Blocked IP Addresses</h2>
        <button class="btn-export" onclick="showAWSFormat()">AWS WAF Format</button>
      </div>
    `;
    
    if (window.lastAnalysisResults) {
      html += `<button class="btn-secondary" onclick="restoreResults()" style="margin-bottom: 20px;">Back to Results</button>`;
    }
    
    if (blocked.length === 0) {
      html += '<p class="data-label" style="padding: 40px; text-align: center;">No blocked IPs found</p>';
    } else {
      html += '<div class="blocked-list-container">';
      blocked.forEach(item => {
        html += `
          <div class="blocked-item">
            <div>
              <div class="blocked-ip">${item.ip}</div>
              <div class="blocked-meta">Reason: ${item.reason} | ${new Date(item.timestamp).toLocaleString()}</div>
            </div>
          </div>
        `;
      });
      html += '</div>';
    }
    
    resultsDiv.innerHTML = html;
    resultsDiv.style.display = 'block';
  } catch (error) {
    showToast(`Error: ${error.message}`, 'error');
  }
}

function restoreResults() {
  if (window.lastAnalysisResults) {
    document.getElementById('results').innerHTML = window.lastAnalysisResults;
  }
}

async function showAWSFormat() {
  const resultsDiv = document.getElementById('results');
  resultsDiv.innerHTML = `
    <div class="results-header">
      <h2>AWS WAF Export</h2>
    </div>
    <div class="export-container">
      <textarea readonly id="awsExport"># AWS WAF IP Set Format
# Generated: ${new Date().toISOString()}
# Add IPs below in CIDR notation

192.168.1.100/32
10.0.0.50/32
172.16.0.25/32</textarea>
      <div class="export-actions">
        <button class="btn-primary" onclick="copyAWSList()">Copy to Clipboard</button>
        <button class="btn-secondary" onclick="showBlockedList()">Back</button>
      </div>
    </div>
  `;
}

function copyAWSList() {
  const textarea = document.getElementById('awsExport');
  textarea.select();
  document.execCommand('copy');
  showToast('Copied to clipboard', 'success');
}

async function generateBlocklist() {
  const input = document.getElementById('ipInput').value.trim();
  if (!input) {
    showToast('Please enter at least one IP address', 'error');
    return;
  }

  const ips = input.split(/[\n,]/).map(ip => ip.trim()).filter(ip => ip);

  if (ips.length === 0) {
    showToast('No valid IP addresses found', 'error');
    return;
  }

  try {
    const analyzed = await Promise.all(ips.map(async (ip) => {
      try {
        const response = await fetch('/api/analyze-ip', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ip })
        });
        const data = await response.json();
        return { ip, riskLevel: data.reputation?.riskLevel || 'low' };
      } catch {
        return { ip, riskLevel: 'low' };
      }
    }));
    
    const response = await fetch('/api/generate-blocklist', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ analyzed })
    });

    const result = await response.json();
    
    const resultsDiv = document.getElementById('results');
    resultsDiv.innerHTML = `
      <div class="results-header">
        <h2>AWS WAF Blocklist</h2>
      </div>
      <div class="reserved-notice">
        <h4>Blocklist Generated</h4>
        <p><strong>Total ranges:</strong> ${result.total}</p>
        <p><strong>Rule:</strong> LOW risk = /32 (single IP), MEDIUM/HIGH = /24 (subnet)</p>
      </div>
      <div class="export-container">
        <textarea readonly id="awsExport">${result.formatted}</textarea>
        <div class="export-actions">
          <button class="btn-primary" onclick="copyAWSList()">Copy to Clipboard</button>
          <button class="btn-secondary" onclick="location.reload()">New Analysis</button>
        </div>
      </div>
    `;
    resultsDiv.style.display = 'block';
  } catch (error) {
    showToast(`Error: ${error.message}`, 'error');
  }
}

function generatePDF() {
  const resultsContent = document.getElementById('results').innerHTML;
  const printWindow = window.open('', '_blank');
  
  printWindow.document.write(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>IP Threat Intelligence Report</title>
      <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Helvetica Neue', Arial, sans-serif; padding: 40px; color: #1e293b; line-height: 1.5; }
        .report-header { text-align: center; border-bottom: 2px solid #1e293b; padding-bottom: 24px; margin-bottom: 32px; }
        .report-header h1 { font-size: 24px; font-weight: 700; margin-bottom: 8px; }
        .report-header p { font-size: 12px; color: #64748b; }
        .ip-card { border: 1px solid #e2e8f0; border-radius: 8px; margin-bottom: 24px; page-break-inside: avoid; }
        .ip-card-header { padding: 16px 20px; border-bottom: 1px solid #e2e8f0; display: flex; justify-content: space-between; }
        .ip-card-header.risk-low { background: #f0fdf4; }
        .ip-card-header.risk-medium { background: #fffbeb; }
        .ip-card-header.risk-high, .ip-card-header.risk-blocked { background: #fef2f2; }
        .ip-card-header.risk-reserved { background: #f8fafc; }
        .ip-address { font-family: monospace; font-weight: 600; }
        .risk-badge { padding: 4px 10px; border-radius: 4px; font-size: 11px; font-weight: 600; text-transform: uppercase; }
        .risk-badge.low { background: #dcfce7; color: #166534; }
        .risk-badge.medium { background: #fef3c7; color: #92400e; }
        .risk-badge.high, .risk-badge.blocked { background: #fee2e2; color: #991b1b; }
        .risk-badge.reserved { background: #e2e8f0; color: #475569; }
        .ip-card-body { padding: 20px; }
        .data-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px; }
        .data-card { background: #f8fafc; padding: 16px; border-radius: 6px; }
        .data-card-title { font-size: 11px; font-weight: 600; color: #64748b; text-transform: uppercase; margin-bottom: 12px; border-bottom: 1px solid #e2e8f0; padding-bottom: 8px; }
        .data-row { display: flex; justify-content: space-between; padding: 6px 0; font-size: 12px; border-bottom: 1px solid #e2e8f0; }
        .data-row:last-child { border-bottom: none; }
        .data-label { color: #64748b; }
        .data-value { font-weight: 500; }
        .reserved-notice { background: #f1f5f9; padding: 16px; border-radius: 6px; margin-bottom: 16px; }
        .reserved-notice h4 { font-size: 13px; margin-bottom: 6px; }
        .reserved-notice p { font-size: 12px; color: #64748b; }
        .ip-card-actions, .btn-action, .btn-primary, .btn-secondary, .btn-export, .results-header button { display: none !important; }
        @media print { body { padding: 20px; } }
      </style>
    </head>
    <body>
      <div class="report-header">
        <h1>IP THREAT INTELLIGENCE REPORT</h1>
        <p>Generated: ${new Date().toLocaleString()} | Classification: CONFIDENTIAL</p>
      </div>
      ${resultsContent}
    </body>
    </html>
  `);
  
  printWindow.document.close();
  setTimeout(() => printWindow.print(), 500);
}
