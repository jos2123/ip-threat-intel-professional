async function analyzeIPs() {
  const input = document.getElementById('ipInput').value.trim();
  const loading = document.getElementById('loading');
  const error = document.getElementById('error');
  const results = document.getElementById('results');
  const btn = document.getElementById('analyzeBtn');

  if (!input) {
    showError('⚠️ Por favor ingrese al menos una dirección IP para continuar');
    return;
  }

  // Separar IPs por líneas o comas y limpiar
  const ips = input.split(/[\n,]/)
    .map(ip => ip.trim())
    .filter(ip => ip && ip.length > 0);

  if (ips.length === 0) {
    showError('No se encontraron IPs válidas');
    return;
  }

  loading.style.display = 'block';
  error.style.display = 'none';
  results.style.display = 'none';
  btn.disabled = true;

  try {
    // Analizar todas las IPs en paralelo
    const promises = ips.map(ip => analyzeIP(ip));
    const allResults = await Promise.allSettled(promises);

    displayMultipleResults(allResults, ips);
  } catch (err) {
    showError(err.message);
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

function displayMultipleResults(results, ips) {
  const resultsDiv = document.getElementById('results');
  let html = `<h2>Analysis Results (${ips.length} IPs)</h2>
    <div style="text-align: center; margin-bottom: 20px;">
      <button onclick="generatePDF()" style="background: #28a745; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer;">Generate Report</button>
    </div>`;

  results.forEach((result, index) => {
    const ip = ips[index];
    
    if (result.status === 'fulfilled') {
      const data = result.value;
      
      // Verificar si es IP reservada
      if (data.reserved) {
        html += `
          <div class="ip-result reserved">
            <div class="risk-indicator risk-reserved">
              RESERVED ${data.ip} - ${data.reservedType.toUpperCase()}
            </div>
            
            <div class="reserved-info">
              <h3>Important Information</h3>
              <p><strong>Message:</strong> ${data.message}</p>
              <p><strong>Note:</strong> ${data.note}</p>
            </div>
            
            <div class="grid">
              <div class="card">
                <h3>Basic Information</h3>
                ${createInfoRows({
                  'Type': data.reservedType.replace('_', ' ').toUpperCase(),
                  'Organization': data.basic?.organization || 'N/A',
                  'Status': 'Reserved/Private IP'
                })}
              </div>
            </div>
          </div>
        `;
      } else if (data.blocked) {
        html += `
          <div class="ip-result blocked">
            <div class="risk-indicator risk-high">
              BLOCKED ${data.ip}
            </div>
            <p><strong>Reason:</strong> ${data.blockInfo.reason}</p>
            <p><strong>Range:</strong> ${data.blockInfo.range}</p>
            
            <div class="grid">
              <div class="card">
                <h3>Basic Information</h3>
                ${createInfoRows({
                  'ASN': data.basic?.asn || 'N/A',
                  'Organización': data.basic?.organization || 'N/A',
                  'País': data.basic?.country || 'N/A',
                  'Ciudad': data.basic?.city || 'N/A'
                })}
              </div>

              ${data.asnMetrics && data.asnMetrics.available ? `
              <div class="card">
                <h3>ASN Metrics ${data.basic?.asn}</h3>
                ${data.asnMetrics.botVsHuman ? `
                  <div class="metric-row">
                    <span class="label">Bot Traffic:</span>
                    <span class="value">${data.asnMetrics.botVsHuman.bot}%</span>
                  </div>
                  <div class="metric-row">
                    <span class="label">Human Traffic:</span>
                    <span class="value">${data.asnMetrics.botVsHuman.human}%</span>
                  </div>
                ` : ''}
                <small>Source: ${data.asnMetrics.source}</small>
              </div>
              ` : ''}

              <div class="card">
                <h3>AbuseIPDB Report</h3>
                ${data.reputation?.abuseipdb ? createInfoRows({
                  'Score': `${data.reputation.abuseipdb.score}%`,
                  'Reports': data.reputation.abuseipdb.reports,
                  'Whitelisted': data.reputation.abuseipdb.isWhitelisted ? 'Yes' : 'No'
                }) : '<p>Not available</p>'}
              </div>

              <div class="card">
                <h3>Shodan Intelligence</h3>
                ${data.intelligence?.shodan ? createInfoRows({
                  'Ports': data.intelligence.shodan?.ports?.join(', ') || 'N/A',
                  'Services': data.intelligence.shodan?.services?.map(s => `${s.port}:${s.product}`).join(', ') || 'N/A'
                }) : createInfoRows({
                  'Puertos': 'N/A',
                  'Servicios': 'N/A'
                })}
              </div>
            </div>
          </div>
        `;
      } else {
        const riskClass = `risk-${data.reputation.riskLevel}`;
        
        html += `
          <div class="ip-result">
            <div class="risk-indicator ${riskClass}">
              ${getRiskEmoji(data.reputation.riskLevel)} ${data.ip} - Risk Level: ${data.reputation.riskLevel.toUpperCase()} (${data.reputation.riskScore}/100)
            </div>`;

        // Mostrar si fue auto-bloqueada
        if (data.autoBlocked) {
          html += `
            <div class="auto-blocked">
              ${data.autoBlocked.type === 'single' ? 'IP blocked' : 'Subnet blocked'}: ${data.autoBlocked.blocked}
            </div>`;
        }

        html += `
            <div class="grid">
              <div class="card">
                <h3>Basic Information</h3>
                ${createInfoRows({
                  'ASN': data.basic?.asn || 'N/A',
                  'Organización': data.basic?.organization || 'N/A',
                  'País': data.basic?.country || 'N/A',
                  'Ciudad': data.basic?.city || 'N/A'
                })}
              </div>

              ${data.asnMetrics && data.asnMetrics.available ? `
              <div class="card">
                <h3>ASN Metrics ${data.basic?.asn}</h3>
                ${data.asnMetrics.botVsHuman ? `
                  <div class="metric-row">
                    <span class="label">Bot Traffic:</span>
                    <span class="value">${data.asnMetrics.botVsHuman.bot}%</span>
                  </div>
                  <div class="metric-row">
                    <span class="label">Human Traffic:</span>
                    <span class="value">${data.asnMetrics.botVsHuman.human}%</span>
                  </div>
                ` : ''}
                ${data.asnMetrics.prefixes ? `
                  <div class="metric-row">
                    <span class="label">IPv4 Prefixes:</span>
                    <span class="value">${data.asnMetrics.prefixes.ipv4}</span>
                  </div>
                  <div class="metric-row">
                    <span class="label">IPv6 Prefixes:</span>
                    <span class="value">${data.asnMetrics.prefixes.ipv6}</span>
                  </div>
                ` : ''}
                <small>Source: ${data.asnMetrics.source}</small>
                ${data.asnMetrics.note ? `<br><small>${data.asnMetrics.note}</small>` : ''}
              </div>
              ` : (data.asnMetrics ? `
              <div class="card">
                <h3>ASN Metrics ${data.basic?.asn}</h3>
                <p>Métricas no disponibles</p>
                ${data.asnMetrics.error ? `<small>Error: ${data.asnMetrics.error}</small>` : ''}
              </div>
              ` : '')}

              <div class="card">
                <h3>AbuseIPDB Report</h3>
                ${data.reputation.abuseipdb ? createInfoRows({
                  'Score': `${data.reputation.abuseipdb.score}%`,
                  'Reportes': data.reputation.abuseipdb.reports,
                  'Whitelisted': data.reputation.abuseipdb.isWhitelisted ? '✅' : '❌'
                }) : '<p>Not available</p>'}
              </div>

              <div class="card">
                <h3>VirusTotal Analysis</h3>
                ${data.reputation.virustotal ? `
                  <div class="info-row">
                    <span class="label">Maliciosos:</span>
                    <span class="badge badge-danger">${data.reputation.virustotal.malicious}</span>
                  </div>
                  <div class="info-row">
                    <span class="label">Inofensivos:</span>
                    <span class="badge badge-success">${data.reputation.virustotal.harmless}</span>
                  </div>
                ` : '<p>Not available</p>'}
              </div>

              <div class="card">
                <h3>Threat Intelligence</h3>
                ${data.intelligence.greynoise ? createInfoRows({
                  'GreyNoise': data.intelligence.greynoise.classification || 'N/A',
                  'Shodan Puertos': data.intelligence.shodan?.ports?.join(', ') || 'N/A'
                }) : createInfoRows({
                  'Shodan Puertos': data.intelligence.shodan?.ports?.join(', ') || 'N/A'
                })}
              </div>
            </div>

            <div class="blocking-buttons">
              <button onclick="blockIP('${data.ip}')">Block IP (/32)</button>
              <button onclick="blockRange100('${data.ip}')">Block ~100 IPs (/25)</button>
              <button onclick="blockSubnet('${data.ip}')">Block 256 IPs (/24)</button>
              ${data.basic?.asn ? `<button onclick="blockASN('${data.basic.asn}')">Block ${data.basic.asn}</button>` : ''}
            </div>
          </div>
        `;
      }
    } else {
      html += `
        <div class="ip-result">
          <div class="risk-indicator risk-high">
            ❌ ${ip} - Error: ${result.reason.message}
          </div>
        </div>
      `;
    }
    html += `<hr style="margin: 30px 0; border: 1px solid #eee;">`;
  });

  resultsDiv.innerHTML = html;
  resultsDiv.style.display = 'block';
  
  // Guardar resultados para poder volver después
  window.lastAnalysisResults = html;
}

function displayResults(data) {
  const results = document.getElementById('results');
  
  // Determinar el nivel de riesgo y título apropiado
  let riskLevel = data.reputation.riskLevel;
  let riskScore = data.reputation.riskScore;
  let titlePrefix = '';
  
  if (data.error && data.error.includes('Partial analysis')) {
    // Si es análisis parcial, mostrar como LOW risk por defecto
    riskLevel = 'low';
    riskScore = 10;
    titlePrefix = 'ANALYZED';
  } else if (data.error) {
    // Si hay error completo, mantener unknown
    titlePrefix = 'UNKNOWN';
  } else {
    // Análisis completo
    titlePrefix = riskLevel.toUpperCase();
  }
  
  const riskClass = `risk-${riskLevel}`;
  
  results.innerHTML = `
    <div class="risk-indicator ${riskClass}">
      ${titlePrefix} ${data.ip} - Risk Level: ${riskLevel.toUpperCase()} (${riskScore}/100)
    </div>

    <div class="grid">
      <div class="card">
        <h3>Basic Information</h3>
        ${createInfoRows({
          'ASN': data.basic?.asn || 'N/A',
          'Organización': data.basic?.organization || 'N/A',
          'País': data.basic?.country || 'N/A',
          'Ciudad': data.basic?.city || 'N/A'
        })}
      </div>

      <div class="card">
        <h3>AbuseIPDB Report</h3>
        ${data.reputation.abuseipdb ? createInfoRows({
          'Score': `${data.reputation.abuseipdb.score}%`,
          'Reportes': data.reputation.abuseipdb.reports,
          'Tipo': data.reputation.abuseipdb.categories || 'N/A',
          'Whitelisted': data.reputation.abuseipdb.isWhitelisted ? '✅' : '❌'
        }) : '<p>Not available</p>'}
      </div>

      <div class="card">
        <h3>VirusTotal Analysis</h3>
        ${data.reputation.virustotal ? `
          <div class="info-row">
            <span class="label">Maliciosos:</span>
            <span class="badge badge-danger">${data.reputation.virustotal.malicious}</span>
          </div>
          <div class="info-row">
            <span class="label">Sospechosos:</span>
            <span class="badge badge-warning">${data.reputation.virustotal.suspicious}</span>
          </div>
          <div class="info-row">
            <span class="label">Inofensivos:</span>
            <span class="badge badge-success">${data.reputation.virustotal.harmless}</span>
          </div>
          <div class="info-row">
            <span class="label">Reputación:</span>
            <span class="value">${data.reputation.virustotal.reputation}</span>
          </div>
        ` : '<p>Not available</p>'}
      </div>

      <div class="card">
        <h3>🔍 GreyNoise</h3>
        ${data.intelligence.greynoise ? createInfoRows({
          'Clasificación': data.intelligence.greynoise.classification || 'N/A',
          'Noise': data.intelligence.greynoise.noise ? '✅' : '❌',
          'RIOT': data.intelligence.greynoise.riot ? '✅' : '❌',
          'Nombre': data.intelligence.greynoise.name || 'N/A'
        }) : '<p>Not available</p>'}
      </div>

      <div class="card">
        <h3>🌐 Shodan</h3>
        ${data.intelligence.shodan ? `
          <div class="info-row">
            <span class="label">Puertos abiertos:</span>
            <span class="value">${data.intelligence.shodan.ports?.join(', ') || 'N/A'}</span>
          </div>
          <div class="info-row">
            <span class="label">Servicios:</span>
            <span class="value">${data.intelligence.shodan.services?.length || 0}</span>
          </div>
          <div class="info-row">
            <span class="label">Hostnames:</span>
            <span class="value">${data.intelligence.shodan.hostnames?.join(', ') || 'N/A'}</span>
          </div>
        ` : '<p>Not available</p>'}
      </div>

      <div class="card">
        <h3>🔗 AlienVault OTX</h3>
        ${data.reputation.otx ? createInfoRows({
          'Pulses': data.reputation.otx.pulseCount,
          'Reputación': data.reputation.otx.reputation
        }) : '<p>Not available</p>'}
      </div>
    </div>
  `;

  results.style.display = 'block';
}

function createInfoRows(data) {
  return Object.entries(data).map(([key, value]) => `
    <div class="info-row">
      <span class="label">${key}:</span>
      <span class="value">${value}</span>
    </div>
  `).join('');
}

function getRiskEmoji(level) {
  return { 
    low: 'LOW RISK', 
    medium: 'MEDIUM RISK', 
    high: 'HIGH RISK',
    reserved: 'RESERVED',
    unknown: 'UNKNOWN'
  }[level];
}

function showError(message) {
  showAlert(message, 'error');
}

function showAlert(message, type = 'info') {
  // Remover alertas existentes
  const existingAlerts = document.querySelectorAll('.input-alert');
  existingAlerts.forEach(alert => alert.remove());

  const inputGroup = document.querySelector('.input-group');
  const alert = document.createElement('div');
  alert.className = `input-alert alert-${type}`;
  alert.textContent = message;
  
  inputGroup.appendChild(alert);
  
  // Auto-remover después de 4 segundos
  setTimeout(() => {
    if (alert.parentNode) {
      alert.remove();
    }
  }, 4000);
  
  // Remover al hacer click en el input
  const input = document.getElementById('ipInput');
  const removeAlert = () => {
    if (alert.parentNode) {
      alert.remove();
    }
    input.removeEventListener('click', removeAlert);
    input.removeEventListener('focus', removeAlert);
  };
  
  input.addEventListener('click', removeAlert);
  input.addEventListener('focus', removeAlert);
}

document.getElementById('ipInput').addEventListener('keypress', (e) => {
  if (e.key === 'Enter' && e.ctrlKey) analyzeIPs();
});

// Funciones de bloqueo
async function blockIP(ip) {
  const reason = prompt('Razón del bloqueo:', 'IP maliciosa detectada manualmente');
  if (!reason) return;
  
  try {
    const response = await fetch('/api/block-ip', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip, reason })
    });
    
    const result = await response.json();
    if (result.success) {
      alert(`✅ ${result.message}\n\n💡 Nota: En producción, esta IP se agregaría a la base de datos de IPs bloqueadas y aparecería en "View Blocked List".`);
    } else {
      alert(`❌ Error: ${result.error}`);
    }
  } catch (error) {
    alert(`❌ Error: ${error.message}`);
  }
}

async function blockSubnet(ip) {
  const reason = prompt('Razón del bloqueo de 256 IPs (/24):', 'Subnet maliciosa detectada');
  if (!reason) return;
  
  try {
    const response = await fetch('/api/block-subnet', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip, cidr: 24, reason })
    });
    
    const result = await response.json();
    alert(`✅ Subnet bloqueada: ${result.blocked} (256 IPs)`);
  } catch (error) {
    alert(`❌ Error: ${error.message}`);
  }
}

async function blockRange100(ip) {
  const reason = prompt('Razón del bloqueo de ~100 IPs (/25):', 'Rango malicioso detectado');
  if (!reason) return;
  
  try {
    const response = await fetch('/api/block-100', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip, reason })
    });
    
    const result = await response.json();
    alert(`✅ Rango bloqueado: ${result.blocked} (~128 IPs)`);
  } catch (error) {
    alert(`❌ Error: ${error.message}`);
  }
}

async function blockASN(asn) {
  const reason = prompt('Razón del bloqueo de ASN:', `ASN ${asn} malicioso detectado`);
  if (!reason) return;
  
  try {
    const response = await fetch('/api/block-asn', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ asn, reason })
    });
    
    const result = await response.json();
    alert(`✅ ASN ${asn} bloqueado: ${result.count} rangos CIDR bloqueados`);
  } catch (error) {
    alert(`❌ Error: ${error.message}`);
  }
}

async function showBlockedList() {
  try {
    const response = await fetch('/api/blocked-list');
    const blocked = await response.json();
    
    let html = '<h2>🚫 Lista de IPs/Rangos Bloqueados</h2>';
    
    // Botón para volver a resultados anteriores
    if (window.lastAnalysisResults) {
      html += `
        <div class="blocked-controls">
          <button onclick="showLastResults()" style="background: #17a2b8; margin-right: 10px;">🔙 Volver a Resultados</button>
          <button onclick="showAWSFormat()" style="background: #f39c12;">📋 Formato AWS WAF</button>
        </div>
      `;
    } else {
      html += `
        <div class="blocked-controls">
          <button onclick="showAWSFormat()" style="background: #f39c12; margin-bottom: 20px;">📋 Formato AWS WAF</button>
        </div>
      `;
    }
    
    if (blocked.length === 0) {
      html += '<p>No hay IPs bloqueadas</p>';
    } else {
      html += '<div class="blocked-list">';
      
      blocked.forEach(item => {
        html += `
          <div class="blocked-item">
            <strong>${item.ip}</strong><br>
            <small>Razón: ${item.reason}</small><br>
            <small>Fecha: ${new Date(item.timestamp).toLocaleString()}</small>
            ${item.reports ? `<br><small>Reportes: ${item.reports}</small>` : ''}
            <br><small>📍 Reportado en: AbuseIPDB, VirusTotal</small>
          </div>
        `;
      });
      html += '</div>';
    }
    
    document.getElementById('results').innerHTML = html;
    document.getElementById('results').style.display = 'block';
  } catch (error) {
    alert(`❌ Error: ${error.message}`);
  }
}

// Función para volver a los últimos resultados
function showLastResults() {
  if (window.lastAnalysisResults) {
    document.getElementById('results').innerHTML = window.lastAnalysisResults;
    document.getElementById('results').style.display = 'block';
  }
}

async function showAWSFormat() {
  try {
    const response = await fetch('/api/blocked-aws');
    const awsText = await response.text();
    
    let html = `
      <h2>📋 Formato AWS WAF</h2>
      <p>Copia y pega estas IPs/rangos en AWS WAF:</p>
      <div class="aws-format">
        <textarea readonly style="width: 100%; height: 300px; font-family: monospace;">${awsText}</textarea>
        <button onclick="copyToClipboard('${awsText.replace(/'/g, "\\'")}')">📋 Copiar</button>
      </div>
      <button onclick="showBlockedList()" style="margin-top: 15px;">← Volver a Lista</button>
    `;
    
    document.getElementById('results').innerHTML = html;
  } catch (error) {
    alert(`❌ Error: ${error.message}`);
  }
}

function copyToClipboard(text) {
  navigator.clipboard.writeText(text).then(() => {
    alert('✅ Copiado al portapapeles');
  }).catch(() => {
    alert('❌ Error al copiar');
  });
}

async function generateBlocklist() {
  const input = document.getElementById('ipInput').value.trim();
  if (!input) {
    alert('❌ Ingresa las IPs primero');
    return;
  }

  const ips = input.split(/[\n,]/)
    .map(ip => ip.trim())
    .filter(ip => ip && ip.length > 0);

  if (ips.length === 0) {
    alert('❌ No se encontraron IPs válidas');
    return;
  }

  try {
    const response = await fetch('/api/generate-blocklist', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ips })
    });

    const result = await response.json();
    
    let html = `
      <h2>📋 Lista de Bloqueo AWS WAF</h2>
      <p><strong>Total de rangos:</strong> ${result.total}</p>
      <p><strong>Regla:</strong> LOW risk = /32 (solo IP), MEDIUM/HIGH = /24 (subnet)</p>
      <div class="aws-format">
        <textarea readonly style="width: 100%; height: 300px; font-family: monospace;">${result.formatted}</textarea>
        <button onclick="copyToClipboard('${result.formatted.replace(/'/g, "\\'")}')">📋 Copiar Lista</button>
      </div>
      <button onclick="location.reload()" style="margin-top: 15px;">← Volver</button>
    `;
    
    document.getElementById('results').innerHTML = html;
    document.getElementById('results').style.display = 'block';
  } catch (error) {
    alert(`❌ Error: ${error.message}`);
  }
}

function generatePDF() {
  const resultsContent = document.getElementById('results').innerHTML;
  
  // Crear ventana nueva para el PDF
  const printWindow = window.open('', '_blank');
  printWindow.document.write(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>IP Threat Intelligence Report - ${new Date().toLocaleDateString()}</title>
      <style>
        body { 
          font-family: 'Times New Roman', serif; 
          margin: 40px; 
          color: #000;
          background: #fff;
          line-height: 1.4;
        }
        .header {
          text-align: center;
          border-bottom: 2px solid #000;
          padding-bottom: 20px;
          margin-bottom: 30px;
        }
        .header h1 {
          font-size: 24px;
          margin: 0;
          font-weight: bold;
        }
        .header p {
          margin: 5px 0;
          font-size: 14px;
        }
        .grid { 
          display: table;
          width: 100%;
          margin: 20px 0;
        }
        .card { 
          display: table-cell;
          vertical-align: top;
          padding: 15px;
          border: 1px solid #000;
          margin: 5px;
          width: 25%;
        }
        .card h3 { 
          margin: 0 0 10px 0; 
          font-size: 14px;
          font-weight: bold;
          border-bottom: 1px solid #000;
          padding-bottom: 5px;
        }
        .info-row, .metric-row { 
          display: flex; 
          justify-content: space-between; 
          padding: 3px 0; 
          border-bottom: 1px solid #ccc;
          font-size: 12px;
        }
        .info-row:last-child, .metric-row:last-child {
          border-bottom: none;
        }
        .label { font-weight: bold; }
        .value { text-align: right; }
        .risk-indicator { 
          padding: 15px; 
          margin: 15px 0; 
          border: 2px solid #000;
          text-align: center; 
          font-weight: bold;
          font-size: 16px;
        }
        .risk-low { background: #f0f0f0; }
        .risk-medium { background: #e0e0e0; }
        .risk-high { background: #d0d0d0; }
        .risk-reserved { background: #f5f5f5; }
        .blocked { background: #e8e8e8; border: 2px solid #000; }
        .ip-result { 
          margin: 25px 0; 
          padding: 20px; 
          border: 1px solid #000;
          page-break-inside: avoid;
        }
        .blocking-buttons, button, .auto-blocked { display: none !important; }
        .reserved-info {
          background: #f5f5f5;
          padding: 15px;
          border: 1px solid #000;
          margin: 10px 0;
        }
        .reserved-info h3 {
          margin: 0 0 10px 0;
          font-size: 14px;
        }
        .reserved-info p {
          margin: 5px 0;
          font-size: 12px;
        }
        @media print { 
          .no-print, button { display: none !important; }
          body { margin: 20px; }
        }
      </style>
    </head>
    <body>
      <div class="header">
        <h1>IP THREAT INTELLIGENCE REPORT</h1>
        <p><strong>Generated:</strong> ${new Date().toLocaleDateString()}</p>
        <p><strong>System:</strong> IP Threat Intelligence Platform</p>
        <p><strong>Classification:</strong> CONFIDENTIAL</p>
      </div>
      ${resultsContent}
    </body>
    </html>
  `);
  
  printWindow.document.close();
  
  // Esperar a que cargue y luego imprimir
  setTimeout(() => {
    printWindow.print();
  }, 500);
}
