// Cloudflare Pages Function - Generate AWS Blocklist
export async function onRequestGet(context) {
  const blockedIPs = [
    "185.177.72.60/32",
    "185.177.72.56/32", 
    "185.177.72.49/32",
    "185.177.72.0/24"
  ];

  const formatted = blockedIPs.join('\n');

  const awsBlocklist = {
    individual: blockedIPs.filter(ip => ip.endsWith('/32')),
    subnets: blockedIPs.filter(ip => ip.endsWith('/24')),
    total: blockedIPs.length,
    formatted: formatted
  };

  return new Response(JSON.stringify(awsBlocklist), {
    headers: { 
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*'
    }
  });
}

export async function onRequestPost(context) {
  const { request, env } = context;
  
  try {
    const { ips, analyzed } = await request.json();
    
    // Si ya vienen analizadas con su riskLevel, usar eso
    if (analyzed && Array.isArray(analyzed)) {
      const awsIPs = analyzed.map(item => {
        const ip = item.ip;
        const riskLevel = item.riskLevel?.toLowerCase() || 'low';
        
        // Aplicar regla: LOW = /32, MEDIUM/HIGH = /24
        if (riskLevel === 'medium' || riskLevel === 'high') {
          const subnet = ip.split('.').slice(0, 3).join('.') + '.0';
          return `${subnet}/24`;
        } else {
          return `${ip}/32`;
        }
      });
      
      const uniqueIPs = [...new Set(awsIPs)];
      const formatted = uniqueIPs.join('\n');
      
      return new Response(JSON.stringify({
        individual: uniqueIPs.filter(ip => ip.endsWith('/32')),
        subnets: uniqueIPs.filter(ip => ip.endsWith('/24')),
        total: uniqueIPs.length,
        formatted: formatted
      }), {
        headers: { 
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        }
      });
    }
    
    // Fallback: consultar AbuseIPDB
    const ABUSEIPDB_KEY = env.ABUSEIPDB_KEY || 'ad5115480bcc83e7ba5899a52dda62cdbf354f803add5137fd9539e73d9c1f214bed758f5d9e5391';
    
    const awsIPs = await Promise.all(ips.map(async (ip) => {
      try {
        const abuseResponse = await fetch(
          `https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}`,
          {
            headers: {
              'Key': ABUSEIPDB_KEY,
              'Accept': 'application/json'
            }
          }
        );
        
        const abuseData = await abuseResponse.json();
        const score = abuseData.data?.abuseConfidenceScore || 0;
        
        if (score > 25) {
          const subnet = ip.split('.').slice(0, 3).join('.') + '.0';
          return `${subnet}/24`;
        } else {
          return `${ip}/32`;
        }
      } catch (error) {
        return `${ip}/32`;
      }
    }));
    
    const uniqueIPs = [...new Set(awsIPs)];
    const formatted = uniqueIPs.join('\n');
    
    return new Response(JSON.stringify({
      individual: uniqueIPs.filter(ip => ip.endsWith('/32')),
      subnets: uniqueIPs.filter(ip => ip.endsWith('/24')),
      total: uniqueIPs.length,
      formatted: formatted
    }), {
      headers: { 
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      }
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}
