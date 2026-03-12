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
    const { analyzed } = await request.json();
    
    // Procesar IPs analizadas y aplicar máscaras
    const awsIPs = analyzed.map(item => {
      const ip = item.ip;
      const riskLevel = item.riskLevel?.toLowerCase() || 'low';
      
      // REGLA SIMPLE: MEDIUM o HIGH = /24, LOW = /32
      if (riskLevel === 'medium' || riskLevel === 'high') {
        const subnet = ip.split('.').slice(0, 3).join('.') + '.0';
        return `${subnet}/24`;
      } else {
        return `${ip}/32`;
      }
    });
    
    // Eliminar duplicados
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
        'Access-Control-Allow-Origin': '*',
        'Cache-Control': 'no-cache, no-store, must-revalidate'
      }
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: error.message, stack: error.stack }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}
