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
  const { request } = context;
  
  try {
    const { ips } = await request.json();
    
    // Generar formato AWS WAF basado en las IPs enviadas
    const awsIPs = ips.map(ip => `${ip}/32`);
    const formatted = awsIPs.join('\n');
    
    const result = {
      individual: awsIPs,
      subnets: [],
      total: awsIPs.length,
      formatted: formatted
    };

    return new Response(JSON.stringify(result), {
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
