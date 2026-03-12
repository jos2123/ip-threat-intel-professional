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
    const { ips } = await request.json();
    
    // Analizar cada IP para determinar su nivel de riesgo
    const awsIPs = await Promise.all(ips.map(async (ip) => {
      try {
        // Consultar AbuseIPDB para obtener el score
        const abuseResponse = await fetch(
          `https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}`,
          {
            headers: {
              'Key': env.ABUSEIPDB_KEY,
              'Accept': 'application/json'
            }
          }
        );
        
        const abuseData = await abuseResponse.json();
        const score = abuseData.data?.abuseConfidenceScore || 0;
        
        // Aplicar regla: LOW = /32, MEDIUM/HIGH = /24
        if (score > 25) {
          // MEDIUM o HIGH: usar subnet /24
          const subnet = ip.split('.').slice(0, 3).join('.') + '.0';
          return `${subnet}/24`;
        } else {
          // LOW: usar IP individual /32
          return `${ip}/32`;
        }
      } catch (error) {
        // Si falla la consulta, usar /32 por defecto
        return `${ip}/32`;
      }
    }));
    
    // Eliminar duplicados
    const uniqueIPs = [...new Set(awsIPs)];
    const formatted = uniqueIPs.join('\n');
    
    const result = {
      individual: uniqueIPs.filter(ip => ip.endsWith('/32')),
      subnets: uniqueIPs.filter(ip => ip.endsWith('/24')),
      total: uniqueIPs.length,
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
