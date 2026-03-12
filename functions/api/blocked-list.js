// Cloudflare Pages Function - Blocked List with KV Storage
export async function onRequestGet(context) {
  const { env } = context;
  
  // Lista base de IPs bloqueadas automáticamente
  const baseBlockedIPs = [
    {
      ip: "185.177.72.60/32",
      reason: "High risk (100% AbuseIPDB score)",
      timestamp: "2026-03-11T19:00:00Z",
      reports: 2418,
      source: "Automatic detection"
    },
    {
      ip: "185.177.72.56/32", 
      reason: "High risk (100% AbuseIPDB score)",
      timestamp: "2026-03-11T19:00:00Z",
      reports: 1500,
      source: "Automatic detection"
    },
    {
      ip: "185.177.72.49/32",
      reason: "High risk (100% AbuseIPDB score)", 
      timestamp: "2026-03-11T19:00:00Z",
      reports: 1200,
      source: "Automatic detection"
    },
    {
      ip: "185.177.72.0/24",
      reason: "Subnet block - medium/high risk",
      timestamp: "2026-03-11T19:00:00Z", 
      reports: 5000,
      source: "Automatic detection"
    }
  ];

  // Obtener IPs bloqueadas manualmente desde KV
  let manualBlocks = [];
  if (env.BLOCKED_IPS) {
    try {
      const kvList = await env.BLOCKED_IPS.list({ prefix: 'blocked_' });
      for (const key of kvList.keys) {
        const value = await env.BLOCKED_IPS.get(key.name);
        if (value) {
          manualBlocks.push(JSON.parse(value));
        }
      }
    } catch (error) {
      console.error('Error reading from KV:', error);
    }
  }

  const allBlocked = [...baseBlockedIPs, ...manualBlocks];

  return new Response(JSON.stringify(allBlocked), {
    headers: { 
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*'
    }
  });
}
