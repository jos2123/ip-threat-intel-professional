// Cloudflare Pages Function - Blocked List with KV Storage
export async function onRequestGet(context) {
  const { env } = context;
  
  let blockedIPs = [];
  
  if (env.BLOCKED_IPS) {
    try {
      const kvList = await env.BLOCKED_IPS.list({ prefix: 'blocked_' });
      for (const key of kvList.keys) {
        const value = await env.BLOCKED_IPS.get(key.name);
        if (value) {
          blockedIPs.push(JSON.parse(value));
        }
      }
    } catch (error) {
      console.error('Error reading from KV:', error);
    }
  }

  // Ordenar por fecha más reciente
  blockedIPs.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

  return new Response(JSON.stringify(blockedIPs), {
    headers: { 
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*'
    }
  });
}
