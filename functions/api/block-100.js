// Cloudflare Pages Function - Block /25 range
export async function onRequestPost(context) {
  const { request, env } = context;
  
  try {
    const { ip, reason } = await request.json();
    
    const parts = ip.split('.');
    const lastOctet = parseInt(parts[3]);
    const rangeStart = lastOctet < 128 ? 0 : 128;
    const subnet = `${parts[0]}.${parts[1]}.${parts[2]}.${rangeStart}`;
    const range = `${subnet}/25`;
    
    const blockedIP = {
      ip: range,
      reason: reason || 'Range bloqueado',
      timestamp: new Date().toISOString(),
      source: 'Manual block',
      type: 'range'
    };
    
    let savedToKV = false;
    if (env.BLOCKED_IPS) {
      const key = `blocked_${subnet.replace(/\./g, '_')}`;
      await env.BLOCKED_IPS.put(key, JSON.stringify(blockedIP));
      savedToKV = true;
    }

    return new Response(JSON.stringify({
      success: true,
      blocked: range,
      savedToKV
    }), {
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
    });
  } catch (error) {
    return new Response(JSON.stringify({ success: false, error: error.message }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
    });
  }
}
