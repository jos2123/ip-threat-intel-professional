// Cloudflare Pages Function - Block IP with KV Storage
export async function onRequestPost(context) {
  const { request, env } = context;
  
  try {
    const { ip, reason } = await request.json();
    
    // Crear objeto de IP bloqueada
    const blockedIP = {
      ip: `${ip}/32`,
      reason: reason || 'IP bloqueada manualmente',
      timestamp: new Date().toISOString(),
      source: 'Manual block',
      type: 'individual'
    };
    
    // Verificar si KV está disponible
    const kvAvailable = !!env.BLOCKED_IPS;
    let savedToKV = false;
    
    if (kvAvailable) {
      try {
        const key = `blocked_${ip.replace(/\./g, '_')}`;
        await env.BLOCKED_IPS.put(key, JSON.stringify(blockedIP));
        savedToKV = true;
      } catch (kvError) {
        console.error('KV write error:', kvError);
      }
    }

    return new Response(JSON.stringify({
      success: true,
      blocked: `${ip}/32`,
      reason: reason,
      timestamp: blockedIP.timestamp,
      kvAvailable,
      savedToKV
    }), {
      headers: { 
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      }
    });
  } catch (error) {
    return new Response(JSON.stringify({ 
      success: false, 
      error: error.message 
    }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}
