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
    
    // Guardar en KV (si está disponible)
    if (env.BLOCKED_IPS) {
      const key = `blocked_${ip.replace(/\./g, '_')}`;
      await env.BLOCKED_IPS.put(key, JSON.stringify(blockedIP));
    }
    
    const blockResult = {
      success: true,
      blocked: `${ip}/32`,
      type: 'individual',
      reason: reason || 'IP bloqueada manualmente',
      timestamp: new Date().toISOString(),
      message: `IP ${ip}/32 bloqueada y guardada exitosamente`,
      savedToKV: !!env.BLOCKED_IPS
    };

    return new Response(JSON.stringify(blockResult), {
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
