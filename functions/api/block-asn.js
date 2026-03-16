// Cloudflare Pages Function - Block ASN
export async function onRequestPost(context) {
  const { request, env } = context;
  
  try {
    const { asn, reason } = await request.json();
    
    const blockedASN = {
      ip: asn,
      reason: reason || `ASN ${asn} bloqueado`,
      timestamp: new Date().toISOString(),
      source: 'Manual block',
      type: 'asn'
    };
    
    let savedToKV = false;
    if (env.BLOCKED_IPS) {
      const key = `blocked_${asn.replace(/[^a-zA-Z0-9]/g, '_')}`;
      await env.BLOCKED_IPS.put(key, JSON.stringify(blockedASN));
      savedToKV = true;
    }

    return new Response(JSON.stringify({
      success: true,
      blocked: asn,
      count: 1,
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
