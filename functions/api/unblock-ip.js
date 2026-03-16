// Cloudflare Pages Function - Delete blocked IP
export async function onRequestPost(context) {
  const { request, env } = context;
  
  try {
    const { ip } = await request.json();
    
    if (!env.BLOCKED_IPS) {
      return new Response(JSON.stringify({ success: false, error: 'KV not available' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
      });
    }
    
    // Crear la key basada en la IP (sin el /32 o /24)
    const cleanIP = ip.replace(/\/\d+$/, '');
    const key = `blocked_${cleanIP.replace(/\./g, '_')}`;
    
    await env.BLOCKED_IPS.delete(key);
    
    return new Response(JSON.stringify({ success: true, deleted: ip }), {
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
    });
  } catch (error) {
    return new Response(JSON.stringify({ success: false, error: error.message }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
    });
  }
}
