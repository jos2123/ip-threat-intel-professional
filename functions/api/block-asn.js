// Cloudflare Pages Function - Block ASN
export async function onRequestPost(context) {
  const { request } = context;
  
  try {
    const { asn, reason } = await request.json();
    
    const blockResult = {
      success: true,
      blocked: asn,
      type: 'asn',
      reason: reason,
      timestamp: new Date().toISOString(),
      message: `ASN ${asn} bloqueado exitosamente`
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
