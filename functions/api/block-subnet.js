// Cloudflare Pages Function - Block Subnet
export async function onRequestPost(context) {
  const { request } = context;
  
  try {
    const { ip, cidr, reason } = await request.json();
    
    // Calcular subnet basada en la IP y CIDR
    const ipParts = ip.split('.');
    let subnet;
    
    if (cidr === 24) {
      subnet = `${ipParts[0]}.${ipParts[1]}.${ipParts[2]}.0/24`;
    } else if (cidr === 25) {
      subnet = `${ipParts[0]}.${ipParts[1]}.${ipParts[2]}.0/25`;
    } else {
      subnet = `${ip}/32`;
    }
    
    const blockResult = {
      success: true,
      blocked: subnet,
      type: `subnet-${cidr}`,
      reason: reason,
      timestamp: new Date().toISOString(),
      message: `Subnet ${subnet} bloqueada exitosamente`
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
