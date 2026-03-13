// Test Cloudflare Radar API
export async function onRequestGet(context) {
  const { env } = context;
  
  const asn = '47890';
  
  if (!env.CLOUDFLARE_API_TOKEN) {
    return new Response(JSON.stringify({ 
      error: 'CLOUDFLARE_API_TOKEN not configured',
      hasToken: false
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
  }
  
  try {
    const response = await fetch(`https://api.cloudflare.com/client/v4/radar/http/summary/bot_class?asn=${asn}&dateRange=7d`, {
      headers: {
        'Authorization': `Bearer ${env.CLOUDFLARE_API_TOKEN}`,
        'Content-Type': 'application/json'
      }
    });
    
    const data = await response.json();
    
    return new Response(JSON.stringify({
      hasToken: true,
      asn: asn,
      status: response.status,
      data: data
    }, null, 2), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    return new Response(JSON.stringify({
      error: error.message,
      hasToken: true
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}
