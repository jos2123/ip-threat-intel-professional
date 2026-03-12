// Test endpoint para verificar que el código está actualizado
export async function onRequest(context) {
  return new Response(JSON.stringify({
    version: '8e77b91',
    timestamp: new Date().toISOString(),
    message: 'Si ves este commit hash, el código está actualizado'
  }), {
    headers: { 
      'Content-Type': 'application/json',
      'Cache-Control': 'no-cache'
    }
  });
}
