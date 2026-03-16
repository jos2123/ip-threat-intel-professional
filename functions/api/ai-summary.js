export async function onRequestPost(context) {
  const { request, env } = context;
  
  try {
    const { threatData } = await request.json();
    
    if (!threatData) {
      return new Response(JSON.stringify({ error: 'threatData required' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const prompt = `Eres un analista de ciberseguridad senior trabajando para LINKTIC S.A.S en Colombia. Analiza los siguientes datos de inteligencia de amenazas IP. Responde siempre en español.

CONTEXTO DE LA EMPRESA:
- Trabajas para LINKTIC S.A.S, empresa de telecomunicaciones en Colombia
- IPs de LINKTIC, Tigo, Colombia Móvil, tigo.com.co son de nuestra infraestructura o clientes
- El ISP "LINKTIC S.A.S" o dominio "tigo.com.co" indica que es tráfico interno o de clientes legítimos

REGLAS DE ANÁLISIS:
- NO menciones puntajes numéricos ni porcentajes
- Si el ISP es LINKTIC o el dominio es tigo.com.co, indica que es tráfico de nuestra red/clientes
- Analiza: reportes de abuso, ISP, tipo de uso, dominio, detecciones VirusTotal, puertos Shodan, tráfico bot/humano
- Si el Usage Type es "Mobile ISP" y es de Colombia, probablemente es un cliente móvil legítimo
- NUNCA recomiendes bloquear sin investigar primero el origen
- Considera falsos positivos comunes en Colombia
- Sé conciso (3-4 oraciones)

Datos: ${JSON.stringify(threatData)}

Evaluación:`;

    const response = await env.AI.run('@cf/meta/llama-3-8b-instruct', {
      prompt,
      max_tokens: 300
    });

    return new Response(JSON.stringify({ 
      summary: response.response 
    }), {
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}
