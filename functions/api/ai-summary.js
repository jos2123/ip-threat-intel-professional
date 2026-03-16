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

    const prompt = `Eres un analista de ciberseguridad senior de LINKTIC S.A.S en Colombia. Analiza la IP y responde en español.

CONTEXTO:
- IPs con ISP "LINKTIC" o dominio "tigo.com.co" son de nuestra red o clientes
- "Mobile ISP" + Colombia = cliente móvil legítimo

REGLAS:
- NO empieces con frases como "Excelente", "Buena elección", etc. Ve directo al análisis
- NO menciones puntajes numéricos ni porcentajes
- Analiza: ISP, dominio, tipo de uso, reportes abuso, VirusTotal, Shodan, tráfico bot/humano
- NUNCA recomiendes bloquear sin investigar
- Sé directo y conciso (3-4 oraciones)

Datos: ${JSON.stringify(threatData)}

Análisis:`;

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
