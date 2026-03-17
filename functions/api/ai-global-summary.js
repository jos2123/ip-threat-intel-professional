export async function onRequestPost(context) {
  const { request, env } = context;
  
  try {
    const { allData } = await request.json();
    
    if (!allData || allData.length === 0) {
      return new Response(JSON.stringify({ error: 'No data provided' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const summary = allData.map(d => 
      `${d.ip}: ${d.riskLevel}, ${d.country}, ${d.org || d.isp}, reportes:${d.abuseReports || 0}, malicious:${d.malicious || 0}`
    ).join('\n');

    const prompt = `Eres un analista de ciberseguridad senior de LINKTIC S.A.S en Colombia. Analiza este conjunto de ${allData.length} IPs y genera un RESUMEN EJECUTIVO. Responde en español.

REGLAS:
- NO listes cada IP individualmente
- Genera un resumen consolidado de hallazgos
- Agrupa por nivel de riesgo (cuántas high, medium, low)
- Menciona patrones: países más frecuentes, ISPs comunes, tipos de uso
- Si hay IPs de LINKTIC/Tigo/Colombia Móvil, indica que son de nuestra red
- Identifica IPs que requieren atención inmediata vs las que son seguras
- NO recomiendes bloquear sin investigar
- Sé conciso pero completo (5-6 oraciones)

Datos de las ${allData.length} IPs:
${summary}

Resumen Ejecutivo:`;

    const response = await env.AI.run('@cf/meta/llama-3-8b-instruct', {
      prompt,
      max_tokens: 500
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
