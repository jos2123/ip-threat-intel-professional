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

    const prompt = `Eres un analista de ciberseguridad senior trabajando para una empresa en Colombia. Analiza los siguientes datos de inteligencia de amenazas IP.

REGLAS IMPORTANTES:
- NO menciones puntajes numéricos ni porcentajes en tu análisis
- Aunque el riesgo sea alto, NUNCA recomiendes bloquear sin investigar primero
- Siempre sugiere investigar el origen y contexto antes de tomar acciones
- Analiza cada estadística: reportes de abuso, detecciones de VirusTotal, puertos abiertos, tipo de tráfico
- Considera que en Colombia muchas IPs legítimas pueden tener reportes por falsos positivos
- Sé profesional y conciso (3-4 oraciones)

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
