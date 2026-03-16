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

    const prompt = `Eres un analista de ciberseguridad. Analiza estos datos de inteligencia de amenazas IP y proporciona una evaluación de seguridad breve en 3-4 oraciones. Sé conciso y profesional. Responde en español.

Datos: ${JSON.stringify(threatData)}

Evaluación:`;

    const response = await env.AI.run('@cf/meta/llama-3-8b-instruct', {
      prompt,
      max_tokens: 200
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
