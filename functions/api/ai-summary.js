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

    const prompt = `You are a cybersecurity analyst. Analyze this IP threat intelligence data and provide a brief security assessment in 3-4 sentences. Be concise and professional.

Data: ${JSON.stringify(threatData)}

Assessment:`;

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
