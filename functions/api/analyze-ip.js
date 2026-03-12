// Cloudflare Pages Function
async function analyzeIP(ip, env) {
  try {
    // AbuseIPDB - Solicitar datos de 90 días y verbose para más información
    const abuseResponse = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90&verbose`, {
      headers: {
        'Key': env.ABUSEIPDB_KEY,
        'Accept': 'application/json'
      }
    });
    const abuseData = await abuseResponse.json();

    // VirusTotal
    const vtResponse = await fetch(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, {
      headers: {
        'x-apikey': env.VIRUSTOTAL_KEY
      }
    });
    const vtData = await vtResponse.json();

    // IPinfo
    const ipinfoResponse = await fetch(`https://ipinfo.io/${ip}/json`);
    const ipinfoData = await ipinfoResponse.json();

    // Shodan
    let shodanData = null;
    if (env.SHODAN_KEY) {
      try {
        const shodanResponse = await fetch(`https://api.shodan.io/shodan/host/${ip}?key=${env.SHODAN_KEY}`);
        if (shodanResponse.ok) {
          shodanData = await shodanResponse.json();
        }
      } catch (e) {
        console.log('Shodan error:', e);
      }
    }

    // Format response
    const result = {
      ip,
      timestamp: new Date().toISOString(),
      basic: {
        asn: ipinfoData.org?.split(' ')[0] || 'Unknown',
        organization: ipinfoData.org?.substring(ipinfoData.org.indexOf(' ') + 1) || 'Unknown',
        country: ipinfoData.country || 'Unknown',
        city: ipinfoData.city || 'Unknown',
        region: ipinfoData.region || 'Unknown'
      },
      reputation: {
        abuseipdb: {
          score: abuseData.data?.abuseConfidenceScore || 0,
          reports: abuseData.data?.totalReports || 0,
          categories: abuseData.data?.usageType || 'Unknown',
          isWhitelisted: abuseData.data?.isWhitelisted || false
        },
        virustotal: {
          malicious: vtData.data?.attributes?.last_analysis_stats?.malicious || 0,
          suspicious: vtData.data?.attributes?.last_analysis_stats?.suspicious || 0,
          harmless: vtData.data?.attributes?.last_analysis_stats?.harmless || 0
        },
        riskLevel: abuseData.data?.abuseConfidenceScore > 50 ? 'high' : 
                   abuseData.data?.abuseConfidenceScore > 25 ? 'medium' : 'low',
        riskScore: abuseData.data?.abuseConfidenceScore || 0
      },
      intelligence: {
        shodan: shodanData ? {
          ports: shodanData.ports || [],
          services: shodanData.data?.map(s => ({ 
            port: s.port, 
            product: s.product, 
            version: s.version 
          })) || []
        } : null
      }
    };

    return result;

  } catch (error) {
    throw error;
  }
}

export async function onRequestGet(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const ip = url.searchParams.get('ip');

  if (!ip) {
    return new Response(JSON.stringify({ error: 'IP required' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  try {
    const result = await analyzeIP(ip, env);
    return new Response(JSON.stringify(result), {
      headers: { 
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      }
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

export async function onRequestPost(context) {
  const { request, env } = context;
  
  try {
    const { ip } = await request.json();
    
    if (!ip) {
      return new Response(JSON.stringify({ error: 'IP required' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const result = await analyzeIP(ip, env);
    return new Response(JSON.stringify(result), {
      headers: { 
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Cache-Control': 'no-cache'
      }
    });

  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}
