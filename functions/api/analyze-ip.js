// Cloudflare Pages Function
async function analyzeIP(ip, env) {
  try {
    // AbuseIPDB - API data
    const abuseResponse = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90&verbose`, {
      headers: {
        'Key': env.ABUSEIPDB_KEY,
        'Accept': 'application/json'
      }
    });
    const abuseData = await abuseResponse.json();

    // AbuseIPDB - Scrape total reports from public page
    let totalReportsAllTime = null;
    try {
      const scrapeResponse = await fetch(`https://www.abuseipdb.com/check/${ip}`, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
      });
      const html = await scrapeResponse.text();
      const match = html.match(/was reported (\d+) times/i);
      if (match) {
        totalReportsAllTime = parseInt(match[1]);
      }
    } catch (e) {
      console.log('Scrape error:', e);
    }

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

    // Cloudflare Radar - Bot vs Human stats for ASN
    let cloudflareStats = null;
    const asn = ipinfoData.org?.split(' ')[0]?.replace('AS', '');
    if (asn && env.CLOUDFLARE_API_TOKEN) {
      try {
        console.log(`Fetching Cloudflare stats for ASN: ${asn}`);
        const cfResponse = await fetch(`https://api.cloudflare.com/client/v4/radar/http/summary/bot_class?asn=${asn}&dateRange=7d`, {
          headers: {
            'Authorization': `Bearer ${env.CLOUDFLARE_API_TOKEN}`,
            'Content-Type': 'application/json'
          }
        });
        const cfData = await cfResponse.json();
        console.log('Cloudflare response:', JSON.stringify(cfData));
        
        if (cfData.success && cfData.result?.summary_0) {
          cloudflareStats = {
            bot: Math.round(parseFloat(cfData.result.summary_0.bot || 0)),
            human: Math.round(parseFloat(cfData.result.summary_0.human || 0)),
            asn: asn
          };
        }
      } catch (e) {
        console.log('Cloudflare Radar error:', e);
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
          totalReportsAllTime: totalReportsAllTime,
          isp: abuseData.data?.isp || 'Unknown',
          usageType: abuseData.data?.usageType || 'Unknown',
          domain: abuseData.data?.domain || 'N/A',
          hostnames: abuseData.data?.hostnames || [],
          isWhitelisted: abuseData.data?.isWhitelisted || false,
          lastReported: abuseData.data?.lastReportedAt || null
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
        } : null,
        cloudflare: cloudflareStats
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
