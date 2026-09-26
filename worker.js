export default {
  async fetch(request, env, ctx) {
    const ip = request.headers.get("CF-Connecting-IP");

    if (!ip) {
      return fetch(request);
    }

    const cacheKey = `ip:${ip}`;

    /*
     * Scanner probe: any .html or .php path.
     * Blocked regardless of Blackbox reputation.
     */
    const pathname =
      new URL(request.url).pathname.toLowerCase();

    const isProbe =

      pathname.includes("wp") ||

      pathname.includes(".env") ||

      pathname.includes(".git") ||

      pathname.includes(".py") ||

      pathname.includes("cgn");

    /*
     * Check KV first.
     */
    const cached = await env.IP_REPUTATION_CACHE.get(
      cacheKey,
      {
        type: "json"
      }
    );

    /*
     * Already classified as suspicious.
     */
    if (cached && cached.suspicious === true) {
      return new Response("Forbidden", {
        status: 403
      });
    }

    if (isProbe) {
      /*
       * Block now; flag asynchronously.
       */
      ctx.waitUntil(
        flagIP(ip, pathname, env)
      );

      return new Response("Forbidden", {
        status: 403
      });
    }

    /*
     * Already checked and clean.
     */
    if (cached) {
      return fetch(request);
    }

    /*
     * First time seeing this IP.
     *
     * Don't make the user wait for Blackbox.
     */
    ctx.waitUntil(
      checkIP(ip, env)
    );

    /*
     * Allow first request.
     */
    return fetch(request);
  }
};


/*
 * ------------------------------------------------------------
 * Flag IP on .html / .php probe
 *
 * Overrides any cached "clean" verdict and adds the IP
 * to the Cloudflare list without consulting Blackbox.
 * ------------------------------------------------------------
 */
async function flagIP(ip, pathname, env) {
  const cacheKey = `ip:${ip}`;

  const result = {
    ip: ip,

    suspicious: true,

    classification: "scanner",

    confidence: null,

    asn: null,

    categories: {},

    signals: {},

    evidence: [
      `path_probe:${pathname}`
    ],

    checked_at:
      new Date().toISOString()
  };

  try {
    /*
     * Cache for 24 hours so repeat probes short-circuit.
     */
    await env.IP_REPUTATION_CACHE.put(
      cacheKey,
      JSON.stringify(result),
      {
        expirationTtl: 86400
      }
    );

    await addToCloudflareList(
      ip,
      result,
      env
    );

  } catch (error) {
    console.error(
      `Failed to flag ${ip}:`,
      error
    );
  }
}


/*
 * ------------------------------------------------------------
 * Check IP with Blackbox
 * ------------------------------------------------------------
 */
async function checkIP(ip, env) {
  const cacheKey = `ip:${ip}`;

  try {
    /*
     * Blackbox arbitrary-IP lookup.
     */
    const url =
      `https://blackbox.ipinfo.app/api/v3beta/${encodeURIComponent(ip)}`;

    const response = await fetch(url, {
      method: "GET",

      headers: {
        "Accept": "application/json",
        "User-Agent": "Cloudflare-IP-Reputation/1.0"
      }
    });

    if (!response.ok) {
      console.error(
        `Blackbox HTTP ${response.status} for ${ip}`
      );

      return;
    }

    const data = await response.json();

    /*
     * Blackbox API error.
     */
    if (data.error !== null) {
      console.error(
        `Blackbox error for ${ip}:`,
        JSON.stringify(data.error)
      );

      return;
    }

    /*
     * Normalize response.
     */
    const result = {
      ip: ip,

      suspicious:
        data.suspicious === true,

      classification:
        data.classification || "unknown",

      confidence:
        typeof data.confidence === "number"
          ? data.confidence
          : null,

      asn:
        data.asn || null,

      categories:
        data.categories || {},

      signals:
        data.signals || {},

      evidence:
        Array.isArray(data.evidence)
          ? data.evidence
          : [],

      checked_at:
        new Date().toISOString()
    };

    console.log(
      `Blackbox result: ${JSON.stringify(result)}`
    );

    /*
     * Cache for 24 hours.
     */
    await env.IP_REPUTATION_CACHE.put(
      cacheKey,
      JSON.stringify(result),
      {
        expirationTtl: 86400
      }
    );

    /*
     * Add suspicious IP to Cloudflare list.
     */
    if (result.suspicious === true) {
      await addToCloudflareList(
        ip,
        result,
        env
      );
    }

  } catch (error) {
    console.error(
      `IP reputation check failed for ${ip}:`,
      error
    );
  }
}


/*
 * ------------------------------------------------------------
 * Add IP to Cloudflare IP List
 * ------------------------------------------------------------
 */
async function addToCloudflareList(ip, result, env) {

  const url =
    `https://api.cloudflare.com/client/v4/accounts/` +
    `${env.CF_ACCOUNT_ID}/rules/lists/` +
    `${env.CF_LIST_ID}/items`;

  const payload = [
    {
      ip: ip,

      comment:
        `Blackbox suspicious | ` +
        `classification=${result.classification} | ` +
        `confidence=${result.confidence} | ` +
        `evidence=${result.evidence.join(",")}`
    }
  ];

  try {

    const response = await fetch(url, {
      method: "POST",

      headers: {
        "Authorization":
          `Bearer ${env.CF_API_TOKEN}`,

        "Content-Type":
          "application/json",

        "Accept":
          "application/json"
      },

      body: JSON.stringify(payload)
    });

    const data = await response.json();

    if (!response.ok || data.success !== true) {
      console.error(
        "Cloudflare List API error:",
        JSON.stringify(data)
      );

      return;
    }

    console.log(
      `Added ${ip} to Cloudflare IP list`
    );

  } catch (error) {

    console.error(
      `Cloudflare list update failed for ${ip}:`,
      error
    );
  }
}
