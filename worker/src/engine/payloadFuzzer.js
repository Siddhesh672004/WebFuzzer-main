import { classifyEndpoint } from './paramClassifier.js';
import { loadPayloads, recordSuccess } from './payloadEngine.js';
import { analyzeResponse } from './responseAnalyzer.js';
import { mutate } from './mutationEngine.js';
import { makeFinding } from './findingFactory.js';

// Payload Fuzzer (PRD §9.5) — the active injection engine. Classifies params,
// loads payloads, fires them through the rate-limited HTTP client, analyzes
// responses, and runs the mutation engine on HIGH_INTEREST hits.

/**
 * Fuzz a single endpoint.
 * @param {object} endpoint  { url, method, params[] }
 * @param {HttpClient} http
 * @param {object} [opts]  { payloadModel, onFinding, onProgress, maxPayloads }
 * @returns {Promise<{findings: object[], payloadsSent: number}>}
 */
export async function fuzzEndpoint(endpoint, http, opts = {}) {
  const classified = classifyEndpoint(endpoint);
  const findings = [];
  let payloadsSent = 0;
  const onFinding = opts.onFinding || (() => {});
  const onProgress = opts.onProgress || (() => {});

  for (const param of classified.params) {
    if (!param.attackTypes || param.attackTypes.length === 0) continue;

    // Load payloads for this param's attack types.
    // eslint-disable-next-line no-await-in-loop
    const payloads = await loadPayloads(param.attackTypes, {
      cap: opts.maxPayloads || 50,
      model: opts.payloadModel,
    });

    // Establish baseline.
    // eslint-disable-next-line no-await-in-loop
    const baseline = await getBaseline(endpoint, http);

    for (let pi = 0; pi < payloads.length; pi++) {
      const payload = payloads[pi];
      // eslint-disable-next-line no-await-in-loop
      const response = await sendPayload(endpoint, param, payload.value, http);
      payloadsSent += 1;
      onProgress({
        payloadsSent,
        url: endpoint.url,
        param: param.name,
        attackType: payload.type,
        index: pi + 1,
        total: payloads.length,
      });

      const result = analyzeResponse(baseline, response, {
        attackType: payload.type,
        value: payload.value,
        url: endpoint.url,
        param: param.name,
      });

      if (result?.finding) {
        findings.push(result.finding);
        onFinding(result.finding);
        await recordSuccess(payload.type, payload.value, opts.payloadModel).catch(() => {});
      } else if (result?.interest === 'HIGH') {
        // Run mutation engine on HIGH_INTEREST.
        const variants = mutate(payload.value, payload.type);
        for (const variant of variants.slice(0, 10)) {
          // eslint-disable-next-line no-await-in-loop
          const mutRes = await sendPayload(endpoint, param, variant, http);
          payloadsSent += 1;
          onProgress({
            payloadsSent,
            url: endpoint.url,
            param: param.name,
            attackType: `${payload.type}*`, // mutation variant
            index: pi + 1,
            total: payloads.length,
          });
          const mutResult = analyzeResponse(baseline, mutRes, {
            attackType: payload.type,
            value: variant,
            url: endpoint.url,
            param: param.name,
          });
          if (mutResult?.finding) {
            const f = { ...mutResult.finding, isMutation: true, parentPayload: payload.value };
            findings.push(f);
            onFinding(f);
            break; // one confirmed mutation per payload is enough
          }
        }
      }
    }
  }

  return { findings, payloadsSent };
}

async function getBaseline(endpoint, http) {
  try {
    const res = await http.request({ url: endpoint.url, method: endpoint.method || 'GET' });
    return {
      status: res.status,
      bodyLength: (res.body || '').length,
      responseTimeMs: res.timeMs || 100,
    };
  } catch {
    return { status: 200, bodyLength: 0, responseTimeMs: 100 };
  }
}

async function sendPayload(endpoint, param, payloadValue, http) {
  const url = new URL(endpoint.url);
  let data;

  if (param.type === 'query' || endpoint.method === 'GET') {
    url.searchParams.set(param.name, payloadValue);
    return http.request({ url: url.toString(), method: 'GET' });
  } else {
    data = `${encodeURIComponent(param.name)}=${encodeURIComponent(payloadValue)}`;
    return http.request({
      url: endpoint.url,
      method: endpoint.method || 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      data,
    });
  }
}
