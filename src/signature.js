'use strict';

/**
 * Signature request analysis (EIP-712 typed data, personal_sign, eth_sign).
 * Most modern drains are signatures, not transactions: ERC-2612 permits,
 * Permit2 allowances / signature transfers, Seaport orders that give NFTs away
 * for nothing, and blind hash signing.
 */

const { getAddress, isAddress, isHexString, toUtf8String } = require('ethers');
const registry = require('./registry');
const { createChainReader, RpcError, supportedChainIds } = require('./rpc');
const { inspectContract, formatAmount, getTokenMeta } = require('./intel');
const contextAnalyzer = require('./context-analyzer');
const { detectPhishingPattern } = contextAnalyzer;

const UINT160_MAX = 2n ** 160n - 1n;
const UINT256_MAX = 2n ** 256n - 1n;
const UINT48_MAX = 2n ** 48n - 1n;
const DEFAULT_MAX_DEADLINE_DAYS = 30;
const AUTHORITY_FIELDS = new Set(['spender', 'operator', 'authorized', 'delegate', 'delegatee', 'executor', 'relayer', 'taker', 'recipient', 'to', 'target']);

class SignatureValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ValidationError';
  }
}

function finding(code, severity, message, extra) {
  return Object.assign({ code, severity, message, layer: 'signature' }, extra || {});
}

function big(v) {
  if (typeof v === 'bigint') return v;
  if (typeof v === 'number') return BigInt(Math.trunc(v));
  if (typeof v === 'string' && /^(0x[0-9a-fA-F]+|[0-9]+)$/.test(v.trim())) return BigInt(v.trim());
  return null;
}

function maxDeadlineSeconds(env) {
  const d = Number.parseInt((env || process.env).PERMIT_MAX_DEADLINE_DAYS || '', 10);
  return (Number.isInteger(d) && d > 0 ? d : DEFAULT_MAX_DEADLINE_DAYS) * 86400;
}

function normalizeInput(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new SignatureValidationError('Request body must be a JSON object');
  const type = String(input.type || (input.typedData ? 'eip712' : input.message !== undefined ? 'personal_sign' : '')).toLowerCase();
  if (!['eip712', 'eth_signtypeddata', 'eth_signtypeddata_v4', 'personal_sign', 'eth_sign'].includes(type)) {
    throw new SignatureValidationError('"type" must be one of eip712, personal_sign, eth_sign');
  }
  const out = { type: type.startsWith('eth_signtypeddata') ? 'eip712' : type, from: null, chainId: 1, typedData: null, message: null, context: null };
  if (input.from !== undefined && input.from !== null) {
    if (typeof input.from !== 'string' || !isAddress(input.from)) throw new SignatureValidationError('"from" must be a valid EVM address');
    out.from = getAddress(input.from);
  }
  if (input.chainId !== undefined && input.chainId !== null && input.chainId !== '') {
    const n = Number(input.chainId);
    if (!Number.isInteger(n) || n <= 0) throw new SignatureValidationError('chainId must be a positive integer');
    out.chainId = n;
  }
  try {
    out.context = contextAnalyzer.validateContext(input.context);
  } catch (err) {
    throw new SignatureValidationError(err.message);
  }
  if (out.type === 'eip712') {
    let td = input.typedData;
    if (typeof td === 'string') {
      try {
        td = JSON.parse(td);
      } catch {
        throw new SignatureValidationError('"typedData" is not valid JSON');
      }
    }
    if (!td || typeof td !== 'object' || !td.types || typeof td.types !== 'object' || !td.message || typeof td.message !== 'object') {
      throw new SignatureValidationError('"typedData" must contain types, primaryType, domain and message');
    }
    const primaryType = td.primaryType || Object.keys(td.types).find((t) => t !== 'EIP712Domain');
    if (!primaryType) throw new SignatureValidationError('"typedData.primaryType" is required');
    out.typedData = { types: td.types, primaryType: String(primaryType), domain: td.domain && typeof td.domain === 'object' ? td.domain : {}, message: td.message };
    if (out.typedData.domain.chainId !== undefined && input.chainId === undefined) {
      const n = Number(out.typedData.domain.chainId);
      if (Number.isInteger(n) && n > 0) out.chainId = n;
    }
  } else {
    if (typeof input.message !== 'string') throw new SignatureValidationError('"message" must be a string (utf-8 text or 0x hex)');
    if (input.message.length > 64 * 1024) throw new SignatureValidationError('"message" exceeds 64 KB');
    out.message = input.message;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Typed-data classifiers
// ---------------------------------------------------------------------------

function classifyTypedData(td) {
  const t = td.primaryType;
  const m = td.message;
  const fields = (td.types[t] || []).map((f) => f.name);
  const has = (...names) => names.every((n) => fields.includes(n));
  if (t === 'Permit' && has('owner', 'spender', 'value', 'nonce', 'deadline')) return { kind: 'erc2612_permit', spender: m.spender, amount: big(m.value), deadline: big(m.deadline), token: td.domain.verifyingContract || null };
  if (t === 'Permit' && has('holder', 'spender', 'nonce', 'expiry', 'allowed')) return { kind: 'dai_permit', spender: m.spender, amount: m.allowed ? UINT256_MAX : 0n, deadline: big(m.expiry), token: td.domain.verifyingContract || null };
  if (t === 'PermitSingle' && m.details && m.spender !== undefined) return { kind: 'permit2_single', spender: m.spender, amount: big(m.details.amount), deadline: big(m.details.expiration), sigDeadline: big(m.sigDeadline), token: m.details.token || null, permit2: true };
  if (t === 'PermitBatch' && Array.isArray(m.details) && m.spender !== undefined) {
    const amounts = m.details.map((d) => big(d.amount));
    const exps = m.details.map((d) => big(d.expiration));
    return { kind: 'permit2_batch', spender: m.spender, amount: amounts.reduce((a, b) => (b !== null && (a === null || b > a) ? b : a), null), deadline: exps.reduce((a, b) => (b !== null && (a === null || b > a) ? b : a), null), sigDeadline: big(m.sigDeadline), token: null, tokens: m.details.map((d) => d.token), permit2: true };
  }
  if ((t === 'PermitTransferFrom' || t === 'PermitWitnessTransferFrom') && m.permitted && m.spender !== undefined) return { kind: 'permit2_transfer', spender: m.spender, amount: big(m.permitted.amount), deadline: big(m.deadline), token: m.permitted.token || null, permit2: true, transfer: true };
  if (t === 'PermitBatchTransferFrom' && Array.isArray(m.permitted) && m.spender !== undefined) return { kind: 'permit2_transfer_batch', spender: m.spender, amount: m.permitted.map((p) => big(p.amount)).reduce((a, b) => (b !== null && (a === null || b > a) ? b : a), null), deadline: big(m.deadline), tokens: m.permitted.map((p) => p.token), permit2: true, transfer: true };
  if (t === 'OrderComponents' && Array.isArray(m.offer) && Array.isArray(m.consideration)) return { kind: 'seaport_order', offerer: m.offerer, offer: m.offer, consideration: m.consideration, endTime: big(m.endTime) };
  return { kind: 'unknown' };
}

function seaportZeroConsideration(c) {
  if (!c.offer.length) return null;
  const offerer = String(c.offerer || '').toLowerCase();
  const toOfferer = c.consideration.filter((x) => String(x.recipient || '').toLowerCase() === offerer);
  const total = toOfferer.reduce((sum, x) => sum + (big(x.startAmount) || 0n), 0n);
  if (c.consideration.length === 0) return 'the order has no consideration at all';
  if (toOfferer.length === 0) return 'nothing in the consideration is paid to the offerer';
  if (total === 0n) return 'the amount paid to the offerer is zero';
  return null;
}

function findAuthorityFields(message, from, path, acc, depth) {
  if (depth > 4 || !message || typeof message !== 'object') return acc;
  for (const [k, v] of Object.entries(message)) {
    const p = path ? path + '.' + k : k;
    if (typeof v === 'string' && isAddress(v) && AUTHORITY_FIELDS.has(k.toLowerCase())) {
      if (!from || v.toLowerCase() !== from.toLowerCase()) acc.push({ field: p, address: getAddress(v) });
    } else if (v && typeof v === 'object') findAuthorityFields(v, from, p, acc, depth + 1);
  }
  return acc;
}

// ---------------------------------------------------------------------------
// personal_sign helpers
// ---------------------------------------------------------------------------

function parseSiwe(text) {
  const m = text.match(/^([^\n]+?) wants you to sign in with your Ethereum account:\n(0x[0-9a-fA-F]{40})/);
  if (!m) return null;
  const uri = (text.match(/\nURI: (\S+)/) || [])[1] || null;
  const domain = m[1].trim();
  return { domain, address: m[2], uri };
}

function decodeHexMessage(hex) {
  try {
    const text = toUtf8String(hex);
    // eslint-disable-next-line no-control-regex
    if (/^[\x09\x0a\x0d\x20-\x7e -￿]*$/.test(text)) return text;
  } catch {
    /* not utf-8 */
  }
  return null;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function analyzeSignature(input, deps) {
  deps = deps || {};
  const env = deps.env || process.env;
  const req = normalizeInput(input);
  const findings = [];
  const details = { type: req.type, chainId: req.chainId, from: req.from, classification: null, spender: null, token: null, domain: null, rpc: { ok: true, endpoint: null, error: null } };
  const now = deps.now === undefined ? Math.floor(Date.now() / 1000) : deps.now;
  const maxDeadline = maxDeadlineSeconds(env);
  let pseudoDecoded = { kind: 'native', args: {}, amountBig: null, function: null, selector: null };
  let pseudoValue = 0n;

  const chainOk = supportedChainIds().includes(req.chainId) || Boolean(env['RPC_URL_' + req.chainId]);
  const getReader = () => {
    if (deps.reader) return deps.reader;
    if (!chainOk) return null;
    return createChainReader(req.chainId);
  };

  if (req.type === 'eth_sign') {
    findings.push(finding('eth_sign_deprecated', 'DENY', 'eth_sign signs an arbitrary 32-byte hash. A signature over an unknown hash can authorise any transaction or permit. Refuse.'));
    details.classification = 'eth_sign';
  } else if (req.type === 'personal_sign') {
    let text = req.message;
    let hexBlob = null;
    if (isHexString(req.message)) {
      const decoded = decodeHexMessage(req.message);
      if (decoded !== null && decoded.length > 0) text = decoded;
      else hexBlob = req.message;
    }
    if (hexBlob) {
      const bytes = (hexBlob.length - 2) / 2;
      if (bytes === 32) findings.push(finding('blind_hash_signing', 'DENY', 'The message is a raw 32-byte value that is not text. Signing an opaque hash with personal_sign can authorise permits, orders or meta-transactions you cannot see.', { bytes }));
      else findings.push(finding('opaque_hex_message', 'WARN', 'The message is ' + bytes + ' bytes of non-text data. You cannot know what you are authorising.', { bytes }));
      details.classification = 'opaque_hex';
    } else {
      const siwe = parseSiwe(text);
      if (siwe) {
        details.classification = 'siwe';
        details.siwe = siwe;
        const phish = detectPhishingPattern(siwe.domain.toLowerCase());
        if (phish) findings.push(finding('siwe_phishing_domain', 'DENY', 'Sign-In-With-Ethereum request from "' + siwe.domain + '" matches a phishing pattern (' + phish.pattern + '): ' + phish.detail, { domain: siwe.domain, pattern: phish.pattern }));
        if (siwe.uri) {
          let uriHost = null;
          try {
            uriHost = new URL(siwe.uri).hostname.toLowerCase();
          } catch {
            uriHost = null;
          }
          if (uriHost && uriHost !== siwe.domain.toLowerCase() && !uriHost.endsWith('.' + siwe.domain.toLowerCase()) && !siwe.domain.toLowerCase().endsWith('.' + uriHost)) {
            findings.push(finding('siwe_domain_mismatch', 'WARN', 'SIWE domain "' + siwe.domain + '" does not match URI host "' + uriHost + '".', { domain: siwe.domain, uriHost }));
          }
        }
        if (req.from && siwe.address.toLowerCase() !== req.from.toLowerCase()) {
          findings.push(finding('siwe_address_mismatch', 'WARN', 'SIWE message names account ' + siwe.address + ' but the signer is ' + req.from + '.', { messageAddress: siwe.address }));
        }
      } else {
        details.classification = 'text';
        const hasAddress = /0x[0-9a-fA-F]{40}/.test(text);
        const authWords = /\b(approve|approval|permit|allowance|transfer|withdraw|setApprovalForAll|delegate|authorize|authorise)\b/i.test(text);
        if (hasAddress && authWords) findings.push(finding('authorization_text_in_message', 'WARN', 'The text contains authorisation language and an address. Off-chain services may treat this signature as consent to move assets.', {}));
        const urls = text.match(/https?:\/\/[^\s)]+/g) || [];
        for (const u of urls) {
          let host = null;
          try {
            host = new URL(u).hostname.toLowerCase();
          } catch {
            host = null;
          }
          const phish = host ? detectPhishingPattern(host) : null;
          if (phish) {
            findings.push(finding('phishing_url_in_message', 'DENY', 'Message links to "' + host + '" which matches a phishing pattern (' + phish.pattern + ').', { host, pattern: phish.pattern }));
            break;
          }
        }
      }
    }
  } else {
    const td = req.typedData;
    const c = classifyTypedData(td);
    details.classification = c.kind;
    details.primaryType = td.primaryType;
    details.domain = { name: td.domain.name || null, version: td.domain.version || null, chainId: td.domain.chainId !== undefined ? Number(td.domain.chainId) : null, verifyingContract: td.domain.verifyingContract || null };

    if (details.domain.chainId !== null && details.domain.chainId !== req.chainId) {
      findings.push(finding('domain_chain_mismatch', 'WARN', 'typedData.domain.chainId (' + details.domain.chainId + ') differs from the requested chainId (' + req.chainId + ').', {}));
    }

    const addressesToCheck = [];
    if (details.domain.verifyingContract && isAddress(details.domain.verifyingContract)) addressesToCheck.push({ role: 'verifyingContract', address: getAddress(details.domain.verifyingContract) });

    if (c.kind.startsWith('erc2612') || c.kind === 'dai_permit' || c.kind.startsWith('permit2')) {
      const spender = isAddress(c.spender || '') ? getAddress(c.spender) : null;
      details.spender = { address: spender };
      if (!spender) findings.push(finding('unrecognized_authorization', 'WARN', 'Permit message has an invalid spender field.', {}));
      const unlimited = c.amount !== null && (c.permit2 ? c.amount >= UINT160_MAX : c.amount > 2n ** 255n - 1n);
      pseudoDecoded = { kind: 'approve', args: { spender, amount: c.amount === null ? null : c.amount.toString() }, amountBig: c.amount, function: c.kind, selector: null };
      if (c.transfer) {
        pseudoDecoded.kind = 'transfer';
        pseudoDecoded.args = { recipient: spender, amount: pseudoDecoded.args.amount };
        findings.push(finding('signature_transfer_authorization', 'WARN', 'This Permit2 signature lets ' + (spender || 'the spender') + ' pull ' + (c.amount === null ? 'tokens' : c.amount.toString() + ' raw units') + ' from your wallet immediately, without a separate approve transaction.', { spender, amount: c.amount === null ? null : c.amount.toString() }));
      } else if (unlimited) {
        findings.push(finding('unlimited_approval', 'WARN', 'The permit grants an unlimited allowance to ' + (spender || 'the spender') + '.', { spender, permit: c.kind }));
      }
      const deadline = c.deadline;
      if (deadline !== null) {
        if (deadline >= UINT48_MAX && c.permit2 || deadline >= UINT256_MAX - 1n || deadline > BigInt(now + 10 * 365 * 86400)) {
          findings.push(finding('far_deadline', 'WARN', 'The permit never expires (deadline ' + deadline.toString() + ').', { deadline: deadline.toString() }));
        } else if (deadline > BigInt(now + maxDeadline)) {
          findings.push(finding('far_deadline', 'WARN', 'The permit stays valid for ' + Math.round((Number(deadline) - now) / 86400) + ' days; longer than the ' + Math.round(maxDeadline / 86400) + '-day policy.', { deadline: deadline.toString() }));
        } else if (deadline < BigInt(now)) {
          findings.push(finding('expired_deadline', 'WARN', 'The permit deadline is already in the past; the signature would be useless.', { deadline: deadline.toString() }));
        }
      }
      if (spender) addressesToCheck.push({ role: 'spender', address: spender });
      if (c.token && isAddress(c.token)) details.token = { address: getAddress(c.token) };
      if (c.permit2 && details.domain.verifyingContract && !registry.lookupContract(req.chainId, details.domain.verifyingContract)) {
        findings.push(finding('permit2_domain_mismatch', 'DENY', 'A Permit2-shaped message whose verifyingContract (' + details.domain.verifyingContract + ') is not the canonical Permit2 contract. This is a spoofed permit.', {}));
      }
    } else if (c.kind === 'seaport_order') {
      const why = seaportZeroConsideration(c);
      pseudoDecoded = { kind: 'transfer', args: { recipient: null, amount: null }, amountBig: null, function: 'seaport_order', selector: null };
      if (why) findings.push(finding('seaport_zero_consideration', 'DENY', 'This Seaport order gives away ' + c.offer.length + ' item(s) while ' + why + '. Classic NFT-drainer signature.', { offerItems: c.offer.length, consideration: c.consideration.length }));
      if (c.endTime !== null && c.endTime > BigInt(now + 10 * 365 * 86400)) findings.push(finding('far_deadline', 'WARN', 'The order stays valid for more than 10 years.', { endTime: c.endTime.toString() }));
    } else {
      const auth = findAuthorityFields(td.message, req.from, '', [], 0);
      if (auth.length) {
        findings.push(finding('unrecognized_authorization', 'WARN', 'Unrecognised typed data "' + td.primaryType + '" contains authority fields naming other addresses: ' + auth.map((a) => a.field + '=' + a.address).join(', ') + '. Decode the schema before signing.', { fields: auth }));
        for (const a of auth) addressesToCheck.push({ role: 'authority:' + a.field, address: a.address });
        pseudoDecoded = { kind: 'approve', args: { spender: auth[0].address, amount: null }, amountBig: null, function: td.primaryType, selector: null };
      } else {
        details.note = 'Unrecognised typed data without authority fields; no asset-moving semantics detected.';
      }
    }

    // ---- on-chain checks for spender / verifyingContract ----
    if (addressesToCheck.length) {
      const reader = getReader();
      if (!reader) {
        findings.push(finding('rpc_unavailable', 'WARN', 'chainId ' + req.chainId + ' has no RPC configured; spender and contract checks were skipped.', {}));
      } else {
        try {
          const unique = Array.from(new Map(addressesToCheck.map((a) => [a.address.toLowerCase(), a.address])).values());
          const states = await Promise.all(unique.map((a) => reader.addressState(a)));
          const byAddr = new Map(states.map((s) => [s.address.toLowerCase(), s]));
          details.rpc.endpoint = reader.endpoint || null;
          details.addressChecks = {};
          for (const item of addressesToCheck) {
            const state = byAddr.get(item.address.toLowerCase());
            const info = await inspectContract(reader, req.chainId, item.address, state);
            details.addressChecks[item.role] = { address: item.address, isContract: info.isContract, known: info.known, proxy: info.proxy, codeSize: info.codeSize };
            if (item.role === 'spender') details.spender = Object.assign(details.spender || {}, { isContract: info.isContract, known: info.known, proxy: info.proxy });
            if (info.lookalikeOf) findings.push(finding('contract_lookalike', 'DENY', item.address + ' imitates ' + info.lookalikeOf.name + ' (' + info.lookalikeOf.address + ') but is a different address.', { role: item.role, imitates: info.lookalikeOf.address }));
            if (!info.isContract) {
              if (item.role === 'spender') findings.push(finding('approval_to_eoa', 'DENY', 'The permit spender ' + item.address + ' is a plain wallet, not a contract. This signature would let that wallet drain the token.', { address: item.address }));
              else if (item.role === 'verifyingContract') findings.push(finding('verifying_contract_is_eoa', 'DENY', 'domain.verifyingContract ' + item.address + ' has no code. A legitimate EIP-712 domain always points at the contract that consumes the signature.', { address: item.address }));
              else findings.push(finding('authority_is_eoa', 'WARN', item.address + ' (' + item.role + ') is a plain wallet.', { address: item.address }));
            } else if (item.role === 'spender' && !info.known && pseudoDecoded.kind === 'approve' && (pseudoDecoded.amountBig === null || pseudoDecoded.amountBig > 2n ** 255n - 1n || (c.permit2 && pseudoDecoded.amountBig >= UINT160_MAX))) {
              findings.push(finding('unknown_spender', 'WARN', 'Unlimited permit to a contract that is not a recognised protocol (' + item.address + ').', { address: item.address }));
            }
          }
          if (details.token && details.token.address) {
            try {
              const meta = await getTokenMeta(reader, req.chainId, details.token.address);
              if (meta) details.token = Object.assign(details.token, meta);
              if (meta && pseudoDecoded.amountBig !== null) details.amount = formatAmount(pseudoDecoded.amountBig, meta);
            } catch (err) {
              if (!(err instanceof RpcError)) throw err;
              details.token.metaError = err.message;
            }
          }
        } catch (err) {
          details.rpc.ok = false;
          details.rpc.error = err instanceof RpcError ? err.message : 'Unexpected RPC failure: ' + err.message;
          findings.push(finding('rpc_unavailable', 'WARN', 'On-chain checks for the spender could not be completed (' + details.rpc.error + '). Fail-safe: verdict is at least WARN.', {}));
        }
      }
    }
  }

  // ---- agent-integrity layer ----
  let intentAnalysis = null;
  let contextSignals = [];
  let contextFindings = [];
  if (req.context) {
    try {
      const ctx = contextAnalyzer.analyzeContext(req.context, pseudoDecoded, pseudoValue, { env, sessionStore: deps.sessionStore, now: deps.nowMs });
      contextFindings = ctx.findings;
      intentAnalysis = ctx.intent_analysis;
      contextSignals = ctx.context_signals;
    } catch (err) {
      contextFindings = [finding('context_analysis_failed', 'WARN', 'Context analysis failed unexpectedly (' + err.message + ').', {})];
    }
    for (const f of contextFindings) findings.push(f);
  }

  const SEV = { ALLOW: 0, WARN: 1, DENY: 2 };
  let verdict = 'ALLOW';
  for (const f of findings) if (SEV[f.severity] > SEV[verdict]) verdict = f.severity;
  const { computeRiskScore } = require('./analyzer');
  const { buildRecommendations } = require('./summary');
  const reasons = Array.from(new Set(findings.map((f) => f.code)));
  const summary = summarize(req, details, verdict, reasons);
  return {
    verdict,
    reasons,
    summary,
    details: Object.assign(details, {
      findings,
      risk_score: computeRiskScore(findings),
      recommendations: buildRecommendations(findings).concat(SIGNATURE_RECOMMENDATIONS.filter((r) => reasons.includes(r.code))),
      context_analyzed: req.context !== null,
      intent_analysis: intentAnalysis,
      context_signals: contextSignals,
      session_risk_score: computeRiskScore(contextFindings),
      analyzedAt: new Date().toISOString(),
    }),
  };
}

const SIGNATURE_RECOMMENDATIONS = [
  { code: 'eth_sign_deprecated', action: 'Refuse eth_sign entirely; use personal_sign or EIP-712 with a readable schema.' },
  { code: 'blind_hash_signing', action: 'Refuse. Ask the requesting app for the EIP-712 typed data instead of a raw hash.' },
  { code: 'opaque_hex_message', action: 'Ask for a human-readable message or typed data before signing.' },
  { code: 'signature_transfer_authorization', action: 'Only sign if you expect this exact protocol to pull this exact amount now; the signature is as good as a transfer.' },
  { code: 'far_deadline', action: 'Ask for a permit with a short deadline (minutes to hours).' },
  { code: 'seaport_zero_consideration', action: 'Refuse. You would give your NFTs away for nothing.' },
  { code: 'permit2_domain_mismatch', action: 'Refuse. Real Permit2 messages verify against the canonical Permit2 contract.' },
  { code: 'verifying_contract_is_eoa', action: 'Refuse. The domain points at a wallet, so the signature can be replayed anywhere.' },
  { code: 'siwe_phishing_domain', action: 'Refuse the sign-in; the requesting site imitates a known brand.' },
  { code: 'siwe_domain_mismatch', action: 'Verify the site URL matches the message domain before signing in.' },
  { code: 'unrecognized_authorization', action: 'Obtain the contract ABI or docs for this typed data before signing.' },
];

function summarize(req, details, verdict, reasons) {
  let what;
  switch (details.classification) {
    case 'eth_sign':
      what = 'eth_sign over an arbitrary hash';
      break;
    case 'opaque_hex':
      what = 'personal_sign over opaque bytes';
      break;
    case 'siwe':
      what = 'Sign-In-With-Ethereum for ' + details.siwe.domain;
      break;
    case 'text':
      what = 'personal_sign over a text message';
      break;
    case 'erc2612_permit':
    case 'dai_permit':
      what = 'ERC-2612 permit' + (details.amount ? ' for ' + details.amount : '') + ' to ' + (details.spender && details.spender.known ? details.spender.known.name : (details.spender && details.spender.address) || 'spender');
      break;
    case 'permit2_single':
    case 'permit2_batch':
      what = 'Permit2 allowance' + (details.amount ? ' for ' + details.amount : '') + ' to ' + (details.spender && details.spender.known ? details.spender.known.name : (details.spender && details.spender.address) || 'spender');
      break;
    case 'permit2_transfer':
    case 'permit2_transfer_batch':
      what = 'Permit2 signature transfer' + (details.amount ? ' of ' + details.amount : '') + ' pulled by ' + (details.spender && details.spender.known ? details.spender.known.name : (details.spender && details.spender.address) || 'spender');
      break;
    case 'seaport_order':
      what = 'Seaport order';
      break;
    default:
      what = 'EIP-712 "' + (details.primaryType || 'unknown') + '"' + (details.domain && details.domain.name ? ' from ' + details.domain.name : '');
  }
  return what + '. ' + (verdict === 'ALLOW' ? 'No risk rules triggered.' : verdict + ': ' + reasons.join(', ') + '.');
}

const SIGNATURE_RULES = [
  { code: 'eth_sign_deprecated', severity: 'DENY', layer: 'signature', description: 'eth_sign over an arbitrary 32-byte hash.' },
  { code: 'blind_hash_signing', severity: 'DENY', layer: 'signature', description: 'personal_sign over a raw 32-byte non-text value.' },
  { code: 'opaque_hex_message', severity: 'WARN', layer: 'signature', description: 'personal_sign over non-text bytes.' },
  { code: 'siwe_phishing_domain', severity: 'DENY', layer: 'signature', description: 'Sign-In-With-Ethereum domain matches a phishing pattern.' },
  { code: 'siwe_domain_mismatch', severity: 'WARN', layer: 'signature', description: 'SIWE domain and URI host differ.' },
  { code: 'siwe_address_mismatch', severity: 'WARN', layer: 'signature', description: 'SIWE message account differs from the signer.' },
  { code: 'authorization_text_in_message', severity: 'WARN', layer: 'signature', description: 'Plain-text message contains authorisation language plus an address.' },
  { code: 'phishing_url_in_message', severity: 'DENY', layer: 'signature', description: 'Plain-text message links to a phishing-pattern host.' },
  { code: 'signature_transfer_authorization', severity: 'WARN', layer: 'signature', description: 'Permit2 PermitTransferFrom: the spender can pull tokens immediately.' },
  { code: 'far_deadline', severity: 'WARN', layer: 'signature', description: 'Permit or order deadline beyond PERMIT_MAX_DEADLINE_DAYS (default 30) or never expires.' },
  { code: 'expired_deadline', severity: 'WARN', layer: 'signature', description: 'Permit deadline already passed.' },
  { code: 'permit2_domain_mismatch', severity: 'DENY', layer: 'signature', description: 'Permit2-shaped message whose verifyingContract is not the canonical Permit2.' },
  { code: 'seaport_zero_consideration', severity: 'DENY', layer: 'signature', description: 'Seaport order that gives items away with no payment to the offerer.' },
  { code: 'verifying_contract_is_eoa', severity: 'DENY', layer: 'signature', description: 'EIP-712 domain verifyingContract has no code.' },
  { code: 'authority_is_eoa', severity: 'WARN', layer: 'signature', description: 'An authority field in unrecognised typed data names a plain wallet.' },
  { code: 'unrecognized_authorization', severity: 'WARN', layer: 'signature', description: 'Unrecognised typed data contains spender/operator-like fields.' },
  { code: 'domain_chain_mismatch', severity: 'WARN', layer: 'signature', description: 'typedData.domain.chainId differs from the requested chainId.' },
];

module.exports = { analyzeSignature, classifyTypedData, normalizeInput, SIGNATURE_RULES, SignatureValidationError };
