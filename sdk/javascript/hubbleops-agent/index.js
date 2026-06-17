const crypto = require("crypto");

class HubbleOpsLoopBlocked extends Error {
  constructor(payload) {
    super(payload.reason || payload.message || "HubbleOps blocked tool execution");
    this.name = "HubbleOpsLoopBlocked";
    this.payload = payload;
  }
}

class HubbleOpsClient {
  constructor(options = {}) {
    this.baseUrl = (options.baseUrl || process.env.HUBBLEOPS_BASE_URL || process.env.HUBBLEOPS_URL || "http://localhost:8080").replace(/\/+$/, "");
    this.project = options.project || process.env.HUBBLEOPS_PROJECT || process.env.HUBBLEOPS_PROJECT_KEY || "unknown";
    this.sessionId = options.sessionId || process.env.HUBBLEOPS_SESSION_ID || "";
    this.timeoutMs = Number(options.timeoutMs || process.env.HUBBLEOPS_TIMEOUT_MS || 1000);
    this.failOpen = options.failOpen !== undefined ? Boolean(options.failOpen) : boolEnv("HUBBLEOPS_FAIL_OPEN", true);
    this.apiKey = options.apiKey || process.env.HUBBLEOPS_API_KEY || process.env.HUBBLEOPS_PROJECT_KEY || "";
    this.capture = (options.capture || process.env.HUBBLEOPS_CAPTURE_MODE || "fingerprint").toLowerCase();
    this.lastError = null;
  }

  async checkTool(toolName, args = {}, options = {}) {
    const payload = this.payload(toolName, {
      args,
      project: options.project,
      sessionId: options.sessionId,
      stepId: options.stepId,
      stateDeltaHash: options.stateDeltaHash,
      risk: options.risk,
      idempotencyKey: options.idempotencyKey,
      agentId: options.agentId,
      userId: options.userId,
      resourceId: options.resourceId ?? options.resource_id,
      amountCents: options.amountCents ?? options.amount_cents,
      maxAmountCents: options.maxAmountCents ?? options.max_amount_cents,
      backupId: options.backupId ?? options.backup_id,
      recipient: options.recipient,
      allowedDomain: options.allowedDomain ?? options.allowed_domain,
      capabilityToken: options.capabilityToken ?? options.capability_token,
      duplicateWindowSeconds: options.duplicateWindowSeconds,
    });
    return this.post("/v1/tool/check", payload, true, true);
  }

  async checkAction(actionName, args = {}, options = {}) {
    const payload = this.payload(actionName, { ...options, args });
    payload.action_name = actionName;
    return this.post("/v1/action/check", payload, true, true);
  }

  async recordResult(toolName, args = {}, result = null, options = {}) {
    const payload = this.payload(toolName, {
      args,
      result,
      resultClass: options.resultClass || classifyResult(result),
      project: options.project,
      sessionId: options.sessionId,
      stepId: options.stepId,
      stateDeltaHash: options.stateDeltaHash,
      costUsd: options.costUsd || 0,
      promptTokens: options.promptTokens || 0,
      outputTokens: options.outputTokens || 0,
      risk: options.risk,
      idempotencyKey: options.idempotencyKey,
      agentId: options.agentId,
      userId: options.userId,
      resourceId: options.resourceId ?? options.resource_id,
      amountCents: options.amountCents ?? options.amount_cents,
      maxAmountCents: options.maxAmountCents ?? options.max_amount_cents,
      backupId: options.backupId ?? options.backup_id,
      recipient: options.recipient,
      allowedDomain: options.allowedDomain ?? options.allowed_domain,
      capabilityToken: options.capabilityToken ?? options.capability_token,
      duplicateWindowSeconds: options.duplicateWindowSeconds,
    });
    return this.post("/v1/tool/result", payload, true);
  }

  async recordActionResult(actionName, args = {}, result = null, options = {}) {
    const payload = this.payload(actionName, { ...options, args, result, resultClass: options.resultClass || classifyResult(result) });
    payload.action_name = actionName;
    return this.post("/v1/action/result", payload, true);
  }

  wrapTool(fn, options = {}) {
    const toolName = options.name || fn.name || "tool";
    return async (...args) => {
      const callArgs = { args };
      const stepId = `${toolName}:${hashJSON(callArgs).slice(0, 16)}`;
      const idempotencyKey = resolveIdempotencyKey(options.idempotencyKey, toolName, callArgs, options.risk);
      const effect = resolveEffectOptions(options, toolName, callArgs);
      const check = await this.checkAction(toolName, callArgs, { ...options, ...effect, stepId, idempotencyKey });
      if (check.action === "block") {
        throw new HubbleOpsLoopBlocked(check);
      }
      if (check.action === "duplicate") {
        // The action already committed under this idempotency key. Replay the recorded
        // outcome instead of running the side effect again; do NOT record a result (that
        // would re-commit the same key).
        return duplicateReplayResult(check);
      }
      // The check that claimed the pending lease hands back an ownership nonce; the
      // result event must echo it or a failure release will (correctly) be refused.
      const claimNonce = check.claim_nonce || "";

      try {
        const result = await fn(...args);
        await this.recordActionResult(toolName, callArgs, result, {
          ...options,
          ...effect,
          stepId,
          idempotencyKey,
          claimNonce,
          stateDeltaHash: hashJSON(result),
        });
        return result;
      } catch (err) {
        await this.recordActionResult(toolName, callArgs, { error: err.name, message: err.message }, {
          ...options,
          ...effect,
          stepId,
          idempotencyKey,
          claimNonce,
          resultClass: classifyError(err),
        });
        throw err;
      }
    };
  }

  wrapAction(fn, options = {}) {
    return this.wrapTool(fn, options);
  }

  action(fn, options = {}) {
    return this.wrapAction(fn, options);
  }

  async doctor() {
    const checks = [];
    const health = await this.get("/healthz", false);
    checks.push({ name: "healthz", ok: Boolean(health.ok || health.status === "healthy"), detail: health.reason || "" });
    const check = await this.checkTool("hubbleops_doctor_noop", { probe: true }, { sessionId: "hubbleops-doctor" });
    checks.push({ name: "tool_check", ok: check.action === "allow" || check.action === "warn", detail: check.reason || "" });
    const result = await this.recordResult("hubbleops_doctor_noop", { probe: true }, { ok: true }, {
      sessionId: "hubbleops-doctor",
      stateDeltaHash: "hubbleops-doctor-ok",
    });
    checks.push({ name: "tool_result", ok: result.action === "allow" || result.action === "warn", detail: result.reason || "" });
    return { baseUrl: this.baseUrl, ok: checks.every((check) => check.ok), checks };
  }

  payload(toolName, options) {
    const payload = {
      project: options.project || this.project,
      session_id: options.sessionId || this.sessionId,
      step_id: options.stepId || "",
      action_name: toolName,
      tool_name: toolName,
      args: this.captureValue(options.args || {}),
      state_delta_hash: options.stateDeltaHash || "",
      cost_usd: options.costUsd || 0,
      prompt_tokens: options.promptTokens || 0,
      output_tokens: options.outputTokens || 0,
      unix_millis: Date.now(),
    };
    if (options.risk) payload.action_risk = options.risk;
    if (options.idempotencyKey) payload.idempotency_key = options.idempotencyKey;
    if (options.agentId) payload.agent_id = options.agentId;
    if (options.userId) payload.user_id = options.userId;
    const resourceId = options.resourceId ?? options.resource_id;
    const amountCents = options.amountCents ?? options.amount_cents;
    const maxAmountCents = options.maxAmountCents ?? options.max_amount_cents;
    const backupId = options.backupId ?? options.backup_id;
    const allowedDomain = options.allowedDomain ?? options.allowed_domain;
    const capabilityToken = options.capabilityToken ?? options.capability_token;
    if (resourceId) payload.resource_id = resourceId;
    if (amountCents !== undefined && amountCents !== null) payload.amount_cents = Number(amountCents);
    if (maxAmountCents !== undefined && maxAmountCents !== null) payload.max_amount_cents = Number(maxAmountCents);
    if (backupId) payload.backup_id = backupId;
    if (options.recipient) payload.recipient = options.recipient;
    if (allowedDomain) payload.allowed_domain = allowedDomain;
    if (capabilityToken) payload.capability_token = capabilityToken;
    if (options.duplicateWindowSeconds) payload.duplicate_window_seconds = Number(options.duplicateWindowSeconds);
    if (options.claimNonce) payload.claim_nonce = options.claimNonce;
    if (options.result !== undefined && options.result !== null) {
      payload.result = this.captureValue(options.result);
    }
    if (options.resultClass) {
      payload.result_class = options.resultClass;
    }
    return payload;
  }

  captureValue(value) {
    if (this.capture === "raw") {
      return value;
    }
    return {
      hubbleops_capture: "fingerprint",
      sha256: hashJSON(value),
      type: Array.isArray(value) ? "array" : typeof value,
    };
  }

  async get(path, allowFailOpen) {
    return this.send(path, { method: "GET" }, allowFailOpen);
  }

  async post(path, payload, allowFailOpen, enforceRisk = false) {
    // Per-tier fail policy: for a high-stakes action (dangerous / money movement) we
    // fail CLOSED on the pre-execution check even when the global default is fail-open
    // — if we can't reach HubbleOps to verify it, we don't let it run.
    const failClosedBlock = enforceRisk && isHighRisk(payload.action_risk);
    return this.send(path, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Project": payload.project },
      body: JSON.stringify(payload),
    }, failClosedBlock ? false : allowFailOpen, failClosedBlock);
  }

  async send(path, init, allowFailOpen, failClosedBlock = false) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const headers = { "User-Agent": "hubbleops-agent-js/0", ...(init.headers || {}) };
      if (this.apiKey) {
        headers["X-HubbleOps-API-Key"] = this.apiKey;
      }
      const res = await fetch(this.baseUrl + path, { ...init, headers, signal: controller.signal });
      const text = await res.text();
      const payload = text ? JSON.parse(text) : { action: "allow" };
      // 429 = loop/rate block, 422 = contradictory idempotency replay, 409 = the first
      // attempt with this idempotency key is still in flight. All three are deliberate
      // server blocks with a decision body — never fail-open them.
      if (res.status === 429 || res.status === 422 || res.status === 409) {
        payload.action = payload.action || "block";
        throw new HubbleOpsLoopBlocked(payload);
      }
      if (!res.ok) {
        throw new Error(`HubbleOps HTTP ${res.status}: ${text}`);
      }
      return payload;
    } catch (err) {
      if (err instanceof HubbleOpsLoopBlocked) {
        throw err;
      }
      if (allowFailOpen && this.failOpen) {
        this.lastError = err;
        return {
          action: "allow",
          fail_open: true,
          reason: "HubbleOps unavailable; allowed by fail-open SDK policy",
          error: err.name || "Error",
        };
      }
      if (failClosedBlock) {
        this.lastError = err;
        throw new HubbleOpsLoopBlocked({
          action: "block",
          fail_closed: true,
          reason: "HubbleOps unavailable; high-risk action blocked by fail-closed SDK policy",
          error: err.name || "Error",
        });
      }
      throw err;
    } finally {
      clearTimeout(timer);
    }
  }
}

function wrapTool(fn, options = {}) {
  const client = options.client || new HubbleOpsClient(options);
  return client.wrapTool(fn, options);
}

function wrapAction(fn, options = {}) {
  return wrapTool(fn, options);
}

function action(fn, options = {}) {
  return wrapAction(fn, options);
}

function duplicateReplayResult(check) {
  // Return the recorded outcome of an already-committed action. Raw capture retains the
  // original result body (Stripe-style idempotent replay); fingerprint capture retains
  // only metadata, returned with a hubbleopsReplay marker. The action is not run again.
  const replay = check.replay || {};
  if (replay.result !== undefined && replay.result !== null) {
    return replay.result;
  }
  return { hubbleopsReplay: true, ...replay };
}

function resolveIdempotencyKey(value, toolName, callArgs, risk = "read") {
  if (typeof value === "function") {
    value = value(callArgs);
  }
  if (value) {
    return String(value);
  }
  const normalizedRisk = String(risk || "read").toLowerCase();
  if (["read", "readonly", "read_only", "low"].includes(normalizedRisk)) {
    return "";
  }
  return `${toolName}:${hashJSON(callArgs)}`;
}

function resolveEffectOptions(options, toolName, callArgs) {
  return {
    resourceId: resolveOption(options.resourceId ?? options.resource_id, toolName, callArgs),
    amountCents: resolveOption(options.amountCents ?? options.amount_cents, toolName, callArgs),
    maxAmountCents: resolveOption(options.maxAmountCents ?? options.max_amount_cents, toolName, callArgs),
    backupId: resolveOption(options.backupId ?? options.backup_id, toolName, callArgs),
    recipient: resolveOption(options.recipient, toolName, callArgs),
    allowedDomain: resolveOption(options.allowedDomain ?? options.allowed_domain, toolName, callArgs),
    capabilityToken: resolveOption(options.capabilityToken ?? options.capability_token, toolName, callArgs),
  };
}

function resolveOption(value, toolName, callArgs) {
  if (typeof value === "function") {
    return value(callArgs, toolName);
  }
  return value;
}

const HIGH_RISK_LABELS = new Set(["dangerous", "danger", "critical", "destructive", "money_movement"]);

function isHighRisk(risk) {
  return HIGH_RISK_LABELS.has(String(risk || "").trim().toLowerCase());
}

function hashJSON(value) {
  return crypto.createHash("sha256").update(stableStringify(value)).digest("hex");
}

function stableStringify(value) {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(",")}]`;
  }
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(",")}}`;
}

function boolEnv(name, fallback) {
  const value = process.env[name];
  if (value === undefined) {
    return fallback;
  }
  return ["1", "true", "yes", "on"].includes(value.toLowerCase());
}

function classifyError(err) {
  const text = `${err.name || ""} ${err.message || ""}`.toLowerCase();
  if (text.includes("timeout") || text.includes("deadline")) return "timeout";
  if (text.includes("permission") || text.includes("unauthorized") || text.includes("forbidden")) return "permission_error";
  if (text.includes("not found") || text.includes("no such file")) return "not_found";
  if (text.includes("schema") || text.includes("validation") || text.includes("json")) return "schema_error";
  return "unknown_error";
}

function classifyResult(result) {
  if (result === null || result === undefined) return "empty";
  const text = stableStringify(result).toLowerCase();
  if (text === "null" || text === "{}" || text === "[]") return "empty";
  if (text.includes("rate limit") || text.includes("rate_limit") || text.includes("429")) return "rate_limited";
  if (text.includes("timeout") || text.includes("deadline exceeded")) return "timeout";
  if (text.includes("not_found") || text.includes("not found") || text.includes("no such file") || text.includes("404")) return "not_found";
  if (text.includes("permission") || text.includes("unauthorized") || text.includes("forbidden")) return "permission_error";
  if (text.includes("schema") || text.includes("invalid json") || text.includes("validation")) return "schema_error";
  if (text.includes("\"status\":\"pending\"") || text.includes("\"status\":\"queued\"") || text.includes("\"status\":\"running\"")) return "pending";
  if (text.includes("error") || text.includes("failed") || text.includes("exception")) return "unknown_error";
  return "success";
}

module.exports = { HubbleOpsClient, HubbleOpsLoopBlocked, wrapTool, wrapAction, action };
