import functools
import hashlib
import inspect
import json
import os
import socket
import time
import urllib.error
import urllib.request


class WitnessLoopBlocked(RuntimeError):
    def __init__(self, payload):
        self.payload = payload
        error = payload.get("reason") or payload.get("message") or "Witness blocked tool execution"
        super().__init__(error)


class WitnessClient:
    def __init__(
        self,
        base_url=None,
        project=None,
        session_id=None,
        timeout=None,
        fail_open=None,
        api_key=None,
        capture=None,
    ):
        self.base_url = (base_url or os.getenv("WITNESS_BASE_URL") or os.getenv("WITNESS_URL") or "http://localhost:8080").rstrip("/")
        self.project = project or os.getenv("WITNESS_PROJECT") or os.getenv("WITNESS_PROJECT_KEY")
        self.session_id = session_id or os.getenv("WITNESS_SESSION_ID")
        self.timeout = _float_env("WITNESS_TIMEOUT_SECONDS", timeout, 1.0)
        self.fail_open = _bool_env("WITNESS_FAIL_OPEN", fail_open, True)
        self.api_key = api_key or os.getenv("WITNESS_API_KEY") or os.getenv("WITNESS_PROJECT_KEY")
        self.capture = (capture or os.getenv("WITNESS_CAPTURE_MODE") or "fingerprint").lower()
        self.last_error = None

    def check_tool(
        self,
        tool_name,
        args=None,
        *,
        project=None,
        session_id=None,
        step_id=None,
        state_delta_hash=None,
        risk=None,
        idempotency_key=None,
        agent_id=None,
        user_id=None,
        resource_id=None,
        amount_cents=None,
        max_amount_cents=None,
        backup_id=None,
        recipient=None,
        allowed_domain=None,
        capability_token=None,
        duplicate_window_seconds=None,
    ):
        payload = self._payload(
            tool_name,
            args=args,
            project=project,
            session_id=session_id,
            step_id=step_id,
            state_delta_hash=state_delta_hash,
            risk=risk,
            idempotency_key=idempotency_key,
            agent_id=agent_id,
            user_id=user_id,
            resource_id=resource_id,
            amount_cents=amount_cents,
            max_amount_cents=max_amount_cents,
            backup_id=backup_id,
            recipient=recipient,
            allowed_domain=allowed_domain,
            capability_token=capability_token,
            duplicate_window_seconds=duplicate_window_seconds,
        )
        return self._post("/v1/tool/check", payload, allow_fail_open=True)

    def check_action(self, action_name, args=None, **kwargs):
        payload = self._payload(action_name, args=args, **kwargs)
        payload["action_name"] = action_name
        return self._post("/v1/action/check", payload, allow_fail_open=True)

    def record_result(
        self,
        tool_name,
        args=None,
        result=None,
        *,
        project=None,
        session_id=None,
        step_id=None,
        state_delta_hash=None,
        cost_usd=0.0,
        prompt_tokens=0,
        output_tokens=0,
        result_class=None,
        risk=None,
        idempotency_key=None,
        agent_id=None,
        user_id=None,
        resource_id=None,
        amount_cents=None,
        max_amount_cents=None,
        backup_id=None,
        recipient=None,
        allowed_domain=None,
        capability_token=None,
        duplicate_window_seconds=None,
    ):
        payload = self._payload(
            tool_name,
            args=args,
            result=result,
            result_class=result_class or _classify_result(result),
            project=project,
            session_id=session_id,
            step_id=step_id,
            state_delta_hash=state_delta_hash,
            cost_usd=cost_usd,
            prompt_tokens=prompt_tokens,
            output_tokens=output_tokens,
            risk=risk,
            idempotency_key=idempotency_key,
            agent_id=agent_id,
            user_id=user_id,
            resource_id=resource_id,
            amount_cents=amount_cents,
            max_amount_cents=max_amount_cents,
            backup_id=backup_id,
            recipient=recipient,
            allowed_domain=allowed_domain,
            capability_token=capability_token,
            duplicate_window_seconds=duplicate_window_seconds,
        )
        return self._post("/v1/tool/result", payload, allow_fail_open=True)

    def record_action_result(self, action_name, args=None, result=None, **kwargs):
        if not kwargs.get("result_class"):
            kwargs["result_class"] = _classify_result(result)
        payload = self._payload(action_name, args=args, result=result, **kwargs)
        payload["action_name"] = action_name
        return self._post("/v1/action/result", payload, allow_fail_open=True)

    def wrap_tool(
        self,
        fn=None,
        *,
        name=None,
        project=None,
        session_id=None,
        risk="read",
        idempotency_key=None,
        agent_id=None,
        user_id=None,
        resource_id=None,
        amount_cents=None,
        max_amount_cents=None,
        backup_id=None,
        recipient=None,
        allowed_domain=None,
        capability_token=None,
        duplicate_window_seconds=None,
    ):
        if fn is None:
            return lambda inner: self.wrap_tool(
                inner,
                name=name,
                project=project,
                session_id=session_id,
                risk=risk,
                idempotency_key=idempotency_key,
                agent_id=agent_id,
                user_id=user_id,
                resource_id=resource_id,
                amount_cents=amount_cents,
                max_amount_cents=max_amount_cents,
                backup_id=backup_id,
                recipient=recipient,
                allowed_domain=allowed_domain,
                capability_token=capability_token,
                duplicate_window_seconds=duplicate_window_seconds,
            )

        tool_name = name or getattr(fn, "name", None) or getattr(fn, "__name__", "tool")

        if inspect.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def async_wrapped(*args, **kwargs):
                call_args = {"args": args, "kwargs": kwargs}
                step_id = _step_id(tool_name, call_args)
                action_key = _resolve_idempotency_key(idempotency_key, tool_name, call_args, risk)
                effect = _resolve_effect_options(
                    tool_name,
                    call_args,
                    resource_id=resource_id,
                    amount_cents=amount_cents,
                    max_amount_cents=max_amount_cents,
                    backup_id=backup_id,
                    recipient=recipient,
                    allowed_domain=allowed_domain,
                    capability_token=capability_token,
                )
                check = self.check_action(
                    tool_name,
                    call_args,
                    project=project,
                    session_id=session_id,
                    step_id=step_id,
                    risk=risk,
                    idempotency_key=action_key,
                    agent_id=agent_id,
                    user_id=user_id,
                    duplicate_window_seconds=duplicate_window_seconds,
                    **effect,
                )
                if check.get("action") == "block":
                    raise WitnessLoopBlocked(check)

                try:
                    result = await fn(*args, **kwargs)
                except Exception as exc:
                    self.record_action_result(
                        tool_name,
                        call_args,
                        {"error": exc.__class__.__name__, "message": str(exc)},
                        result_class=_classify_exception(exc),
                        project=project,
                        session_id=session_id,
                        step_id=step_id,
                        risk=risk,
                        idempotency_key=action_key,
                        agent_id=agent_id,
                        user_id=user_id,
                        duplicate_window_seconds=duplicate_window_seconds,
                        **effect,
                    )
                    raise

                self.record_action_result(
                    tool_name,
                    call_args,
                    result,
                    project=project,
                    session_id=session_id,
                    step_id=step_id,
                    state_delta_hash=_hash_json(result),
                    risk=risk,
                    idempotency_key=action_key,
                    agent_id=agent_id,
                    user_id=user_id,
                    duplicate_window_seconds=duplicate_window_seconds,
                    **effect,
                )
                return result

            return async_wrapped

        @functools.wraps(fn)
        def wrapped(*args, **kwargs):
            call_args = {"args": args, "kwargs": kwargs}
            step_id = _step_id(tool_name, call_args)
            action_key = _resolve_idempotency_key(idempotency_key, tool_name, call_args, risk)
            effect = _resolve_effect_options(
                tool_name,
                call_args,
                resource_id=resource_id,
                amount_cents=amount_cents,
                max_amount_cents=max_amount_cents,
                backup_id=backup_id,
                recipient=recipient,
                allowed_domain=allowed_domain,
                capability_token=capability_token,
            )
            check = self.check_action(
                tool_name,
                call_args,
                project=project,
                session_id=session_id,
                step_id=step_id,
                risk=risk,
                idempotency_key=action_key,
                agent_id=agent_id,
                user_id=user_id,
                duplicate_window_seconds=duplicate_window_seconds,
                **effect,
            )
            if check.get("action") == "block":
                raise WitnessLoopBlocked(check)

            try:
                result = fn(*args, **kwargs)
            except Exception as exc:
                self.record_action_result(
                    tool_name,
                    call_args,
                    {"error": exc.__class__.__name__, "message": str(exc)},
                    result_class=_classify_exception(exc),
                    project=project,
                    session_id=session_id,
                    step_id=step_id,
                    risk=risk,
                    idempotency_key=action_key,
                    agent_id=agent_id,
                    user_id=user_id,
                    duplicate_window_seconds=duplicate_window_seconds,
                    **effect,
                )
                raise

            self.record_action_result(
                tool_name,
                call_args,
                result,
                project=project,
                session_id=session_id,
                step_id=step_id,
                state_delta_hash=_hash_json(result),
                risk=risk,
                idempotency_key=action_key,
                agent_id=agent_id,
                user_id=user_id,
                duplicate_window_seconds=duplicate_window_seconds,
                **effect,
            )
            return result

        return wrapped

    def wrap_action(self, fn=None, **kwargs):
        return self.wrap_tool(fn, **kwargs)

    def action(self, fn=None, **kwargs):
        return self.wrap_action(fn, **kwargs)

    def doctor(self):
        report = {"base_url": self.base_url, "checks": []}
        health = self._get("/healthz", allow_fail_open=False)
        report["checks"].append({
            "name": "healthz",
            "ok": bool(health.get("ok") or health.get("status") == "healthy"),
            "detail": health.get("reason", ""),
        })
        check = self.check_tool("witness_doctor_noop", {"probe": True}, session_id="witness-doctor")
        report["checks"].append({"name": "tool_check", "ok": check.get("action") in ("allow", "warn"), "detail": check.get("reason", "")})
        result = self.record_result(
            "witness_doctor_noop",
            {"probe": True},
            {"ok": True},
            session_id="witness-doctor",
            state_delta_hash="witness-doctor-ok",
        )
        report["checks"].append({"name": "tool_result", "ok": result.get("action") in ("allow", "warn"), "detail": result.get("reason", "")})
        report["ok"] = all(check["ok"] for check in report["checks"])
        return report

    def _payload(
        self,
        tool_name,
        *,
        args=None,
        result=None,
        result_class=None,
        project=None,
        session_id=None,
        step_id=None,
        state_delta_hash=None,
        cost_usd=0.0,
        prompt_tokens=0,
        output_tokens=0,
        risk=None,
        idempotency_key=None,
        agent_id=None,
        user_id=None,
        resource_id=None,
        amount_cents=None,
        max_amount_cents=None,
        backup_id=None,
        recipient=None,
        allowed_domain=None,
        capability_token=None,
        duplicate_window_seconds=None,
    ):
        raw_args = args if args is not None else {}
        payload = {
            "project": project or self.project or "unknown",
            "session_id": session_id or self.session_id or "",
            "step_id": step_id or "",
            "action_name": tool_name,
            "tool_name": tool_name,
            "args": self._capture_value(raw_args),
            "state_delta_hash": state_delta_hash or "",
            "cost_usd": cost_usd,
            "prompt_tokens": prompt_tokens,
            "output_tokens": output_tokens,
            "unix_millis": int(time.time() * 1000),
        }
        if risk:
            payload["action_risk"] = risk
        if idempotency_key:
            payload["idempotency_key"] = idempotency_key
        if agent_id:
            payload["agent_id"] = agent_id
        if user_id:
            payload["user_id"] = user_id
        if resource_id:
            payload["resource_id"] = resource_id
        if amount_cents is not None:
            payload["amount_cents"] = int(amount_cents)
        if max_amount_cents is not None:
            payload["max_amount_cents"] = int(max_amount_cents)
        if backup_id:
            payload["backup_id"] = backup_id
        if recipient:
            payload["recipient"] = recipient
        if allowed_domain:
            payload["allowed_domain"] = allowed_domain
        if capability_token:
            payload["capability_token"] = capability_token
        if duplicate_window_seconds:
            payload["duplicate_window_seconds"] = int(duplicate_window_seconds)
        if result is not None:
            payload["result"] = self._capture_value(result)
        if result_class:
            payload["result_class"] = result_class
        return payload

    def _capture_value(self, value):
        if self.capture == "raw":
            return value
        return {
            "witness_capture": "fingerprint",
            "sha256": _hash_json(value),
            "type": type(value).__name__,
        }

    def _get(self, path, *, allow_fail_open):
        req = urllib.request.Request(self.base_url + path, headers=self._headers(), method="GET")
        return self._send(req, allow_fail_open=allow_fail_open)

    def _post(self, path, payload, *, allow_fail_open):
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True, default=str).encode("utf-8")
        req = urllib.request.Request(
            self.base_url + path,
            data=body,
            headers={**self._headers(), "Content-Type": "application/json", "X-Project": payload.get("project", "unknown")},
            method="POST",
        )
        return self._send(req, allow_fail_open=allow_fail_open)

    def _send(self, req, *, allow_fail_open):
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = resp.read().decode("utf-8")
                if not data:
                    return {"ok": True, "action": "allow"}
                return json.loads(data)
        except urllib.error.HTTPError as exc:
            data = exc.read().decode("utf-8")
            try:
                payload = json.loads(data)
            except json.JSONDecodeError:
                payload = {"action": "block", "reason": data}
            if exc.code == 429:
                payload.setdefault("action", "block")
                raise WitnessLoopBlocked(payload)
            if allow_fail_open and self.fail_open:
                return self._fail_open(exc)
            raise
        except (urllib.error.URLError, TimeoutError, socket.timeout, json.JSONDecodeError, OSError) as exc:
            if allow_fail_open and self.fail_open:
                return self._fail_open(exc)
            raise

    def _fail_open(self, exc):
        self.last_error = exc
        return {
            "action": "allow",
            "fail_open": True,
            "reason": "Witness unavailable; allowed by fail-open SDK policy",
            "error": exc.__class__.__name__,
        }

    def _headers(self):
        headers = {"User-Agent": "witness-agent-python/0"}
        if self.api_key:
            headers["X-Witness-API-Key"] = self.api_key
        return headers


def wrap_tool(fn=None, **kwargs):
    client = kwargs.pop("client", None)
    tool_options = {}
    for key in (
        "name",
        "project",
        "session_id",
        "risk",
        "idempotency_key",
        "agent_id",
        "user_id",
        "resource_id",
        "amount_cents",
        "max_amount_cents",
        "backup_id",
        "recipient",
        "allowed_domain",
        "capability_token",
        "duplicate_window_seconds",
    ):
        if key in kwargs:
            tool_options[key] = kwargs.pop(key)
    client = client or WitnessClient(**kwargs)
    return client.wrap_tool(fn, **tool_options)


def wrap_action(fn=None, **kwargs):
    return wrap_tool(fn, **kwargs)


def action(fn=None, **kwargs):
    return wrap_action(fn, **kwargs)


def _step_id(tool_name, payload):
    return tool_name + ":" + _hash_json(payload)[:16]


def _resolve_idempotency_key(value, tool_name, call_args, risk):
    if callable(value):
        value = value(call_args)
    if value:
        return str(value)
    if str(risk or "read").lower() in ("read", "readonly", "read_only", "low"):
        return ""
    return f"{tool_name}:{_hash_json(call_args)}"


def _resolve_effect_options(tool_name, call_args, **options):
    resolved = {}
    for key, value in options.items():
        if value is None:
            continue
        resolved[key] = _resolve_option(value, tool_name, call_args)
    return resolved


def _resolve_option(value, tool_name, call_args):
    if callable(value):
        try:
            return value(call_args)
        except TypeError:
            return value(tool_name, call_args)
    return value


def _hash_json(value):
    data = json.dumps(value, separators=(",", ":"), sort_keys=True, default=str)
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _bool_env(name, value, default):
    if value is not None:
        return bool(value)
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.lower() in ("1", "true", "yes", "on")


def _float_env(name, value, default):
    if value is not None:
        return float(value)
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _classify_exception(exc):
    text = f"{exc.__class__.__name__} {exc}".lower()
    if "timeout" in text or "deadline" in text:
        return "timeout"
    if "permission" in text or "unauthorized" in text or "forbidden" in text:
        return "permission_error"
    if "not found" in text or "filenotfound" in text or "no such file" in text:
        return "not_found"
    if "schema" in text or "validation" in text or "json" in text:
        return "schema_error"
    return "unknown_error"


def _classify_result(result):
    if result is None:
        return "empty"
    text = json.dumps(result, separators=(",", ":"), sort_keys=True, default=str).lower()
    if text in ("", "null", "{}", "[]"):
        return "empty"
    if "rate limit" in text or "rate_limit" in text or "too many requests" in text or "429" in text:
        return "rate_limited"
    if "timeout" in text or "timed out" in text or "deadline exceeded" in text:
        return "timeout"
    if "not_found" in text or "not found" in text or "no such file" in text or "does not exist" in text or "404" in text:
        return "not_found"
    if "permission" in text or "unauthorized" in text or "forbidden" in text or "access denied" in text:
        return "permission_error"
    if "schema" in text or "invalid json" in text or "parse error" in text or "validation" in text:
        return "schema_error"
    if "\"status\":\"pending\"" in text or "\"status\":\"queued\"" in text or "\"status\":\"running\"" in text:
        return "pending"
    if "error" in text or "failed" in text or "exception" in text:
        return "unknown_error"
    return "success"
