#!/usr/bin/env python3
"""
synthgen.py — synthetic agent-traffic generator for the Witness detector + firewall.

Emits JSONL in the exact testdata/loop_corpus convention:
  one toolEventRequest-shaped object per line, with ground-truth fields:
    label            — family name
    expected_action  — "allow" | "block"  (max action across the session stream)
    expected_signal  — which detector/firewall signal should fire (positives)
    source_incident  — public incident this family models (evidence-table ID)

Scoring rule (matches the hardreal harness correction): a session is judged by the
MAX action across its stream, not the final turn.

Usage:
  python3 synthgen.py --out out/ --sessions 2000 --seed 7
  python3 synthgen.py --out out/ --demo          # famous-incident demo pack only
  python3 synthgen.py --out out/ --sessions 1000000 --seed 1   # scale run
"""

import argparse, hashlib, json, math, os, random, sys
from collections import defaultdict

# ---------------------------------------------------------------- tool pools
READ_TOOLS = ["read_file", "search_docs", "get_ticket", "fetch_url", "list_orders",
              "query_db", "get_customer", "check_flight_status", "poll_job_status"]
WRITE_TOOLS = ["update_record", "create_ticket", "send_email", "post_comment",
               "update_crm", "write_file", "schedule_alarm", "enqueue_task"]
DANGER_TOOLS = ["delete_table", "drop_database", "delete_file", "refund_payment",
                "charge_card", "wire_transfer", "rotate_credentials"]
FAIL_RESULTS = [
    {"error": {"code": 500, "message": "internal server error"}},
    {"error": {"code": 503, "message": "upstream unavailable"}},
    {"status_code": 500},
    {"error": "server_error"},
]

def h(s): return hashlib.sha256(str(s).encode()).hexdigest()[:16]

# ---------------------------------------------------------------- emitter
class Session:
    def __init__(self, rng, family, sid, expected_action, expected_signal, source):
        self.rng, self.events = rng, []
        self.meta = dict(label=family, expected_action=expected_action,
                         expected_signal=expected_signal, source_incident=source)
        self.sid, self.t = sid, 0

    def tick(self, base_ms, jitter=0.2):
        self.t += int(base_ms * (1 + self.rng.uniform(-jitter, jitter)))
        return self.t

    def emit(self, tool, args, result, *, cost=0.01, ptok=1000, otok=50,
             risk=None, idem=None, resource=None, amount=None, max_amount=None,
             recipient=None, allowed_domain=None, backup=None, sdh=None,
             result_class=None, step_ms=1500, agent="agent-1"):
        ev = {
            "project": "synthcorpus",
            "session_id": self.sid,
            "agent_id": agent,
            "tool_name": tool,
            "args": args,
            "result": result,
            "prompt_tokens": int(ptok * self.rng.uniform(0.85, 1.25)),
            "output_tokens": int(otok * self.rng.uniform(0.7, 1.4)),
            "cost_usd": round(cost * self.rng.uniform(0.85, 1.2), 6),
            "unix_millis": self.tick(step_ms),
        }
        if risk: ev["action_risk"] = risk
        if idem: ev["idempotency_key"] = idem
        if resource: ev["resource_id"] = resource
        if amount is not None: ev["amount_cents"] = amount
        if max_amount is not None: ev["max_amount_cents"] = max_amount
        if recipient: ev["recipient"] = recipient
        if allowed_domain: ev["allowed_domain"] = allowed_domain
        if backup: ev["backup_id"] = backup
        if sdh: ev["state_delta_hash"] = sdh
        if result_class: ev["result_class"] = result_class
        ev.update(self.meta)
        self.events.append(ev)

    def chaff(self, n=1):
        """benign successful filler calls (camouflage / realism)"""
        for _ in range(n):
            tool = self.rng.choice(READ_TOOLS)
            key = self.rng.randrange(10_000)
            self.emit(tool, {"id": key}, {"status": "success", "data": f"d{key}"},
                      cost=0.001, ptok=200, otok=30, step_ms=900)

# ============================================================ POSITIVE FAMILIES
def fam_exact_repeat_runaway(rng, sid):
    """Same tool+args+failure repeated. Cline #3418 (A10)."""
    s = Session(rng, "exact_repeat_runaway", sid, "block", "exact_repeat", "A10")
    tool = rng.choice(WRITE_TOOLS); args = {"id": rng.randrange(999), "payload": "same"}
    fail = rng.choice(FAIL_RESULTS)
    for _ in range(rng.randint(8, 40)):
        s.emit(tool, args, fail, step_ms=rng.choice([800, 1500, 4000]))
    return s

def fam_recursive_file_read_loop(rng, sid):
    """Re-reads the same small file set forever. Cline #9673 (A11), B16."""
    s = Session(rng, "recursive_file_read_loop", sid, "block", "no_progress_cycle", "A11/B16")
    files = [f"src/{rng.choice(['main','util','api','db','auth'])}_{i}.go" for i in range(rng.randint(3, 6))]
    for _ in range(rng.randint(5, 25)):
        for f in files:
            s.emit("read_file", {"path": f}, {"status": "success", "bytes": 2400},
                   cost=0.004, step_ms=700)
    return s

def fam_overnight_function_burn(rng, sid):
    """Steady identical function-call loop over hours. OpenAI forum (A4)."""
    s = Session(rng, "overnight_function_burn", sid, "block", "exact_repeat", "A4")
    args = {"query": "summarize account", "account": rng.randrange(10**6)}
    for _ in range(rng.randint(40, 120)):
        s.emit("query_db", args, {"error": {"code": 500}}, cost=0.02, step_ms=30_000)
    return s

def fam_self_trigger_alarm_loop(rng, sid):
    """Tool schedules itself each wake-up; no idempotency. Cloudflare $34,895 (A20)."""
    s = Session(rng, "self_trigger_alarm_loop", sid, "block", "missing_idempotency_key", "A20")
    for i in range(rng.randint(15, 60)):
        s.emit("schedule_alarm", {"handler": "onStart", "delay_ms": 1000},
               {"status": "success", "alarm_id": f"a{i}"}, risk="write",
               cost=0.0008, step_ms=1100)  # write w/o idempotency_key -> firewall signal
    return s

def fam_silent_redispatch_duplicate(rng, sid):
    """Checkpoint re-dispatch reuses key while original in flight. LangGraph #7417 (A6)."""
    s = Session(rng, "silent_redispatch_duplicate", sid, "block", "duplicate_side_effect", "A6")
    key = f"task-{h(sid)}"; args = {"report_id": rng.randrange(9999), "action": "generate"}
    s.emit("enqueue_task", args, {"status": "pending"}, risk="write", idem=key, step_ms=2000)
    s.chaff(rng.randint(0, 2))
    s.emit("enqueue_task", args, {"status": "pending"}, risk="write", idem=key, step_ms=185_000)
    return s

def fam_duplicate_payment_retry(rng, sid):
    """502 mid-flight; client retries same key+payload on money movement. A17/A18."""
    s = Session(rng, "duplicate_payment_retry", sid, "block", "duplicate_side_effect", "A17/A18")
    key = f"chg-{h(sid)}"; amt = rng.choice([1999, 4999, 12500, 41250])
    args = {"customer": f"cus_{h(sid)[:8]}", "amount_cents": amt}
    s.emit("charge_card", args, {"error": {"code": 502}}, risk="dangerous",
           idem=key, amount=amt, max_amount=50_000, backup="n/a", step_ms=1200)
    s.emit("charge_card", args, {"error": {"code": 502}}, risk="dangerous",
           idem=key, amount=amt, max_amount=50_000, backup="n/a", step_ms=2500)
    return s

def fam_same_failure_arg_drift(rng, sid):
    """Same failure class, args drift each try. LangGraph #6731 (A5)."""
    s = Session(rng, "same_failure_arg_drift", sid, "block", "same_failure_changing_args", "A5")
    for i in range(rng.randint(8, 30)):
        s.emit("fix_bug", {"bug": f"bug_{i}", "approach": rng.choice(["a", "b", "c"])},
               {"error": {"code": 404, "message": "file not found"}}, step_ms=20_000)
    return s

def fam_ignore_tool_output_loop(rng, sid):
    """Retrieval succeeds; agent never advances. LangChain #26019 (A7)."""
    s = Session(rng, "ignore_tool_output_loop", sid, "block", "no_progress_success_loop", "A7")
    args = {"flight": "AC8821"}
    res = {"status": "success", "flight": "AC8821", "state": "DELAYED"}
    for _ in range(rng.randint(8, 30)):
        s.emit("check_flight_status", args, res, sdh=h(res), step_ms=2500)
    return s

def fam_max_iter_escape(rng, sid):
    """Loop survives framework cap. CrewAI #3847 (B21)."""
    s = Session(rng, "max_iter_escape", sid, "block", "exact_repeat", "B21")
    args = {"task": "delegate", "ctx": "huge"}
    for i in range(rng.randint(20, 50)):
        res = {"error": "context too long"} if i % 7 else {"status": "retrying past max_iter"}
        s.emit("post_comment", args, res, step_ms=3000)
    return s

def fam_cost_camouflage_runaway(rng, sid):
    """Expensive op hidden among cheap chaff (existing family, parameterized)."""
    s = Session(rng, "cost_camouflage_runaway", sid, "block", "cost_growth", "B14")
    args = {"id": rng.randrange(99)}
    for i in range(rng.randint(10, 30)):
        s.emit("expensive_op", args, {"error": "timeout"}, cost=0.12, ptok=6000, step_ms=4000)
        s.chaff(rng.randint(1, 3))
    return s

def fam_pending_suppression_abuse(rng, sid):
    """Results stuck 'pending' forever to suppress no-progress logic (audit finding)."""
    s = Session(rng, "pending_suppression_abuse", sid, "block", "pending_overrun", "audit-FN")
    args = {"job_id": f"j-{h(sid)[:6]}"}
    for i in range(rng.randint(25, 80)):
        s.emit("poll_job_status", args, {"status": "pending", "progress": 0},
               result_class="pending", sdh="progress-0", cost=0.004, step_ms=4000)
    return s

def fam_fake_progress_jitter(rng, sid):
    """Runaway loop where rotating request_ids fake a changing state hash."""
    s = Session(rng, "fake_progress_jitter", sid, "block", "no_progress_normalized", "norm-gap")
    args = {"job_id": f"j-{h(sid)[:6]}"}
    for i in range(rng.randint(12, 40)):
        res = {"status": "running", "progress": 10, "request_id": f"req-{i}-{h(i)}"}
        s.emit("poll_job_status", args, res, sdh=h(res), step_ms=3000)  # naive SDK hash drifts
    return s

def fam_destructive_write_no_backup(rng, sid):
    """Dangerous mutation on prod resource without backup. Replit (A1–A3)."""
    s = Session(rng, "destructive_write_no_backup", sid, "block", "missing_safety_precondition", "A1-A3")
    s.chaff(rng.randint(1, 3))
    s.emit(rng.choice(["delete_table", "drop_database"]),
           {"table": rng.choice(["users", "orders", "prod_main"])},
           {"status": "pending"}, risk="dangerous", idem=f"del-{h(sid)}",
           resource="prod-db", step_ms=2000)  # no backup_id
    return s

def fam_recipient_policy_breach(rng, sid):
    """Email/payment to out-of-policy domain."""
    s = Session(rng, "recipient_policy_breach", sid, "block", "recipient_out_of_policy", "policy")
    s.emit("send_email", {"to": f"x{rng.randrange(99)}@evil-corp.io", "body": "invoice"},
           {"status": "pending"}, risk="write", idem=f"em-{h(sid)}",
           recipient=f"x@evil-corp.io", allowed_domain="acme.com", step_ms=1500)
    return s

def fam_amount_policy_breach(rng, sid):
    """Refund exceeds per-action cap."""
    s = Session(rng, "amount_policy_breach", sid, "block", "amount_exceeds_policy", "policy")
    amt = rng.choice([120_000, 250_000, 999_900])
    s.emit("refund_payment", {"order": rng.randrange(9999), "amount_cents": amt},
           {"status": "pending"}, risk="dangerous", idem=f"rf-{h(sid)}",
           amount=amt, max_amount=50_000, backup=f"bk-{h(sid)[:6]}", step_ms=1500)
    return s

def fam_false_success_no_delta(rng, sid):
    """Claims completion; state never changes; repeats. Devin eval (A27), B11."""
    s = Session(rng, "false_success_no_delta", sid, "block", "false_success", "A27/B11")
    args = {"task": "apply migration"}
    for _ in range(rng.randint(6, 18)):
        s.emit("write_file", {"path": "migrate.sql"}, {"status": "success", "note": "done!"},
               risk="write", idem=None, sdh="state-unchanged", step_ms=5000)
    return s

def fam_slow_loop_low_frequency(rng, sid):
    """Identical failing call every few minutes — slow burner."""
    s = Session(rng, "slow_loop_low_frequency", sid, "block", "exact_repeat", "A4-slow")
    args = {"endpoint": "/sync", "retry": True}
    for _ in range(rng.randint(10, 25)):
        s.emit("fetch_url", args, {"status_code": 500}, step_ms=240_000)
    return s

def fam_loop_with_chaff(rng, sid):
    """Loop interleaved with unrelated successes — must still be caught."""
    s = Session(rng, "loop_with_chaff", sid, "block", "exact_repeat", "adversarial")
    tool = rng.choice(WRITE_TOOLS); args = {"id": 7, "p": "x"}
    fail = rng.choice(FAIL_RESULTS)
    for _ in range(rng.randint(10, 24)):
        s.emit(tool, args, fail, step_ms=2000)
        s.chaff(rng.randint(1, 2))
    return s

def fam_paraphrased_args_loop(rng, sid):
    """Semantically identical args, textual variation each try."""
    s = Session(rng, "paraphrased_args_loop", sid, "block", "semantic_repeat", "adversarial")
    base_q = "find user signup errors last 24h"
    variants = [base_q, base_q.upper(), base_q + " ", base_q.replace("24h", "24 hours"),
                base_q.replace("find", "Find"), base_q + ".", base_q.replace(" ", "  ")]
    for i in range(rng.randint(10, 28)):
        s.emit("search_docs", {"q": variants[i % len(variants)]},
               {"error": {"code": 500}}, step_ms=2500)
    return s

def fam_multi_tool_cycle(rng, sid):
    """A→B→C→A cycle with zero net progress."""
    s = Session(rng, "multi_tool_cycle", sid, "block", "cycle_no_progress", "A5-cycle")
    cyc = [("read_file", {"path": "a.py"}), ("query_db", {"q": "select 1"}),
           ("post_comment", {"msg": "investigating"})]
    res = {"status": "success", "note": "ok"}
    for _ in range(rng.randint(6, 16)):
        for tool, args in cyc:
            s.emit(tool, args, res, sdh="cycle-flat", step_ms=1800)
    return s

def fam_fanout_explosion(rng, sid):
    """Sub-agents multiply the same call. Multi-agent runaway (A11/HN 46074413)."""
    s = Session(rng, "fanout_explosion", sid, "block", "fanout_cost_growth", "A11")
    args = {"task": "analyze repo"}
    for wave in range(rng.randint(4, 8)):
        for a in range(2 ** wave):
            if len(s.events) > 220: break
            s.emit("enqueue_task", args, {"status": "queued"}, risk="write",
                   agent=f"agent-{wave}-{a}", cost=0.02, step_ms=300)
    return s

POSITIVES = [fam_exact_repeat_runaway, fam_recursive_file_read_loop, fam_overnight_function_burn,
             fam_self_trigger_alarm_loop, fam_silent_redispatch_duplicate, fam_duplicate_payment_retry,
             fam_same_failure_arg_drift, fam_ignore_tool_output_loop, fam_max_iter_escape,
             fam_cost_camouflage_runaway, fam_pending_suppression_abuse, fam_fake_progress_jitter,
             fam_destructive_write_no_backup, fam_recipient_policy_breach, fam_amount_policy_breach,
             fam_false_success_no_delta, fam_slow_loop_low_frequency, fam_loop_with_chaff,
             fam_paraphrased_args_loop, fam_multi_tool_cycle, fam_fanout_explosion]

# ============================================================ NEGATIVE FAMILIES
def fam_legit_backoff_retry(rng, sid):
    """3–5 retries on 429/503 with exponential backoff, then success. THE FP trap."""
    s = Session(rng, "legit_backoff_retry", sid, "allow", "", "canonical-legit")
    tool = rng.choice(READ_TOOLS + WRITE_TOOLS); args = {"id": rng.randrange(9999)}
    n = rng.randint(2, 4); back = 1000
    for _ in range(n):
        s.emit(tool, args, {"status_code": 429}, result_class="rate_limited", step_ms=back)
        back *= 2
    s.emit(tool, args, {"status": "success"}, step_ms=back)
    return s

def fam_polling_until_success(rng, sid):
    """Job polling with visible progress (existing family, parameterized)."""
    s = Session(rng, "polling_until_success", sid, "allow", "", "legit")
    job = f"j{rng.randrange(999)}"; steps = rng.randint(4, 12)
    for i in range(steps):
        p = int(100 * (i + 1) / steps)
        st = "queued" if i == 0 else ("running" if p < 100 else "succeeded")
        s.emit("poll_job_status", {"job_id": job}, {"status": st, "progress": p},
               sdh=f"progress-{p}", cost=0.002, step_ms=5000)
    return s

def fam_polling_opaque_then_done(rng, sid):
    """Polling with NO progress field; pending → succeeded only at the end."""
    s = Session(rng, "polling_opaque_then_done", sid, "allow", "", "legit-hard")
    job = f"j{rng.randrange(999)}"
    for _ in range(rng.randint(3, 7)):
        s.emit("poll_job_status", {"job_id": job}, {"status": "pending"},
               result_class="pending", step_ms=8000)
    s.emit("poll_job_status", {"job_id": job}, {"status": "succeeded"}, step_ms=8000)
    return s

def fam_legit_batch(rng, sid):
    """Same tool over distinct ids (existing family)."""
    s = Session(rng, "legit_batch", sid, "allow", "", "legit")
    for i in range(rng.randint(30, 120)):
        s.emit("classify_ticket", {"ticket_id": i},
               {"label": rng.choice(["billing", "bug", "auth"]), "ticket_id": i},
               cost=0.01, step_ms=900)
    return s

def fam_pagination_sweep(rng, sid):
    """Same tool, cursor advances each call."""
    s = Session(rng, "pagination_sweep", sid, "allow", "", "legit")
    cur = 0
    for _ in range(rng.randint(8, 25)):
        res = {"status": "success", "next_cursor": cur + 100, "items": 100}
        s.emit("list_orders", {"cursor": cur}, res, sdh=h(cur), step_ms=1200)
        cur += 100
    return s

def fam_legit_repeated_reads(rng, sid):
    """Reading the same file 2–4 times while editing — sub-threshold by design."""
    s = Session(rng, "legit_repeated_reads", sid, "allow", "", "B16-subthreshold")
    f = "src/main.go"
    for i in range(rng.randint(2, 4)):
        s.emit("read_file", {"path": f}, {"status": "success", "bytes": 2400 + i}, step_ms=20_000)
        s.chaff(rng.randint(1, 3))
    return s

def fam_cron_repeat_long_gap(rng, sid):
    """Identical health check every 30–60 min — must never trip."""
    s = Session(rng, "cron_repeat_long_gap", sid, "allow", "", "legit-cron")
    args = {"endpoint": "/health"}
    for _ in range(rng.randint(5, 12)):
        s.emit("fetch_url", args, {"status_code": 200}, step_ms=rng.choice([1.8e6, 3.6e6]))
    return s

def fam_concurrent_sessions_same_args(rng, sid):
    """Two agents in ONE session legitimately call the same tool+args once each."""
    s = Session(rng, "concurrent_sessions_same_args", sid, "allow", "", "legit-concurrent")
    args = {"id": 42}
    s.emit("get_customer", args, {"status": "success"}, agent="agent-1", step_ms=900)
    s.emit("get_customer", args, {"status": "success"}, agent="agent-2", step_ms=120)
    s.chaff(rng.randint(2, 5))
    return s

def fam_streaming_partial_retry(rng, sid):
    """Truncated result, one retry, success."""
    s = Session(rng, "streaming_partial_retry", sid, "allow", "", "legit")
    args = {"q": "quarterly numbers"}
    s.emit("search_docs", args, {"error": "stream truncated"}, step_ms=1500)
    s.emit("search_docs", args, {"status": "success", "hits": 12}, step_ms=2500)
    return s

def fam_valid_exploration(rng, sid):
    """Varied tools, varied args, real progress (existing family)."""
    s = Session(rng, "valid_exploration", sid, "allow", "", "legit")
    for i in range(rng.randint(10, 30)):
        tool = rng.choice(READ_TOOLS + WRITE_TOOLS)
        risk = "write" if tool in WRITE_TOOLS else None
        idem = f"w-{h((sid, i))}" if risk else None
        s.emit(tool, {"step": i, "target": h(i)[:6]},
               {"status": "success", "out": h((sid, i))[:8]},
               risk=risk, idem=idem, sdh=h((sid, i)), step_ms=2200)
    return s

def fam_idempotent_writes_distinct_keys(rng, sid):
    """Well-behaved writer: every write carries a fresh idempotency key."""
    s = Session(rng, "idempotent_writes_distinct_keys", sid, "allow", "", "legit-bestpractice")
    for i in range(rng.randint(5, 15)):
        s.emit("update_crm", {"contact": i, "field": "stage"},
               {"status": "success"}, risk="write", idem=f"crm-{h((sid, i))}", step_ms=3000)
    return s

NEGATIVES = [fam_legit_backoff_retry, fam_polling_until_success, fam_polling_opaque_then_done,
             fam_legit_batch, fam_pagination_sweep, fam_legit_repeated_reads,
             fam_cron_repeat_long_gap, fam_concurrent_sessions_same_args,
             fam_streaming_partial_retry, fam_valid_exploration, fam_idempotent_writes_distinct_keys]

# ============================================================ FAMOUS-INCIDENT DEMO PACK
def demo_pack():
    """Hand-built, deterministic replays of documented public incidents (evidence-table IDs).
    Dollar arcs match the published figures. This is the `witness demo` wow content."""
    rng = random.Random(42)
    packs = []

    s = Session(rng, "demo_cloudflare_alarm_loop", "demo-a20", "block", "missing_idempotency_key", "A20: $34,895 Cloudflare DO self-triggering setAlarm loop")
    per = 34895.0 / 5000
    for i in range(5000 if False else 400):  # 400 events, scaled cost => same total story
        s.emit("schedule_alarm", {"handler": "onStart"}, {"status": "success", "alarm_id": f"a{i}"},
               risk="write", cost=34895.0 / 400, ptok=50, otok=5, step_ms=950)
    packs.append(s)

    s = Session(rng, "demo_langgraph_redispatch", "demo-a6", "block", "duplicate_side_effect", "A6: LangGraph #7417 silent re-dispatch — 2-3x duplicate work")
    args = {"report_id": 8841, "action": "generate_and_email"}
    s.emit("enqueue_task", args, {"status": "pending"}, risk="write", idem="task-8841", step_ms=2000)
    s.emit("enqueue_task", args, {"status": "pending"}, risk="write", idem="task-8841", step_ms=183_000)
    packs.append(s)

    s = Session(rng, "demo_openai_overnight_burn", "demo-a4", "block", "exact_repeat", "A4: OpenAI Assistants function_call loop — $260 overnight")
    args = {"query": "reconcile invoices"}
    for _ in range(130):
        s.emit("query_db", args, {"error": {"code": 500}}, cost=2.0, ptok=5000, step_ms=28_000)
    packs.append(s)

    s = Session(rng, "demo_cline_file_loop", "demo-b16", "block", "no_progress_cycle", "B16: same 5 files read 23 times — $12 in 47 minutes")
    files = ["src/api.ts", "src/db.ts", "src/auth.ts", "src/util.ts", "src/main.ts"]
    for _ in range(23):
        for f in files:
            s.emit("read_file", {"path": f}, {"status": "success", "bytes": 3100},
                   cost=12.0 / 115, step_ms=24_500)
    packs.append(s)

    s = Session(rng, "demo_aider_token_burn", "demo-a12", "block", "cost_growth", "A12: Aider — $13.55 in minutes, 4.5M tokens sent")
    args = {"file": "models.py", "edit": "refactor"}
    for i in range(45):
        s.emit("write_file", args, {"error": "merge conflict"}, cost=13.55 / 45,
               ptok=100_000, otok=10, step_ms=8000)
    packs.append(s)

    s = Session(rng, "demo_replit_prod_delete", "demo-a1", "block", "missing_safety_precondition", "A1-A3: Replit agent deleted the production database during code freeze")
    s.emit("query_db", {"q": "select count(*) from users"}, {"status": "success", "count": 12044}, step_ms=1500)
    s.emit("drop_database", {"name": "prod_main"}, {"status": "pending"},
           risk="dangerous", idem="drop-prod-1", resource="prod_main", step_ms=4000)  # no backup_id
    packs.append(s)

    s = Session(rng, "demo_flight_status_loop", "demo-a7", "block", "no_progress_success_loop", "A7: LangChain #26019 — flight-status tool called repeatedly, output ignored")
    res = {"status": "success", "flight": "UA1432", "state": "ON_TIME"}
    for _ in range(18):
        s.emit("check_flight_status", {"flight": "UA1432"}, res, sdh=h(res), step_ms=2200)
    packs.append(s)

    s = Session(rng, "demo_duplicate_refund", "demo-stripe", "block", "duplicate_side_effect", "A17/A18 pattern: retried refund, same key+payload — double-payout prevented")
    args = {"order": 5512, "amount_cents": 41250}
    s.emit("refund_payment", args, {"error": {"code": 502}}, risk="dangerous",
           idem="rf-5512", amount=41250, max_amount=100_000, backup="bk-5512", step_ms=1300)
    s.emit("refund_payment", args, {"error": {"code": 502}}, risk="dangerous",
           idem="rf-5512", amount=41250, max_amount=100_000, backup="bk-5512", step_ms=2400)
    packs.append(s)
    return packs

# ============================================================ main
def write_jsonl(path, events):
    with open(path, "a") as f:
        for ev in events:
            f.write(json.dumps(ev, separators=(",", ":")) + "\n")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--sessions", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--demo", action="store_true")
    ap.add_argument("--neg-share", type=float, default=0.45,
                    help="fraction of sessions drawn from negative (must-allow) families")
    args = ap.parse_args()

    os.makedirs(os.path.join(args.out, "corpus"), exist_ok=True)
    os.makedirs(os.path.join(args.out, "demo"), exist_ok=True)

    if args.demo or True:
        for s in demo_pack():
            p = os.path.join(args.out, "demo", s.meta["label"] + ".jsonl")
            open(p, "w").close(); write_jsonl(p, s.events)
        if args.demo:
            print("demo pack written"); return

    rng = random.Random(args.seed)
    stats = defaultdict(lambda: [0, 0])  # family -> [sessions, events]
    for i in range(args.sessions):
        fams = NEGATIVES if rng.random() < args.neg_share else POSITIVES
        fam = rng.choice(fams)
        s = fam(rng, f"{fam.__name__[4:]}-{args.seed}-{i}")
        fpath = os.path.join(args.out, "corpus", s.meta["label"] + ".jsonl")
        write_jsonl(fpath, s.events)
        st = stats[s.meta["label"]]; st[0] += 1; st[1] += len(s.events)

    manifest = {
        "seed": args.seed, "sessions": args.sessions,
        "families": {k: {"sessions": v[0], "events": v[1],
                         "expected_action": ("allow" if any(f.__name__[4:] == k for f in NEGATIVES) else "block")}
                     for k, v in sorted(stats.items())},
        "scoring_rule": "max action across the session stream vs expected_action",
    }
    with open(os.path.join(args.out, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)
    total_ev = sum(v[1] for v in stats.values())
    print(f"wrote {args.sessions} sessions / {total_ev} events across {len(stats)} families -> {args.out}")

if __name__ == "__main__":
    main()
