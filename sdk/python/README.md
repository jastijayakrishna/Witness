# HubbleOps Agent Python SDK

Fail-open action firewall wrapper for Python agents.

```python
from hubbleops_agent import HubbleOpsClient

hubbleops = HubbleOpsClient(base_url="https://YOUR_HUBBLEOPS_ENDPOINT", project="prod")

@hubbleops.action(
    risk="money_movement",
    idempotency_key=lambda call: f"refund:{call['args'][0]}:{call['args'][1]}",
    resource_id=lambda call: call["args"][0],
    amount_cents=lambda call: call["args"][1],
    max_amount_cents=5000,
)
def refund_customer(invoice_id: str, amount_cents: int):
    return payments.refund(invoice_id, amount_cents)
```

HubbleOps checks the action before execution, blocks duplicate or over-limit side effects, records the result after execution, and returns fail-open if the HubbleOps endpoint is unavailable by default.
