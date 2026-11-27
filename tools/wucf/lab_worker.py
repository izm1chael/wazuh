"""Explicit, one-shot local spool worker with injected provider, never a service."""
from execution_plan import bind_claim
from ledger import ContractError, Ledger
from management import Management
from runtime import run
from spool import LocalSpool


def run_claimed(management, plan, claim, actor, clock, ledger, spool, provider_factory,
                max_pages=10):
    """Execute only a current local lab reservation.

    Provider factory is trusted and receives the exact immutable plan. It must
    enforce account/credential binding and bounded work. Clock and adapters
    remain caller-controlled. The checks here are not an external atomic fence:
    no automatic reassignment, and an operator must stop the worker before
    recovery. An expired/ambiguous completion leaves the reservation intact.
    Only local spool durability is claimed; this cannot invoke native ingress.
    """
    if (type(management) is not Management or type(ledger) is not Ledger
            or type(spool) is not LocalSpool):
        raise ContractError("local reference stores required")
    if type(max_pages) is not int or not 1 <= max_pages <= 100:
        raise ContractError("invalid page budget")
    bind_claim(plan, claim, ledger, spool)

    def check():
        management.check_claim(claim, actor, clock())

    check()
    provider = provider_factory(plan)
    check()

    class CheckedProvider:
        def fetch(self, cursor):
            check()
            result = provider.fetch(cursor)
            check()
            return result

    class CheckedSpool:
        def deliver(self, pid, body):
            check()
            receipt = spool.deliver(pid, body)
            check()
            return receipt

    result = run(ledger, CheckedProvider(), CheckedSpool(), max_pages=max_pages,
                 expected_boundary="local_spool")
    check()
    management.finish(plan.instance, plan.dataset, claim["lease"], actor, clock(),
                      result.status, result.boundary)
    return result
