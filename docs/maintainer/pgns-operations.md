# PGNS alias admission and abuse response

Portal's sequencer rejects new claims and reclaims of `auth.app.<zone>`,
`gosuda.app.<zone>`, and `login.app.<zone>` at submission time. This supplements
the existing protocol-reserved labels, such as `admin` and `mail`, without changing
proof validation, witness verification, or the wire format. It does not reserve
the same service labels in the self-certifying `.id` namespace. Existing records
can still be updated or recovered under the usual ownership rules.

For reported abuse, distinguish a DNS or relay operator's local serving policy
from the authenticated PGNS ledger. A local refusal does not delete or transfer
a name. The remaining [operational design](https://github.com/gosuda/portal-tunnel/issues/791)
calls for a separate reviewed denial policy for renewal, allowing an abusive
alias to expire normally while retaining the standard cold recovery path.
That enforcement and the DNS/relay serving policy are not implemented here.
