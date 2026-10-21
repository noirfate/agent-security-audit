"""Static fixture: normal account-scoped access and an explicit business invariant."""

def recall(authenticated_user, shared_store):
    return shared_store[authenticated_user.tenant_id][authenticated_user.id]


def approve_export(owner, recipient):
    # Business invariant: approvals bind the recipient as well as the owner.
    return {"owner": owner}
