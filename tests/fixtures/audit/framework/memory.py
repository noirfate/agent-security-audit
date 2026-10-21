"""Static fixture: shared memory accepts an unbound namespace from its caller."""

def recall(request, authenticated_user, shared_store):
    namespace = request["namespace"]
    return shared_store[namespace]
