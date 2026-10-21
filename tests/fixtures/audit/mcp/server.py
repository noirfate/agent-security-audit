"""Static fixture: an MCP handler whose upstream guard checks resource ownership."""

def read_resource(request, authenticated_subject, store):
    resource = store[request["resource_id"]]
    if resource["owner"] != authenticated_subject:
        raise PermissionError("wrong owner")
    return serialize_resource(resource)


def serialize_resource(resource):
    return {"text": resource["text"]}
