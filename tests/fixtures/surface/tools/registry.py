"""Static fixture: a tool registry and an MCP call handler. Read as material, never run."""

TOOLS = [
    Tool(name="read_notes", description="Read the user's notes", inputSchema={"type": "object"}),
]


def list_tools():
    return TOOLS


def handle_tool(request):
    name = request["name"]
    arguments = json.loads(request["arguments"])
    return dispatch_tool(name, arguments)


def serve(app):
    @app.post("/mcp")
    def endpoint(body):
        if body["method"] == "tools/call":
            return handle_tool(body["params"])
        if body["method"] == "resources/read":
            return read_resource(body["params"])
        return {"error": "unknown"}
