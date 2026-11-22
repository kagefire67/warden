"""A small fake tool server used only for testing Warden.

It pretends to be an email/files tool so we can test safely: nothing here
touches real files or sends real email.
"""

from mcp.server.mcpserver import MCPServer

mcp = MCPServer("fake-tools")


@mcp.tool()
def read_file(path: str) -> str:
    """Read a (fake) file."""
    return f"Contents of {path}: quarterly invoice totals..."


@mcp.tool()
def send_email(to: str, subject: str, body: str) -> str:
    """Send a (fake) email."""
    return f"Email to {to} with subject '{subject}' was sent (fake)."


if __name__ == "__main__":
    mcp.run()
