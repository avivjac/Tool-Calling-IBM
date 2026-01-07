import asyncio
import json
import os
import sys
from pathlib import Path
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def main():
    # Ensure we're running from the workspace root
    workspace_root = Path(__file__).parent.parent.parent
    os.chdir(workspace_root)
    
    server_params = StdioServerParameters(
        command=sys.executable,  # Use current Python interpreter
        args=[str(workspace_root / "src" / "server" / "providers" / "API_tools" / "virusTotal.py")],
        env={**os.environ}  # Pass environment variables including .env
    )

    try:
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()          # handshake
                tools = await session.list_tools()  # <-- this is the "discovery"
                
                # Build the desired JSON structure
                result = {
                    "type": "capabilities.response",
                    "tools": []
                }
                
                for t in tools.tools:
                    tool_info = {
                        "name": t.name,
                        "description": t.description,
                        "input_schema": t.inputSchema
                    }
                    result["tools"].append(tool_info)
                
                # Print the JSON with nice formatting
                print(json.dumps(result, indent=2))
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        print("Make sure you have a .env file with VIRUSTOTAL_API_KEY set", file=sys.stderr)
        sys.exit(1)

asyncio.run(main())
