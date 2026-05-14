# codex-mcp-ghidra

Tiny MCP server that runs Ghidra headless.

## Files

- `ghidra_mcp_server.py`: MCP server
- `summary.java`: program summary script
- `functions.java`: function list script
- `decompile.java`: decompiler script
- `strings.java`: string search script
- `memory.java`: memory/section helpers
- `xrefs_to.java`, `xrefs_from.java`: reference helpers
- `finders.java`: function search helpers

## Run

```bash
export GHIDRA_HOME=/path/to/ghidra
export GHIDRA_MCP_PROJECTS=/tmp/ghidra-mcp-projects
export GHIDRA_MCP_TIMEOUT=600
python3 -m pip install mcp
python3 ghidra_mcp_server.py
```

Projects are kept under `GHIDRA_MCP_PROJECTS`. Use the `delete_project` MCP tool
when you want to remove one.

## Add to Codex

```bash
codex mcp add ghidra -- python3 /Users/user/dev/codex-mcp-ghidra/ghidra_mcp_server.py
```
# codex-mcp-ghidra
