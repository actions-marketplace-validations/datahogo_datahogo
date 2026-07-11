# @datahogo/mcp

MCP server for [Data Hogo](https://github.com/datahogo/datahogo) — lets Claude, Cursor, and other MCP clients scan a project for security issues directly. Runs entirely locally over stdio; the host LLM does the explaining and fixing, at no AI cost to you.

```bash
claude mcp add datahogo -- npx -y @datahogo/mcp
```

For Cursor or another MCP client, point it at the same command: `npx -y @datahogo/mcp`, stdio transport.

Tools: `scan_project`, `get_finding`, `scan_url`, `check_db_rules`.

Full docs: [github.com/datahogo/datahogo](https://github.com/datahogo/datahogo)

License: AGPL-3.0
