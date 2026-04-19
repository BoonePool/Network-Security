# test_databricks.py
import asyncio
from databricks.sdk import WorkspaceClient
from databricks_mcp import DatabricksMCPClient

TABLE_NAME   = "tmp.cis.centripetal_confidential_mou_wake_forest_apf_flows_jan_2026"
WAREHOUSE_ID = "b21bb7e42c8f3962"

async def main():
    print("Connecting via WorkspaceClient...")
    workspace_client = WorkspaceClient()
    host = workspace_client.config.host
    print(f"✓ WorkspaceClient connected: {host}")

    print("\nConnecting MCP client...")
    mcp_client = DatabricksMCPClient(
        server_url=f"{host}/api/2.0/mcp/sql",
        workspace_client=workspace_client,
    )
    print("✓ MCP client created")

    print(f"\nFetching schema for {TABLE_NAME}...")
    response = await mcp_client.acall_tool(
        "execute_sql",
        arguments={
            "query": f"DESCRIBE {TABLE_NAME}",
            "warehouse_id": WAREHOUSE_ID
        },
    )

    import json
    result = json.loads(response.content[0].text)
    statement_id = result.get("statement_id")
    print(f"Statement ID: {statement_id}")

    # Poll until complete
    while True:
        poll = await mcp_client.acall_tool(
            "poll_sql_result",
            arguments={"statement_id": statement_id},
        )
        status_data = json.loads(poll.content[0].text)
        state = status_data.get("status", {}).get("state")
        print(f"  State: {state}")
        if state == "SUCCEEDED":
            break
        elif state == "FAILED":
            print(f"Failed: {status_data}")
            return
        else:
            await asyncio.sleep(2)

    # Print schema
    columns = status_data.get("manifest", {}).get("schema", {}).get("columns", [])
    col_names = [c["name"] for c in columns]
    rows = status_data.get("result", {}).get("data_typed_array", [])

    print(f"\n✓ Schema for {TABLE_NAME}:")
    print(f"   {'Column':<40} {'Type'}")
    print(f"   {'-'*40} {'-'*20}")
    for row in rows:
        vals = [list(cell.values())[0] if cell else None for cell in row.get("values", [])]
        if vals and not str(vals[0]).startswith("#"):
            print(f"   {str(vals[0]):<40} {str(vals[1])}")

if __name__ == "__main__":
    asyncio.run(main())
