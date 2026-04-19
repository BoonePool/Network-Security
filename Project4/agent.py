"""
RuleGate Threat Intelligence Agent
===================================
Agentic framework that combines:
  - Ollama (llama3.1:8b) as the planner / language model
  - Databricks via MCP for SQL-based RuleGate event analysis
  - OSINT APIs (ip-api.com, AbuseIPDB) for IoC enrichment

Architecture: Planner → Tool Selection → Reflection Loop → Answer
"""

import os
import json
import sys
import re
import requests
from pathlib import Path

# ─────────────────────────────────────────────
#  Configuration
# ─────────────────────────────────────────────
OLLAMA_MODEL    = "llama3.1:8b"
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_TIMEOUT  = int(os.getenv("OLLAMA_TIMEOUT", "120"))

DATABRICKS_HOST       = os.getenv("DATABRICKS_HOST", "")          # e.g. adb-xxxx.azuredatabricks.net
DATABRICKS_TOKEN      = os.getenv("DATABRICKS_TOKEN", "")
DATABRICKS_HTTP_PATH  = os.getenv("DATABRICKS_HTTP_PATH", "")     # /sql/1.0/warehouses/<id>
DATABRICKS_CATALOG    = os.getenv("DATABRICKS_CATALOG", "rulegate")
DATABRICKS_SCHEMA     = os.getenv("DATABRICKS_SCHEMA", "events")

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

CONTEXT_FILE    = Path(__file__).parent / "context.md"
MAX_SQL_RETRIES = 3

# ─────────────────────────────────────────────
#  ANSI colours for the terminal
# ─────────────────────────────────────────────
class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    CYAN   = "\033[36m"
    GREEN  = "\033[32m"
    YELLOW = "\033[33m"
    RED    = "\033[31m"
    BLUE   = "\033[34m"
    DIM    = "\033[2m"

def banner():
    print(f"""
{C.CYAN}{C.BOLD}╔══════════════════════════════════════════════════════╗
║      RuleGate Threat Intelligence Agent v1.0         ║
║      Model : {OLLAMA_MODEL:<38}║
╚══════════════════════════════════════════════════════╝{C.RESET}
""")

# ─────────────────────────────────────────────
#  Context loading
# ─────────────────────────────────────────────
def load_context() -> str:
    if CONTEXT_FILE.exists():
        return CONTEXT_FILE.read_text(encoding="utf-8")
    print(f"{C.YELLOW}[WARN] context.md not found — proceeding without domain context{C.RESET}")
    return ""

# ─────────────────────────────────────────────
#  System prompt assembly
# ─────────────────────────────────────────────
ANSWER_SHAPES = """
## Required Answer Shapes (return ONLY valid JSON — no markdown, no extra text)

| Task                        | JSON Shape                                                        |
|-----------------------------|-------------------------------------------------------------------|
| Generate or fix SQL query   | {"action": "query",  "sql": "SELECT ..."}                        |
| Return final answer         | {"action": "answer", "summary": "..."}                           |
| Call an OSINT tool          | {"action": "tool",   "tool": "<name>", "args": {"ip": "..."}}    |

Available OSINT tools:
  - "geoip"     → args: {"ip": "<address>"}
  - "abuseipdb" → args: {"ip": "<address>"}

NEVER include anything outside the JSON object.
NEVER wrap the JSON in markdown code fences.
"""

def build_system_prompt(context: str) -> str:
    return f"""You are a cybersecurity threat intelligence analyst assistant powered by an agentic framework.

{context}

{ANSWER_SHAPES}

Decision logic:
1. If the question is about RuleGate event data, detections, tactics, IPs, or traffic patterns
   → respond with the "query" action containing a valid Databricks SQL query.
2. If the question asks to look up, investigate, or enrich a specific IP address or domain
   → respond with the "tool" action selecting the most appropriate OSINT tool.
3. Once you have data (query results or tool output) and can compose a final answer
   → respond with the "answer" action containing a thorough threat intelligence summary.

Always follow the filtering rules and aggregation conventions from the domain context above.
"""

# ─────────────────────────────────────────────
#  Ollama client
# ─────────────────────────────────────────────
def call_ollama(system_prompt: str, history: list[dict], user_message: str) -> str:
    """Send a composed prompt to Ollama and return the raw response text."""
    messages = []

    # Inject system prompt as first user/assistant pair (Ollama chat format)
    # Some models handle <system> role; use it when available.
    messages.append({"role": "system", "content": system_prompt})

    # Append full interaction history
    for turn in history:
        messages.append(turn)

    # Append current user message
    messages.append({"role": "user", "content": user_message})

    payload = {
        "model":   OLLAMA_MODEL,
        "messages": messages,
        "stream":  False,
        "options": {
            "temperature": 0.1,   # low temp for deterministic JSON
            "num_predict": 1024,
        },
    }

    try:
        resp = requests.post(
            f"{OLLAMA_BASE_URL}/api/chat",
            json=payload,
            timeout=OLLAMA_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()["message"]["content"].strip()
    except requests.exceptions.ConnectionError:
        print(f"\n{C.RED}[ERROR] Cannot reach Ollama at {OLLAMA_BASE_URL}."
              f" Is it running?  →  ollama serve{C.RESET}\n")
        sys.exit(1)
    except Exception as exc:
        print(f"\n{C.RED}[ERROR] Ollama call failed: {exc}{C.RESET}\n")
        return json.dumps({"action": "answer", "summary": f"Model call failed: {exc}"})


# ─────────────────────────────────────────────
#  JSON parsing helpers
# ─────────────────────────────────────────────
def parse_action(raw: str) -> dict:
    """Extract and parse the JSON action from the model's response."""
    # Strip markdown fences the model might add despite instructions
    cleaned = re.sub(r"```(?:json)?", "", raw).replace("```", "").strip()

    # Find the first {...} block
    match = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if match:
        cleaned = match.group(0)

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError as exc:
        return {"action": "answer", "summary": f"[Parse error] Model returned invalid JSON: {exc}\n\nRaw: {raw}"}


# ─────────────────────────────────────────────
#  Databricks SQL execution
# ─────────────────────────────────────────────
def run_databricks_query(sql: str) -> dict:
    """
    Execute SQL against Databricks using the SQL Connector.
    Returns {"success": True, "rows": [...], "columns": [...]}
    or      {"success": False, "error": "..."}
    """
    try:
        from databricks import sql as dbsql
    except ImportError:
        return {
            "success": False,
            "error": (
                "databricks-sql-connector not installed. "
                "Run: pip install databricks-sql-connector"
            ),
        }

    if not all([DATABRICKS_HOST, DATABRICKS_TOKEN, DATABRICKS_HTTP_PATH]):
        return {
            "success": False,
            "error": (
                "Databricks not configured. Set environment variables: "
                "DATABRICKS_HOST, DATABRICKS_TOKEN, DATABRICKS_HTTP_PATH"
            ),
        }

    try:
        with dbsql.connect(
            server_hostname=DATABRICKS_HOST,
            http_path=DATABRICKS_HTTP_PATH,
            access_token=DATABRICKS_TOKEN,
            catalog=DATABRICKS_CATALOG,
            schema=DATABRICKS_SCHEMA,
        ) as conn:
            with conn.cursor() as cursor:
                cursor.execute(sql)
                columns = [desc[0] for desc in cursor.description] if cursor.description else []
                rows = cursor.fetchall()
                # Convert Row objects to plain dicts
                result_rows = [dict(zip(columns, row)) for row in rows]
                return {"success": True, "columns": columns, "rows": result_rows}
    except Exception as exc:
        return {"success": False, "error": str(exc)}


def format_query_results(result: dict) -> str:
    """Format Databricks results as a compact text table for the model."""
    if not result["success"]:
        return f"Query error: {result['error']}"
    rows = result["rows"]
    if not rows:
        return "Query returned 0 rows."
    cols = result["columns"]
    lines = [" | ".join(cols)]
    lines.append("-" * len(lines[0]))
    for row in rows[:50]:  # cap at 50 rows passed back to model
        lines.append(" | ".join(str(row.get(c, "")) for c in cols))
    if len(rows) > 50:
        lines.append(f"... ({len(rows) - 50} more rows truncated)")
    return "\n".join(lines)


# ─────────────────────────────────────────────
#  SQL validation (lightweight)
# ─────────────────────────────────────────────
def validate_sql(sql: str) -> tuple[bool, str]:
    """Basic checks before sending to Databricks."""
    sql_upper = sql.upper().strip()

    # Must start with SELECT
    if not sql_upper.startswith("SELECT"):
        return False, "Query must start with SELECT."

    # Disallow mutations
    for dangerous in ("INSERT", "UPDATE", "DELETE", "DROP", "TRUNCATE", "ALTER", "CREATE"):
        if re.search(rf"\b{dangerous}\b", sql_upper):
            return False, f"Query contains disallowed keyword: {dangerous}"

    # Must reference the correct table
    if "RULEGATE" not in sql_upper and "DETECTIONS" not in sql_upper:
        return False, "Query does not reference the expected table (rulegate.events.detections)."

    return True, "OK"


# ─────────────────────────────────────────────
#  OSINT tools
# ─────────────────────────────────────────────
def tool_geoip(ip: str) -> dict:
    """Query ip-api.com for geolocation + network metadata."""
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,message,country,regionName,city,isp,org,as,proxy,hosting"},
            timeout=5,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "fail":
                return {"error": data.get("message", "ip-api lookup failed")}
            # Return only relevant fields
            return {
                "ip":       ip,
                "country":  data.get("country"),
                "region":   data.get("regionName"),
                "city":     data.get("city"),
                "isp":      data.get("isp"),
                "org":      data.get("org"),
                "asn":      data.get("as"),
                "proxy":    data.get("proxy"),
                "hosting":  data.get("hosting"),
            }
        return {"error": f"HTTP {resp.status_code}"}
    except requests.exceptions.Timeout:
        return {"error": "ip-api.com timed out"}
    except Exception as exc:
        return {"error": str(exc)}


def tool_abuseipdb(ip: str) -> dict:
    """Query AbuseIPDB for reputation and abuse confidence score."""
    if not ABUSEIPDB_API_KEY:
        return {"error": "ABUSEIPDB_API_KEY environment variable not set."}
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=5,
        )
        if resp.status_code == 200:
            d = resp.json().get("data", {})
            return {
                "ip":                 ip,
                "abuse_confidence":   d.get("abuseConfidenceScore"),
                "total_reports":      d.get("totalReports"),
                "last_reported":      d.get("lastReportedAt"),
                "country":            d.get("countryCode"),
                "isp":                d.get("isp"),
                "domain":             d.get("domain"),
                "is_tor":             d.get("isTor"),
                "is_public":          d.get("isPublic"),
                "usage_type":         d.get("usageType"),
            }
        return {"error": f"HTTP {resp.status_code}"}
    except requests.exceptions.Timeout:
        return {"error": "AbuseIPDB timed out"}
    except Exception as exc:
        return {"error": str(exc)}


TOOL_REGISTRY = {
    "geoip":     tool_geoip,
    "abuseipdb": tool_abuseipdb,
}


def dispatch_tool(tool_name: str, args: dict) -> str:
    """Call the named OSINT tool and return a compact JSON string."""
    fn = TOOL_REGISTRY.get(tool_name)
    if fn is None:
        result = {"error": f"Unknown tool '{tool_name}'. Available: {list(TOOL_REGISTRY)}"}
    else:
        ip = args.get("ip", args.get("address", ""))
        if not ip:
            result = {"error": "Tool requires 'ip' argument."}
        else:
            print(f"  {C.DIM}[OSINT] Calling {tool_name} for {ip}…{C.RESET}")
            result = fn(ip)
    return json.dumps(result, indent=2)


# ─────────────────────────────────────────────
#  SQL path  (planner → validate → execute → reflect)
# ─────────────────────────────────────────────
def run_sql_path(
    system_prompt: str,
    history: list[dict],
    user_message: str,
    first_action: dict,
) -> str:
    """
    Handle the full SQL generation → validation → execution → reflection loop.
    Returns a human-readable summary string.
    """
    sql = first_action.get("sql", "").strip()
    last_error = ""

    for attempt in range(1, MAX_SQL_RETRIES + 1):
        print(f"  {C.DIM}[SQL attempt {attempt}/{MAX_SQL_RETRIES}]{C.RESET}")

        # ── Validation ──────────────────────────────────────────────────
        valid, reason = validate_sql(sql)
        if not valid:
            print(f"  {C.YELLOW}[VALIDATE] {reason}{C.RESET}")
            fix_prompt = (
                f"The SQL query you generated failed validation with this error:\n{reason}\n\n"
                f"Original query:\n{sql}\n\n"
                f"Please provide a corrected query using the 'query' action."
            )
            raw = call_ollama(system_prompt, history, fix_prompt)
            action = parse_action(raw)
            sql = action.get("sql", "").strip()
            last_error = reason
            continue

        # ── Execution ────────────────────────────────────────────────────
        print(f"  {C.DIM}[SQL] Executing query…{C.RESET}")
        result = run_databricks_query(sql)

        if result["success"]:
            table_str = format_query_results(result)
            print(f"  {C.GREEN}[SQL] Query returned {len(result['rows'])} row(s){C.RESET}")
            # Ask model to produce final answer
            summary_prompt = (
                f"The following SQL query was executed successfully:\n\n{sql}\n\n"
                f"Results:\n{table_str}\n\n"
                f"Based on these results and the original question, produce a final threat "
                f"intelligence summary using the 'answer' action."
            )
            raw = call_ollama(system_prompt, history, summary_prompt)
            action = parse_action(raw)
            return action.get("summary", raw)

        else:
            last_error = result["error"]
            print(f"  {C.YELLOW}[SQL ERROR] {last_error}{C.RESET}")
            if attempt < MAX_SQL_RETRIES:
                fix_prompt = (
                    f"The query failed with this error:\n{last_error}\n\n"
                    f"Original query:\n{sql}\n\n"
                    f"Please provide a corrected query using the 'query' action."
                )
                raw = call_ollama(system_prompt, history, fix_prompt)
                action = parse_action(raw)
                sql = action.get("sql", "").strip()

    return f"[FAILED] Could not produce a valid result after {MAX_SQL_RETRIES} attempts.\nLast error: {last_error}"


# ─────────────────────────────────────────────
#  OSINT path  (planner → tool → summarise)
# ─────────────────────────────────────────────
def run_osint_path(
    system_prompt: str,
    history: list[dict],
    user_message: str,
    first_action: dict,
) -> str:
    """
    Handle OSINT tool dispatch and final summarisation.
    Returns a human-readable summary string.
    """
    tool_name = first_action.get("tool", "")
    args      = first_action.get("args", {})

    tool_result = dispatch_tool(tool_name, args)

    # Send tool result back to model for summarisation
    summary_prompt = (
        f"You called the '{tool_name}' tool with args {json.dumps(args)}.\n\n"
        f"Tool result:\n{tool_result}\n\n"
        f"Based on this data and the original question, produce a final threat intelligence "
        f"summary using the 'answer' action."
    )
    raw = call_ollama(system_prompt, history, summary_prompt)
    action = parse_action(raw)
    return action.get("summary", raw)


# ─────────────────────────────────────────────
#  Core agent loop (single turn)
# ─────────────────────────────────────────────
def process_query(
    system_prompt: str,
    history: list[dict],
    user_message: str,
) -> str:
    """
    Run one full agent turn:
      1. Call planner to get initial action
      2. Route to SQL or OSINT path
      3. Return final summary
    """
    print(f"\n{C.BLUE}[AGENT] Planning…{C.RESET}")
    raw = call_ollama(system_prompt, history, user_message)
    action = parse_action(raw)
    action_type = action.get("action", "unknown")

    print(f"  {C.DIM}[PLANNER] action={action_type}{C.RESET}")

    if action_type == "query":
        return run_sql_path(system_prompt, history, user_message, action)

    elif action_type == "tool":
        return run_osint_path(system_prompt, history, user_message, action)

    elif action_type == "answer":
        # Model answered directly (e.g., clarification question)
        return action.get("summary", raw)

    else:
        return f"[WARN] Unexpected action type '{action_type}'. Raw response:\n{raw}"


# ─────────────────────────────────────────────
#  Interactive REPL
# ─────────────────────────────────────────────
def repl():
    banner()

    context       = load_context()
    system_prompt = build_system_prompt(context)
    history: list[dict] = []

    print(f"{C.DIM}Commands:  'exit' / 'quit' to stop   |   'reset' to clear history{C.RESET}\n")

    while True:
        try:
            user_input = input(f"{C.CYAN}{C.BOLD}analyst> {C.RESET}").strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n{C.DIM}Session ended.{C.RESET}")
            break

        if not user_input:
            continue

        if user_input.lower() in ("exit", "quit"):
            print(f"{C.DIM}Goodbye.{C.RESET}")
            break

        if user_input.lower() == "reset":
            history.clear()
            print(f"{C.GREEN}[INFO] Conversation history cleared.{C.RESET}\n")
            continue

        if user_input.lower() == "history":
            if not history:
                print(f"{C.DIM}(no history){C.RESET}\n")
            else:
                for i, turn in enumerate(history):
                    role = turn["role"].upper()
                    snippet = str(turn["content"])[:120]
                    print(f"  {C.DIM}[{i}] {role}: {snippet}…{C.RESET}")
            print()
            continue

        # ── Run the agent ────────────────────────────────────────────────
        answer = process_query(system_prompt, history, user_input)

        # Update history
        history.append({"role": "user",      "content": user_input})
        history.append({"role": "assistant", "content": answer})

        # Display answer
        print(f"\n{C.GREEN}{C.BOLD}─── Answer ───────────────────────────────────────────{C.RESET}")
        print(answer)
        print(f"{C.GREEN}{C.BOLD}──────────────────────────────────────────────────────{C.RESET}\n")


# ─────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────
if __name__ == "__main__":
    repl()
