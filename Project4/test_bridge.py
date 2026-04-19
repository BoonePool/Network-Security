import json
import requests

# ── Config (match solution defaults) ─────────────────────────────────────────

OLLAMA_BASE_URL = "http://localhost:11434"
OLLAMA_MODEL    = "llama3.1:8b"

# ── Test system prompt (mirrors solution's SQL_SYSTEM_PROMPT shape) ───────────

TEST_SYSTEM_PROMPT = (
    "You are a helpful assistant. "
    "Respond ONLY with valid JSON in this shape:\n"
    '  {"action": "answer", "summary": "<your response here>"}\n'
    "Do not include any text outside the JSON object. No markdown fences."
)

# ── Step 1: Check Ollama is reachable and model is available ──────────────────

def check_ollama() -> list[str]:
    print(f"[1/3] Checking Ollama is running at {OLLAMA_BASE_URL}…")
    try:
        resp = requests.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=5)
        resp.raise_for_status()
    except requests.exceptions.ConnectionError:
        raise RuntimeError(
            "✗ Cannot connect to Ollama.\n"
            "  Make sure it is running:  ollama serve"
        )
    except requests.exceptions.HTTPError as e:
        raise RuntimeError(f"✗ Ollama returned an error: {e}")

    available = [m["name"] for m in resp.json().get("models", [])]
    print(f"  ✓ Ollama is running. Available models: {available}")
    return available


def check_model(available: list[str]) -> None:
    print(f"\n[2/3] Checking model '{OLLAMA_MODEL}' is available…")
    if any(OLLAMA_MODEL in m for m in available):
        print(f"  ✓ Model '{OLLAMA_MODEL}' found.")
    else:
        raise RuntimeError(
            f"✗ Model '{OLLAMA_MODEL}' is not available locally.\n"
            f"  Pull it with:  ollama pull {OLLAMA_MODEL}\n"
            f"  Available models: {available}"
        )

# ── Step 2: Send a test chat request matching the solution's chat() pattern ───

def test_chat() -> None:
    print(f"\n[3/3] Sending test chat request to '{OLLAMA_MODEL}'…")

    history = [{"role": "user", "content": "Are you capable of writing Databricks SQL instructions?"}]

    payload = {
        "model":    OLLAMA_MODEL,
        "messages": [{"role": "system", "content": TEST_SYSTEM_PROMPT}] + history,
        "stream":   False,
        "format":   "json",   # matches solution exactly
    }

    try:
        resp = requests.post(
            f"{OLLAMA_BASE_URL}/api/chat",
            json=payload,
            timeout=120,       # matches solution exactly
        )
        resp.raise_for_status()
    except requests.exceptions.Timeout:
        raise RuntimeError("✗ Request timed out — model may still be loading.")
    except requests.exceptions.HTTPError as e:
        raise RuntimeError(f"✗ Chat request failed: {e}\n  Body: {resp.text}")

    raw   = resp.json()["message"]["content"].strip()
    print(f"  Raw response: {raw}")

    # Parse JSON response — same pattern as solution
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        raise RuntimeError(
            f"✗ Response was not valid JSON.\n"
            f"  Got: {raw}\n"
            f"  The model may not support JSON format mode reliably."
        )

    action  = parsed.get("action")
    summary = parsed.get("summary", "")

    if action != "answer" or not summary:
        raise RuntimeError(
            f"✗ Unexpected response shape: {parsed}\n"
            f"  Expected: {{\"action\": \"answer\", \"summary\": \"...\"}}"
        )

    print(f"  ✓ Model responded correctly.")
    print(f"  Summary: {summary}")

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("  Ollama Connectivity Test")
    print(f"  URL   : {OLLAMA_BASE_URL}")
    print(f"  Model : {OLLAMA_MODEL}")
    print("=" * 60)

    try:
        available = check_ollama()
        check_model(available)
        test_chat()

        print()
        print("=" * 60)
        print("  ✓ All checks passed — Ollama is ready.")
        print("=" * 60)

    except RuntimeError as e:
        print()
        print("=" * 60)
        print(f"  FAILED: {e}")
        print("=" * 60)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
