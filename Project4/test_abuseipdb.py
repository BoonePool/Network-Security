import os
import requests
import json

# ── Configuration ─────────────────────────────────────────────────────────────

ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")

TEST_IP = "2.57.121.86"

# ── API Function (mirrors agent design) ───────────────────────────────────────

def get_ip_reputation(ip: str) -> dict:
    """
    Query AbuseIPDB for reputation information about an IP address.
    Returns a dictionary with the API response.
    """

    if not ABUSEIPDB_API_KEY:
        return {"error": "ABUSEIPDB_API_KEY is not set"}

    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={
                "Key": ABUSEIPDB_API_KEY,
                "Accept": "application/json"
            },
            params={
                "ipAddress": ip,
                "maxAgeInDays": 90
            },
            timeout=10,
        )

        if response.status_code == 200:
            return response.json().get("data", {})
        else:
            return {
                "error": f"HTTP {response.status_code}",
                "details": response.text
            }

    except Exception as e:
        return {"error": str(e)}


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    print(f"\nChecking AbuseIPDB reputation for IP: {TEST_IP}\n")

    result = get_ip_reputation(TEST_IP)

    if "error" in result:
        print("[Error]")
        print(result["error"])
        if "details" in result:
            print(result["details"])
        return

    # Pretty print selected fields
    print("Abuse Confidence Score:", result.get("abuseConfidenceScore"))
    print("Country:", result.get("countryCode"))
    print("ISP:", result.get("isp"))
    print("Total Reports:", result.get("totalReports"))
    print("Last Reported:", result.get("lastReportedAt"))

    print("\nFull JSON response:\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()


