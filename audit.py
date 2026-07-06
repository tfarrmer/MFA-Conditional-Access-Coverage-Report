import os
import json
import requests
from datetime import datetime
from dotenv import load_dotenv
from openpyxl import Workbook
from openpyxl.styles import PatternFill, Font

load_dotenv()
TENANT_ID = os.getenv("AZURE_TENANT_ID")
CLIENT_ID = os.getenv("AZURE_CLIENT_ID")
CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET")

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
LEGACY_AUTH_CLIENT_TYPES = {"exchangeActiveSync", "other"}

if not all([TENANT_ID, CLIENT_ID, CLIENT_SECRET]):
    raise SystemExit(
        "Missing credentials. Copy .env.example to .env and fill in "
        "AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET."
    )

def get_access_token():
    url = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
    data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "scope": "https://graph.microsoft.com/.default",
        "grant_type": "client_credentials",
    }
    resp = requests.post(url, data=data)
    resp.raise_for_status()
    return resp.json()["access_token"]

def graph_get_all(url, headers):
    results = []
    while url:
        resp = requests.get(url, headers=headers)
        resp.raise_for_status()
        body = resp.json()
        results.extend(body.get("value", []))
        url = body.get("@odata.nextLink")
    return results

def load_known_accounts():
    path = "known_accounts.json"
    if not os.path.exists(path):
        print(f"[warn] {path} not found — break-glass/service accounts won't be labeled. "
              f"Copy known_accounts.json.example to get started.")
        return {"break_glass_accounts": [], "service_accounts": []}
    with open(path) as f:
        data = json.load(f)
    return {
        "break_glass_accounts": {u.lower() for u in data.get("break_glass_accounts", [])},
        "service_accounts": {u.lower() for u in data.get("service_accounts", [])},
    }

def fetch_mfa_registration(headers):
    url = f"{GRAPH_BASE}/reports/authenticationMethods/userRegistrationDetails"
    return graph_get_all(url, headers)

def fetch_ca_policies(headers):
    url = f"{GRAPH_BASE}/identity/conditionalAccess/policies"
    return graph_get_all(url, headers)

def policy_requires_mfa(policy):
    controls = policy.get("grantControls") or {}
    return "mfa" in (controls.get("builtInControls") or [])
 
 
def policy_blocks_legacy_auth(policy):
    client_types = set((policy.get("conditions") or {}).get("clientAppTypes") or [])
    grant = policy.get("grantControls") or {}
    is_block = grant.get("operator") == "OR" and "block" in (grant.get("builtInControls") or [])
    return is_block and bool(client_types & LEGACY_AUTH_CLIENT_TYPES)
 
 
def user_in_policy_scope(user_id, policy):
    """Rough scope check: included (all users, or explicit id) minus excluded."""
    users_cond = (policy.get("conditions") or {}).get("users") or {}
    include_users = set(users_cond.get("includeUsers") or [])
    exclude_users = set(users_cond.get("excludeUsers") or [])
 
    if user_id in exclude_users:
        return False
    if "All" in include_users or user_id in include_users:
        return True
    # Note: group-based include/exclude requires resolving group membership,
    # which needs GroupMember.Read.All. Left as a documented gap below.
    return False