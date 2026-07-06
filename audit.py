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