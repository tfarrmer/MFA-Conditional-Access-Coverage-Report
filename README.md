# MFA & Conditional Access Coverage Report

Pulls MFA registration status and Conditional Access policy coverage from
Microsoft Graph API, cross-references them, and produces a per-user
Red/Yellow/Green heatmap plus a prioritized remediation list.

## Setup

1. **Register an Azure AD App** (Entra admin center → App registrations → New registration)
   - Add **Application permissions** (not delegated): `Reports.Read.All`, `Policy.Read.All`, `Directory.Read.All`
   - Have a Global Admin/Privileged Role Admin grant admin consent
   - Create a client secret under Certificates & secrets

2. **Clone this repo and configure secrets locally**
   ```bash
   cp .env.example .env
   # edit .env with your real tenant ID, client ID, client secret
   ```
   `.env` is gitignored — it will never be committed.

3. **Label your break-glass and service accounts**
   ```bash
   cp known_accounts.json.example known_accounts.json
   # edit known_accounts.json with real UPNs of known break-glass/service accounts
   ```
   `known_accounts.json` is also gitignored since it names real accounts.
   Without this file, the script still runs — it just labels those accounts
   as "unclassified" instead of "break_glass"/"service_account", and flags
   them in the remediation list as "verify manually."

4. **Install dependencies and run**
   ```bash
   pip install -r requirements.txt
   python audit.py
   ```

5. Output lands in `output/mfa_ca_coverage_report_<timestamp>.xlsx` (also gitignored,
   since it contains real tenant user data).

## What it checks

- **MFA registration** — via `reports/authenticationMethods/userRegistrationDetails`
- **CA policy coverage** — whether each user falls under an *enabled* policy
  requiring MFA, vs. only a report-only policy, vs. no policy at all
- **Legacy auth** — whether any enabled policy actually blocks legacy auth
  client types (`exchangeActiveSync`, `other`)
- **Exclusions** — cross-references excluded users against your labeled
  break-glass/service accounts; anything excluded and *not* labeled shows
  up as "unclassified — verify"

## Known limitation

CA policy scoping in this script only resolves **direct user includes/excludes**
(`includeUsers`/`excludeUsers`). Policies scoped by **group** membership
(`includeGroups`/`excludeGroups`) aren't expanded — that requires the
`GroupMember.Read.All` permission and an extra membership-resolution pass,
which was left out to keep the initial permission ask minimal. If your CA
policies are primarily group-scoped, coverage numbers here will undercount
protection. Flagging this as a documented next step rather than a silent gap.

## Why secrets are handled this way

- `.env` holds the app registration credentials — never committed, loaded via `python-dotenv`
- `known_accounts.json` names real accounts in your tenant — never committed
- `output/` holds real user data in the generated reports — never committed
- Only the `.example` versions of the above are tracked in git, so anyone
  cloning this repo gets the structure without any real tenant data
