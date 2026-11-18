"""
b2c_get_tokens.py
─────────────────
Fetch id_token and access_token for any B2C policy + environment.
Also supports exchanging an existing refresh_token so you can compare
claims before/after a refresh (handy for spotting claims that silently
drop out on refresh, e.g. acr/tfp or optional claims).
Reads all config from nprd.env — no hardcoded values.

Usage:
    python b2c_get_tokens.py --policy signinnomfa --env nonprod
    python b2c_get_tokens.py --policy signinmfa   --env nonprod
    python b2c_get_tokens.py --policy signin      --env prod
    python b2c_get_tokens.py --list-policies

    # Refresh-token flow (no browser step needed):
    python b2c_get_tokens.py --policy signinnomfa --env nonprod --refresh-token "eyJ..."
    python b2c_get_tokens.py --policy signinnomfa --env nonprod --refresh-token-file rt.txt

Requirements:
    Python 3.7+  (stdlib only — no pip installs needed)
"""


import base64
import datetime
import hashlib
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from  b2c_utils.config import load_env, build_config,list_policies,die,parse_args






# ═══════════════════════════════════════════════════════════════
# PKCE
# ═══════════════════════════════════════════════════════════════

def generate_pkce() -> tuple:
    verifier  = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
    digest    = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


# ═══════════════════════════════════════════════════════════════
# JWT DECODER  (no signature verification — demo only)
# ═══════════════════════════════════════════════════════════════

def decode_jwt_payload(token: str) -> dict:
    try:
        part = token.split(".")[1]
        part += "=" * (-len(part) % 4)
        return json.loads(base64.urlsafe_b64decode(part))
    except Exception:
        return {}


CLAIM_ORDER = [
    "sub", "oid", "name", "given_name", "family_name",
    "emails", "email", "scp", "tfp", "acr",
    "iss", "aud", "iat", "exp",
]


def print_claims(label: str, token: str):
    claims = decode_jwt_payload(token)
    bar = "─" * 62
    print(f"\n{bar}")
    print(f"  {label}")
    print(bar)
    if not claims:
        print("  (could not decode payload)")
        return
    printed = set()
    for key in CLAIM_ORDER:
        if key not in claims:
            continue
        val = claims[key]
        if key in ("iat", "exp"):
            ts  = datetime.datetime.utcfromtimestamp(val)
            val = f"{val}  ({ts.strftime('%Y-%m-%d %H:%M:%S')} UTC)"
        print(f"  {key:<24} {val}")
        printed.add(key)
    for key, val in claims.items():
        if key not in printed:
            print(f"  {key:<24} {val}")
    return set(claims.keys())


def diff_claims(before_token: str, after_token: str):
    """Print which claim keys were present before a refresh but dropped after (or vice versa)."""
    before = set(decode_jwt_payload(before_token).keys())
    after  = set(decode_jwt_payload(after_token).keys())
    dropped = before - after
    added   = after - before
    bar = "─" * 62
    print(f"\n{bar}")
    print("  CLAIM DIFF  (original token  →  refreshed token)")
    print(bar)
    if not dropped and not added:
        print("  No difference in claim keys.")
    if dropped:
        print(f"  Dropped on refresh : {', '.join(sorted(dropped))}")
    if added:
        print(f"  Added on refresh   : {', '.join(sorted(added))}")


# ═══════════════════════════════════════════════════════════════
# AUTH URL
# ═══════════════════════════════════════════════════════════════

def build_auth_url(cfg: dict, challenge: str) -> str:
    params = {
        "client_id":             cfg["client_id"],
        "response_type":         "code",
        "redirect_uri":          cfg["redirect_uri"],
        "response_mode":         "fragment",
        "scope":                 cfg["scopes"],
        "state":                 "b2c_test_state",
        "nonce":                 base64.urlsafe_b64encode(os.urandom(8)).decode(),
        "prompt":                "login",
        "code_challenge":        challenge,
        "code_challenge_method": "S256",
        "login_hint":            cfg["login_hint"],
    }
    return cfg["auth_endpoint"] + "?" + urllib.parse.urlencode(params)


# ═══════════════════════════════════════════════════════════════
# TOKEN EXCHANGE (authorization_code)
# ═══════════════════════════════════════════════════════════════

def exchange_code(cfg: dict, code: str, verifier: str) -> dict:
    body = urllib.parse.urlencode({
        "grant_type":    "authorization_code",
        "client_id":     cfg["client_id"],
        "redirect_uri":  cfg["redirect_uri"],
        "code":          code,
        "code_verifier": verifier,
        "scope":         cfg["scopes"],
    }).encode()

    req = urllib.request.Request(
        cfg["token_endpoint"],
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        err_body = e.read().decode()
        die(f"Token exchange failed — HTTP {e.code}\n{err_body}")


# ═══════════════════════════════════════════════════════════════
# TOKEN EXCHANGE (refresh_token)
# ═══════════════════════════════════════════════════════════════

def refresh_tokens(cfg: dict, refresh_token: str) -> dict:
    """
    Exchange a refresh_token for a new id_token / access_token / refresh_token.
    Useful for comparing claims on the original token vs. the refreshed one —
    B2C will silently omit a claim on refresh if, e.g., an optional claim or
    a custom policy output claim isn't wired into the token refresh journey.
    """
    body = urllib.parse.urlencode({
        "grant_type":    "refresh_token",
        "client_id":     cfg["client_id"],
        "refresh_token": refresh_token,
        "scope":         cfg["scopes"],
    }).encode()

    req = urllib.request.Request(
        cfg["token_endpoint"],
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        err_body = e.read().decode()
        die(f"Refresh token exchange failed — HTTP {e.code}\n{err_body}")


def read_refresh_token_file(path: str) -> str:
    if not os.path.exists(path):
        die(f"Refresh token file not found: {path}")
    with open(path) as f:
        return f.read().strip()


# ═══════════════════════════════════════════════════════════════
# PRINTERS
# ═══════════════════════════════════════════════════════════════

def banner(cfg: dict, mode: str = "auth_code"):
    label = "Refresh Token Exchange" if mode == "refresh" else "Token Fetch"
    print("\n" + "═" * 62)
    print(f"  B2C {label}")
    print(f"  Policy  : {cfg['policy']}")
    print(f"  Tenant  : {cfg['tenant']}")
    print(f"  Client  : {cfg['client_id']}")
    print(f"  Scopes  : {cfg['scopes']}")
    print("═" * 62)


def print_raw_token(label: str, token: str):
    bar = "─" * 62
    print(f"\n{bar}")
    print(f"  {label}")
    print(bar)
    if token:
        print(f"  {token}")
    else:
        print("  (not returned)")


def print_access_token_help():
    print("\n  ACCESS TOKEN was not returned. Check:")
    print("    1. 'Expose an API' has scopes defined on the API app")
    print("    2. API scope is added to client app under 'API Permissions'")
    print("    3. Admin consent is granted  (green tick in portal)")
    print("    4. SCOPES in nprd.env includes the full API scope URI")


def print_refresh_token_help():
    print("\n  NEW REFRESH TOKEN was not returned. Check:")
    print("    1. 'offline_access' scope is included in SCOPES in nprd.env")
    print("    2. The original refresh token hasn't expired or been revoked")
    print("    3. The user's session / SSO cookie hasn't been invalidated")


def print_missing_claims_help():
    print("\n  If claims are missing after refresh, check in the B2C policy:")
    print("    1. The claim is included in the policy's TokenIssuanceTechnicalProfile")
    print("       output claims (not just the sign-in one)")
    print("    2. If it's a custom/optional claim, it's also wired into the")
    print("       refresh-token grant's user journey, not just the sign-in journey")
    print("    3. The claim's source (e.g. Azure AD attribute / claims provider)")
    print("       is actually populated for this user")


def tip():
    print("\n" + "═" * 62)
    print("  Tip: paste any token into https://jwt.ms to inspect")
    print("═" * 62 + "\n")


def die(msg: str):
    print(f"\n  ERROR: {msg}\n", file=sys.stderr)
    sys.exit(1)





# ═══════════════════════════════════════════════════════════════
# FLOWS
# ═══════════════════════════════════════════════════════════════

def run_auth_code_flow(cfg: dict, args):
    verifier, challenge = generate_pkce()

    banner(cfg, mode="auth_code")

    # Step 1 — print auth URL
    auth_url = build_auth_url(cfg, challenge)
    print("\n── STEP 1  Copy this URL into your browser ──────────────")
    print(f"\n{auth_url}\n")
    print("  Sign in → B2C redirects to oidcdebugger.com")
    print("  Copy the  code=  value from the URL fragment.\n")

    # Step 2 — get code from user
    print("── STEP 2  Paste the 'code' value here ──────────────────")
    code = input("  code: ").strip()
    if not code:
        die("No code entered.")

    # Step 3 — exchange
    print("\n── STEP 3  Exchanging code for tokens… ──────────────────")
    tokens = exchange_code(cfg, code, verifier)
    handle_token_response(tokens, args, missing_access_help=True)


def run_refresh_flow(cfg: dict, refresh_token: str, args):
    banner(cfg, mode="refresh")

    print("\n── Exchanging refresh_token for new tokens… ──────────────")
    tokens = refresh_tokens(cfg, refresh_token)
    handle_token_response(
        tokens, args,
        missing_access_help=True,
        missing_refresh_help=True,
        is_refresh=True,
    )


def handle_token_response(tokens: dict, args,
                           missing_access_help=False,
                           missing_refresh_help=False,
                           is_refresh=False):
    id_token      = tokens.get("id_token", "")
    access_token  = tokens.get("access_token", "")
    new_refresh   = tokens.get("refresh_token", "")

    # Raw tokens
    print_raw_token("ID TOKEN (raw)", id_token)
    print_raw_token("ACCESS TOKEN (raw)", access_token)
    if is_refresh:
        print_raw_token("REFRESH TOKEN (raw, new)", new_refresh)

    # Decoded claims
    if id_token:
        print_claims("ID TOKEN CLAIMS", id_token)

    if access_token:
        print_claims("ACCESS TOKEN CLAIMS", access_token)
    elif missing_access_help:
        print_access_token_help()

    if is_refresh and not new_refresh and missing_refresh_help:
        print_refresh_token_help()

    # Optional: diff against a previously saved id_token
    if args.compare_id_token and id_token:
        old_id_token = read_refresh_token_file(args.compare_id_token)
        diff_claims(old_id_token, id_token)
        print_missing_claims_help()

    # Optional: save tokens for later comparison
    if args.save_tokens:
        prefix = args.save_tokens
        if id_token:
            with open(f"{prefix}_id.txt", "w") as f:
                f.write(id_token)
        if access_token:
            with open(f"{prefix}_access.txt", "w") as f:
                f.write(access_token)
        if new_refresh:
            with open(f"{prefix}_refresh.txt", "w") as f:
                f.write(new_refresh)
        print(f"\n  Saved tokens with prefix '{prefix}_*.txt'")

    tip()


# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════

def main():
    args = parse_args(__name__)
    raw  = load_env(args.env_file)

    if args.list_policies:
        list_policies(raw)

    if not args.policy:
        die("--policy is required.\n  Use --list-policies to see available options.")

    cfg = build_config(args.policy, raw)

    # Resolve refresh token from either flag
    refresh_token = args.refresh_token
    if not refresh_token and args.refresh_token_file:
        refresh_token = read_refresh_token_file(args.refresh_token_file)

    if refresh_token:
        run_refresh_flow(cfg, refresh_token, args)
    else:
        run_auth_code_flow(cfg, args)




if __name__ == "__main__":
    main()