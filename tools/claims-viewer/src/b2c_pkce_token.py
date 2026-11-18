#!/usr/bin/env python3
"""
B2C PKCE Token & Claims Lifecycle Lab
======================================

Interactively walks through:
  1. Build PKCE pair + /authorize URL (you log in via browser)
  2. Exchange authorization code -> id_token, access_token, refresh_token
  3. Use refresh_token -> new id_token, access_token, refresh_token
  4. Decode & diff claims across issuance #1 vs #2

NOTE: Claims are decoded WITHOUT signature verification. This script is for
inspecting claim lifecycle only -- never trust unverified claims in production.
Real validation requires fetching the B2C JWKS and verifying signature, iss,
aud, exp, nbf.

Dependencies: pip install requests
(PyJWT not required -- we decode manually to avoid extra deps)
"""

import base64
import hashlib
import json
import secrets
import urllib.parse
import webbrowser
import requests
from  b2c_utils.config import load_env, build_config,list_policies,die,parse_args
raw  = load_env("../config/nprd.env")
# API
TENANT_NAME = raw.get("TENANT")  
POLICY = raw.get("POLICY_SIGNINADPTIVE")   
CLIENT_ID = raw.get("CLIENT_ID")
REDIRECT_URI =   raw.get("REDIRECT_JWT_URI")
SCOPES = raw.get("SCOPES")
LOGIN_HINT=raw.get("LOGIN_HINT")
AUTHORITY = f"https://{TENANT_NAME}.b2clogin.com/{TENANT_NAME}.onmicrosoft.com/{POLICY}"
AUTHORIZE_ENDPOINT = f"{AUTHORITY}/oauth2/v2.0/authorize"
TOKEN_ENDPOINT = f"{AUTHORITY}/oauth2/v2.0/token"

1
# ------------------------------------------------------------------------
# PKCE helpers
# ------------------------------------------------------------------------
def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def generate_pkce_pair():
    code_verifier = b64url(secrets.token_bytes(32))
    code_challenge = b64url(hashlib.sha256(code_verifier.encode("ascii")).digest())
    return code_verifier, code_challenge


def decode_jwt_claims(token: str) -> dict:
    """Decode JWT payload WITHOUT verifying signature. Inspection only."""
    try:
        payload_b64 = token.split(".")[1]
        padding = "=" * (-len(payload_b64) % 4)
        payload_bytes = base64.urlsafe_b64decode(payload_b64 + padding)
        return json.loads(payload_bytes)
    except Exception as e:
        return {"_decode_error": str(e), "_raw_prefix": token[:20]}


# ------------------------------------------------------------------------
# Step 1: Build authorize URL
# ------------------------------------------------------------------------
def build_authorize_url():
    code_verifier, code_challenge = generate_pkce_pair()
    state = b64url(secrets.token_bytes(16))
    nonce = b64url(secrets.token_bytes(16))

    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "response_mode": "query",
        "scope": SCOPES,
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "login_hint":LOGIN_HINT,
    }
    url = f"{AUTHORIZE_ENDPOINT}?{urllib.parse.urlencode(params)}"
    return url, code_verifier, state, nonce


# ------------------------------------------------------------------------
# Step 2: Exchange code for tokens
# ------------------------------------------------------------------------
def exchange_code_for_tokens(code: str, code_verifier: str) -> dict:
    data = {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "scope": " ".join(SCOPES),
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": code_verifier,
    }
    resp = requests.post(TOKEN_ENDPOINT, data=data)
    resp.raise_for_status()
    return resp.json()


# ------------------------------------------------------------------------
# Step 3: Refresh -- scope-driven, so you control what comes back
# ------------------------------------------------------------------------
# What you get back from a refresh_token grant is entirely a function of the
# `scope` you send, same as the original request:
#   scope contains "openid"          -> id_token issued
#   scope contains a resource scope  -> access_token issued for that resource
#   scope contains "offline_access"  -> a (usually rotated) refresh_token issued
# Ask for only what you want to inspect; the others simply won't appear in
# the response. This lets you test "does refresh reissue the id_token even
# if I only asked for the access token?" (answer: no -- B2C only returns
# what's in scope) and similar on-demand questions.
API_SCOPES = [s for s in SCOPES if s not in ("openid", "offline_access", "profile")]

SCOPE_PRESETS = {
    "1": ("ID token only", ["openid", "offline_access"]),
    "2": ("Access token only", API_SCOPES + ["offline_access"] if API_SCOPES else ["offline_access"]),
    "3": ("Both ID + access token", ["openid", "offline_access"] + API_SCOPES),
}


def refresh_tokens(refresh_token: str, scopes: list) -> dict:
    data = {
        "grant_type": "refresh_token",
        "client_id": CLIENT_ID,
        "scope": " ".join(scopes),
        "refresh_token": refresh_token,
    }
    resp = requests.post(TOKEN_ENDPOINT, data=data)
    resp.raise_for_status()
    return resp.json()


def choose_refresh_scope() -> list:
    print("\nWhat do you want the refresh to return?")
    for key, (label, scopes) in SCOPE_PRESETS.items():
        print(f"  {key}) {label}  (scope: {' '.join(scopes)})")
    print("  4) Custom scope string")
    print("  q) Done refreshing")
    choice = input("Choice: ").strip().lower()
    if choice == "q":
        return None
    if choice == "4":
        raw = input("Enter space-separated scopes (include offline_access to keep the chain alive): ").strip()
        return raw.split()
    if choice in SCOPE_PRESETS:
        return SCOPE_PRESETS[choice][1]
    print("Unrecognized choice, defaulting to 'Both'.")
    return SCOPE_PRESETS["3"][1]


# ------------------------------------------------------------------------
# Step 4: Diff claim sets
# ------------------------------------------------------------------------
def diff_claims(label: str, claims_1: dict, claims_2: dict):
    keys = sorted(set(claims_1) | set(claims_2))
    print(f"\n--- {label}: claim diff (issuance #1 vs #2) ---")
    print(f"{'claim':<20} {'issuance #1':<30} {'issuance #2':<30} status")
    for k in keys:
        v1 = claims_1.get(k, "<absent>")
        v2 = claims_2.get(k, "<absent>")
        if k not in claims_1:
            status = "ADDED on refresh"
        elif k not in claims_2:
            status = "DROPPED on refresh"
        elif v1 == v2:
            status = "unchanged"
        else:
            status = "CHANGED"
        print(f"{k:<20} {str(v1)[:28]:<30} {str(v2)[:28]:<30} {status}")


def print_claims(label: str, claims: dict):
    print(f"\n--- {label} claims ---")
    print(json.dumps(claims, indent=2))


# ------------------------------------------------------------------------
# Main interactive flow
# ------------------------------------------------------------------------
def main():
    print("=" * 70)
    print("STEP 1: Authorization request (PKCE)")
    print("=" * 70)
    auth_url, code_verifier, state, nonce = build_authorize_url()
    print(f"\nAuthorize URL (state={state[:8]}..., nonce={nonce[:8]}...):\n")
    print("AUTHURL",auth_url)
    print("\nOpen this URL in your browser, sign in, then copy the FULL")
    print("redirect URL you land on (it contains ?code=...&state=...).")
    try:
        webbrowser.open(auth_url)
    except Exception:
        pass

    redirected_url = input("\nPaste the full redirect URL here: ").strip()
    parsed = urllib.parse.urlparse(redirected_url)
    qs = urllib.parse.parse_qs(parsed.query)
    code = qs.get("code", [None])[0]
    returned_state = qs.get("state", [None])[0]

    if not code:
        print("No 'code' found in the pasted URL. Aborting.")
        return
    if returned_state != state:
        print("WARNING: state mismatch -- possible CSRF or stale URL. Aborting.")
        return

    print("\n" + "=" * 70)
    print("STEP 2: Exchange code for tokens (grant_type=authorization_code)")
    print("=" * 70)
    tokens_1 = exchange_code_for_tokens(code, code_verifier)

    id_claims_1 = decode_jwt_claims(tokens_1["id_token"]) if "id_token" in tokens_1 else {}
    access_claims_1 = (
        decode_jwt_claims(tokens_1["access_token"])
        if "access_token" in tokens_1 and tokens_1["access_token"].count(".") == 2
        else {"_note": "access_token is opaque (not a JWT) -- no claims to decode"}
    )
    refresh_token_1 = tokens_1.get("refresh_token")

    print_claims("ID token (issuance #1)", id_claims_1)
    print_claims("Access token (issuance #1)", access_claims_1)
    print(f"\nRefresh token present: {bool(refresh_token_1)}")

    # Sanity check: nonce should match what we sent
    if id_claims_1.get("nonce") == nonce:
        print("[OK] id_token nonce matches the one we sent in the authorize request.")

    if not refresh_token_1:
        print("\nNo refresh_token returned -- did you include 'offline_access' in SCOPES?")
        return

    print("\n" + "=" * 70)
    print("STEP 3: Refresh on demand (grant_type=refresh_token)")
    print("=" * 70)
    print("You'll be asked each round what to request. Run it several times")
    print("to see rotation and claim lifecycle across multiple refreshes.")

    current_refresh_token = refresh_token_1
    # "last seen" trackers, seeded with issuance #1, so round 1's diff is
    # always against the original code-exchange tokens
    last_id_claims = id_claims_1
    last_access_claims = access_claims_1 if "_note" not in access_claims_1 else None
    round_num = 1

    while True:
        scopes = choose_refresh_scope()
        if scopes is None:
            break

        print(f"\n--- Refresh round {round_num}: scope = '{' '.join(scopes)}' ---")
        tokens_n = refresh_tokens(current_refresh_token, scopes)

        got_id = "id_token" in tokens_n
        got_access = "access_token" in tokens_n
        print(f"Server returned: id_token={got_id}, access_token={got_access}, "
              f"refresh_token={'refresh_token' in tokens_n}")

        if got_id:
            id_claims_n = decode_jwt_claims(tokens_n["id_token"])
            print_claims(f"ID token (round {round_num})", id_claims_n)
            if last_id_claims is not None:
                diff_claims(f"ID token (prev -> round {round_num})", last_id_claims, id_claims_n)
            last_id_claims = id_claims_n
        else:
            print("(No id_token in response -- 'openid' wasn't in the requested scope.)")

        if got_access and tokens_n["access_token"].count(".") == 2:
            access_claims_n = decode_jwt_claims(tokens_n["access_token"])
            print_claims(f"Access token (round {round_num})", access_claims_n)
            if last_access_claims is not None:
                diff_claims(f"Access token (prev -> round {round_num})", last_access_claims, access_claims_n)
            last_access_claims = access_claims_n
        elif got_access:
            print("(access_token returned but is opaque -- no claims to decode.)")
        else:
            print("(No access_token in response -- no resource scope was requested.)")

        # Refresh tokens usually rotate -- always adopt the newest one, and
        # keep using it even if this round didn't ask for offline_access
        # explicitly (some tenants still rotate; if not, the old one is reused).
        if "refresh_token" in tokens_n:
            current_refresh_token = tokens_n["refresh_token"]
            print("[rotation] New refresh_token issued -- using it for the next round.")
        else:
            print("[rotation] No new refresh_token returned -- reusing the previous one.")

        round_num += 1

    print("\nDone. Reminder: none of this validated signatures -- for that,")
    print("fetch the JWKS from:")
    print(f"  {AUTHORITY}/discovery/v2.0/keys")
    print("and verify signature + iss + aud + exp + nbf before trusting claims.")


if __name__ == "__main__":
    main()
