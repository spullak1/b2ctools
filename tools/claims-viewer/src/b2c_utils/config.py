import os
import sys
import argparse

# ═══════════════════════════════════════════════════════════════
# ENV LOADER
# ═══════════════════════════════════════════════════════════════
CONFIG_DIR = os.path.join(
    os.path.dirname(__file__),
    "../../config"
)


ENV_FILE = os.path.join(CONFIG_DIR,"nprd.env")

def die(message: str):
    print(f"ERROR: {message}", file=sys.stderr)
    sys.exit(1)


def load_env(path: str) -> dict:
    """Parse a .env file into a dict."""
    if not os.path.exists(path):
        die(f"Config file not found: {path}")

    config = {}

    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            if "=" not in line:
                continue

            key, _, value = line.partition("=")
            config[key.strip()] = value.strip()

    return config


def build_config(policy_key: str, raw: dict) -> dict:

    def require(key: str):
        value = raw.get(key)

        if not value:
            die(f"Missing '{key}' in environment file")

        return value

    policy_env_key = f"POLICY_{policy_key.upper()}"
    policy_name = raw.get(policy_env_key)

    if not policy_name:
        available = [
            k.replace("POLICY_", "").lower()
            for k in raw
            if k.startswith("POLICY_")
        ]

        die(
            f"Policy '{policy_key}' not found.\n"
            f"Available: {', '.join(available)}"
        )

    tenant = require("TENANT")
    domain = require("DOMAIN")

    return {
        "tenant": tenant,
        "domain": domain,
        "client_id": require("CLIENT_ID"),
        "redirect_uri": require("REDIRECT_URI"),
        "scopes": require("SCOPES"),
        "login_hint": require("LOGIN_HINT"),
        "policy": policy_name,
        "auth_endpoint":
            f"https://{tenant}.b2clogin.com/"
            f"{domain}/{policy_name}/oauth2/v2.0/authorize",
        "token_endpoint":
            f"https://{tenant}.b2clogin.com/"
            f"{domain}/{policy_name}/oauth2/v2.0/token",
    }


def list_policies(raw: dict):
    print("\nPolicies defined:\n")

    for key, value in raw.items():
        if key.startswith("POLICY_"):
            short = key.removeprefix("POLICY_").lower()
            print(f"  --policy {short:<20} -> {value}")
            
            
# ═══════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════

def parse_args(fileName : str):
    parser = argparse.ArgumentParser(
        description="Fetch B2C id_token + access_token via PKCE auth-code flow, "
                     "or exchange a refresh_token directly.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Examples:\n"
            f"  python ${fileName} --policy signinAdaptive --env nprd\n"
            f"  python ${fileName} --policy changepsigninAdaptiveassword   --env nprd\n"
            f"  python ${fileName} --list-policies\n"
            "\n"
            f"  # Refresh-token troubleshooting (skip the browser steps):\n"
            f"  python b2c_get_tokens.py --policy signinAdaptive --env nprd \\\n"
            f"      --refresh-token \"eyJ...\"\n"
            f"  python ${fileName} --policy signinAdaptive --env nprd \\\n"
            f"      --refresh-token-file rt.txt --compare-id-token old_id.txt\n"
        ),
    )
    parser.add_argument(
        "--policy", "-p",
        metavar="POLICY",
        help="Policy key from nprd.env  e.g.  signinAdaptive  changepassword  ",
    )
    parser.add_argument(
        "--env", "-e",
        metavar="ENV",
        default="nonprd",
        choices=["nprd", "prd","xqa", "pqa"],
        help="Target environment:  nonprod (default)  |  prd",
    )
    parser.add_argument(
        "--env-file",
        metavar="PATH",
        default=ENV_FILE,
        help=f"Path to .env config file  (default: nprd.env next to script)",
    )
    parser.add_argument(
        "--list-policies",
        action="store_true",
        help="List all policies defined in nprd.env and exit",
    )
    parser.add_argument(
        "--refresh-token",
        metavar="TOKEN",
        help="Skip the auth-code flow and exchange this refresh_token instead.",
    )
    parser.add_argument(
        "--refresh-token-file",
        metavar="PATH",
        help="Same as --refresh-token but reads the value from a file.",
    )
    parser.add_argument(
        "--compare-id-token",
        metavar="PATH",
        help="Path to a file containing a previously-saved id_token (raw JWT). "
             "If given alongside --refresh-token(-file), prints a diff of which "
             "claims were added/dropped between that token and the refreshed one.",
    )
    parser.add_argument(
        "--save-tokens",
        metavar="PREFIX",
        help="Save returned id_token/access_token/refresh_token to "
             "PREFIX_id.txt / PREFIX_access.txt / PREFIX_refresh.txt "
             "so they can be reused later (e.g. with --compare-id-token).",
    )
    return parser.parse_args()