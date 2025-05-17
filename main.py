import random
import secrets
import time

from keycloak import KeycloakOpenID
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    RefreshToken,
    construct_redirect_uri,
)
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
from mcp.server.fastmcp.server import FastMCP
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from pydantic import AnyHttpUrl
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response

KEYCLOAK_SERVER_URL = "http://localhost:8080"
KEYCLOAK_REALM = "master"
KEYCLOAK_CLIENT_ID = "mcp"
KEYCLOAK_CLIENT_SECRET = "2moDkh5opHeDN4QZroovSrnzZhfmrWSR"


class MyOAuthServerProvider:
    def __init__(self) -> None:
        self.keycloak_openid = KeycloakOpenID(
            server_url=KEYCLOAK_SERVER_URL,
            client_id=KEYCLOAK_CLIENT_ID,
            realm_name=KEYCLOAK_REALM,
            client_secret_key=KEYCLOAK_CLIENT_SECRET,
        )
        self.tokens: dict[str, AccessToken] = {}
        self.clients: dict[str, OAuthClientInformationFull] = {}
        self.auth_codes: dict[str, AuthorizationCode] = {}
        self.state_mapping: dict[str, dict[str, str]] = {}
        self.token_mapping: dict[str, str] = {}

    async def get_client(self, client_id: str):
        # raise NotImplementedError
        return self.clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull):
        # raise NotImplementedError
        self.clients[client_info.client_id] = client_info

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ):
        state = params.state or secrets.token_hex(16)

        self.state_mapping[state] = {
            "redirect_uri": str(params.redirect_uri),
            "code_challenge": params.code_challenge,
            "redirect_uri_provided_explicitly": str(
                params.redirect_uri_provided_explicitly
            ),
            "client_id": client.client_id,
        }

        auth_url = self.keycloak_openid.auth_url(
            redirect_uri="http://localhost:8000/auth/callback",
            state=state,
        )

        return auth_url

    async def handle_auth_callback(self, code: str, state: str) -> str:
        """Handle GitHub OAuth callback."""
        state_data = self.state_mapping.get(state)
        if not state_data:
            raise HTTPException(400, "Invalid state parameter")

        redirect_uri = state_data["redirect_uri"]
        code_challenge = state_data["code_challenge"]
        redirect_uri_provided_explicitly = (
            state_data["redirect_uri_provided_explicitly"] == "True"
        )
        client_id = state_data["client_id"]
        keycloak_token = await self.keycloak_openid.a_token(
            grant_type="authorization_code",
            code=code,
            redirect_uri="http://localhost:8000/auth/callback",
        )

        keycloak_token = keycloak_token["access_token"]

        new_code = f"mcp_{secrets.token_hex(16)}"
        auth_code = AuthorizationCode(
            code=new_code,
            client_id=client_id,
            redirect_uri=AnyHttpUrl(redirect_uri),
            redirect_uri_provided_explicitly=redirect_uri_provided_explicitly,
            expires_at=time.time() + 300,
            scopes=["fortune"],
            code_challenge=code_challenge,
        )
        self.auth_codes[new_code] = auth_code

        self.tokens[keycloak_token] = AccessToken(
            token=keycloak_token,
            client_id=client_id,
            scopes=["email", "profile"],
            expires_at=None,
        )
        del self.state_mapping[state]
        return construct_redirect_uri(redirect_uri, code=new_code, state=state)

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        return self.auth_codes.get(authorization_code)

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ):
        if authorization_code.code not in self.auth_codes:
            raise ValueError("Invalid authorization code")

        mcp_token = f"mcp_{secrets.token_hex(32)}"

        self.tokens[mcp_token] = AccessToken(
            token=mcp_token,
            client_id=client.client_id,
            scopes=authorization_code.scopes,
            expires_at=int(time.time()) + 3600,
        )

        del self.auth_codes[authorization_code.code]

        return OAuthToken(
            access_token=mcp_token,
            token_type="bearer",
            expires_in=3600,
            scope=" ".join(authorization_code.scopes),
        )

    async def load_refresh_token(self, client, refresh_token):
        """Load a refresh token - not supported."""
        return None

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        """Exchange refresh token"""
        raise NotImplementedError("Not supported")

    async def load_access_token(self, token: str) -> AccessToken | None:
        access_token = self.tokens.get(token)
        if not access_token:
            return None

        if access_token.expires_at and access_token.expires_at < time.time():
            del self.tokens[token]
            return None

        return access_token

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        # Tokenを無効化する処理
        if token.token in self.tokens:
            del self.tokens[token.token]


oauth_provider = MyOAuthServerProvider()
mcp = FastMCP(
    "auth app",
    auth_server_provider=oauth_provider,
    auth=AuthSettings(
        issuer_url=AnyHttpUrl("http://localhost:8000"),
        client_registration_options=ClientRegistrationOptions(
            enabled=True,
            client_secret_expiry_seconds=3600,
            valid_scopes=["fortune"],
            default_scopes=["fortune"],
        ),
        required_scopes=["fortune"],
    ),
    host="localhost",
    port=8000,
    debug=True,
)


@mcp.custom_route("/auth/callback", methods=["GET"])
async def auth_callback_handler(request: Request) -> Response:
    code = request.query_params.get("code")
    state = request.query_params.get("state")

    if not code or not state:
        raise HTTPException(400, "Missing code or state parameter")

    try:
        redirect_uri = await oauth_provider.handle_auth_callback(code, state)
        return RedirectResponse(status_code=302, url=redirect_uri)
    except HTTPException:
        raise
    except Exception:
        return JSONResponse(
            status_code=500,
            content={
                "error": "server_error",
                "error_description": "Unexpected error",
            },
        )


@mcp.tool()
def fortune():
    fortunes = [
        "大吉",
        "中吉",
        "小吉",
        "吉",
        "末吉",
        "凶",
        "大凶",
    ]
    fortune = random.choice(fortunes)

    return f"今日の運勢は: {fortune}"


if __name__ == "__main__":
    mcp.run(transport="sse")
