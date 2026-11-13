import textwrap

from fastapi import FastAPI, Response
from fastapi.responses import HTMLResponse

from app_gateway.auth_server.routes import authorize, metadata, token

app = FastAPI(openapi_url=None)

app.include_router(metadata.router)
app.include_router(authorize.router)
app.include_router(token.router)


@app.get("/")
async def oauth_issuer() -> Response:
    return HTMLResponse(
        textwrap.dedent("""\
            <pre style="font-family: 'Courier'">
            ████████████████████████
            ██                    ██
            ██  ████████████████  ██
            ██  ▒▒██▒▒██▒▒██████  ██
            ██  ████████████████  ██
            ██  ██▒▒▒▒██▒▒▒▒████  ██
            ██  ████████████████  ██
            ██  ████████████████  ██
            ██                    ██
            ████████████████████████
                    ████████
              ████████████████████
            ██████  ██  ██  ██  ████
            ████  ██  ██  ██  ██████
            ████████████████████████
            </pre>"""),
        headers={"cache-control": "public, max-age=3600"},
    )
