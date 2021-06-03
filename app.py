import os
import json
from typing import Optional
import httpx
from fastapi import FastAPI, Request, Response
from dotenv import load_dotenv
from authlib.jose import JWTClaims, jwt, KeySet


from authlib.integrations.starlette_client import OAuth

load_dotenv()
app = FastAPI()
oauth = OAuth(app)
domain = os.getenv('AUTH0_DOMAIN')
auth0_discovery_url = f'https://{domain}/.well-known/openid-configuration'


ks = None
r = httpx.get(auth0_discovery_url)
if r.status_code == 200:
    auth0_config = json.loads(r.text)
    jwks_resp = httpx.get(auth0_config['jwks_uri'])
    ks = KeySet(json.loads(jwks_resp.text)['keys'])

    """ auth0 = oauth.register(
        'auth0',
        # client_id='YOUR_CLIENT_ID',
        # client_secret='YOUR_CLIENT_SECRET',
        api_base_url=f'https://{domain}',
        access_token_url=f'https://{domain}/oauth/token',
        authorize_url=f'https://{domain}/authorize',
        # client_kwargs={
        #    'scope': 'openid profile email',
        # },
    ) """
else:
    print('get config from discovery url failed')
    exit()


@app.middleware("http")
async def check_jwt(request: Request, call_next):
    auth: str = request.headers.get('Authorization')
    token = None
    if auth:
        token = auth.split(' ')[1]
    if not token:
        return Response('Unauthorized', 401)

    claims = jwt.decode(token, ks)
    try:
        claims.validate()
    except Exception as e:
        print(e)
        return Response('Unauthorized', 401)

    response = await call_next(request)
    return response


@app.get("/")
def read_root():

    return {"Hello": "World"}


@app.get("/items/{item_id}")
def read_item(item_id: int, q: Optional[str] = None):
    return {"item_id": item_id, "q": q}
