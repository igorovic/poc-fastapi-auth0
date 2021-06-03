import os
import json
from typing import Optional
import httpx
from fastapi import FastAPI, Request, Response, Security, status, HTTPException, Depends
from fastapi.security import SecurityScopes
from dotenv import load_dotenv
from authlib.jose import JWTClaims, jwt, KeySet
from authlib.jose.errors import DecodeError, ExpiredTokenError
from oAuthTokenBearer import OAuth2TokenBearer


load_dotenv()
app = FastAPI()

domain = os.getenv('AUTH0_DOMAIN')
auth0_discovery_url = f'https://{domain}/.well-known/openid-configuration'


ks = None
auth0_config = None
r = httpx.get(auth0_discovery_url)
if r.status_code == 200:
    auth0_config = json.loads(r.text)
    jwks_resp = httpx.get(auth0_config['jwks_uri'])
    ks = KeySet(json.loads(jwks_resp.text)['keys'])
else:
    print('get config from discovery url failed')
    exit()

oauth2_scheme = OAuth2TokenBearer(tokenUrl=auth0_config["token_endpoint"])


async def check_jwt(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="JWT credentials failed",
        headers={"WWW-Authenticate": "Bearer"},
    )
    payload = {}
    try:
        payload = jwt.decode(token, ks)
        payload.validate()
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except ExpiredTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except DecodeError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception as e:
        print(e)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="OAuth Authorization failure",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return payload


async def check_permissions(security_scopes: SecurityScopes, jwt_payload=Depends(check_jwt)):
    jwt_permissions: list[str] = jwt_payload['permissions']
    for scope in security_scopes.scopes:
        if(not scope in jwt_permissions):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing permissions [" +
                security_scopes.scope_str + "]",
                headers={"WWW-Authenticate": "Bearer"},
            )

    return jwt_permissions

""" async def get_permissions(request: Request, call_next):
    print('check_permissions')
    print(request)
    return await call_next(request)


@app.middleware("http")
async def check_jwt(request: Request, call_next):
    print('check_jwt')
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
    return response """


@app.get("/")
def read_root():
    # Not secured
    return {"Hello": "World"}


@app.get("/items/{item_id}")
def read_item(item_id: int, q: Optional[str] = None, permissions=Security(check_permissions, scopes=['read:items'])):
    # Secured
    print('permissions ', permissions)
    return {"item_id": item_id, "q": q}
