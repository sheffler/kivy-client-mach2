#
# An NLIP client that uses a 401 response to query the user for authenticaiton
#
# RFC2617 Sect 1.2 states that "if a prior request has been authorized" ... the same credentials
# may be reused.

import httpx
from urllib.parse import urlparse

from nlip_sdk.nlip import NLIP_Message

class AuthenticatingNlipAsyncClient:

    def __init__(self, base_url: str):
        self.base_url = base_url

        u = urlparse(base_url)

        if u.scheme == "unix":
            self.transport = httpx.AsyncHTTPTransport(uds=self.unix_path(u.hostname))
            self.client = httpx.AsyncClient(transport=self.transport)
            self.base_url = u._replace(scheme="http").geturl()
        else:
            self.transport = httpx.AsyncHTTPTransport()
            self.client = httpx.AsyncClient(transport=self.transport)
        self.recursion = 0

        self.on_login_elicitation = None  # obtain username/password
        self.on_bearer_elicitation = None # obtain bearer token

    def unix_path(self, name:str):
        "For a unix: scheme, the path of the socket"
        return f"/tmp/agent-{name}.sock"

    # add basic auth to the client and recreate it
    def add_basic_auth(self, username: str, password: str):
        auth = httpx.BasicAuth(username=username, password=password)
        self.client = httpx.AsyncClient(auth=auth, transport=self.transport)

    # add digest auth to the client and recreate it
    def add_digest_auth(self, username: str, password: str):
        auth = httpx.DigestAuth(username=username, password=password)
        self.client = httpx.AsyncClient(auth=auth, transport=self.transport)

    # add digest auth to the client and recreate it
    def add_bearer_token(self, bearer: str):
        headers = { "Authorization" : f"Bearer {bearer}" }
        self.client = httpx.AsyncClient(headers=headers, transport=self.transport)

    # register an elicitation for username/password
    def on_login_requested(self, on_login_elicitation):
        print(f"ON LOGIN REQUESTED")
        self.on_login_elicitation = on_login_elicitation

    # call the elicitation and get the credentials
    async def elicit_login_credentials(self):
        print(f"ELICIT LOGIN CREDENTIALS")
        if self.on_login_elicitation:
            (username, password) = await self.on_login_elicitation(self)
            return (username, password)
        else:
            print(f"NO LOGIN HANDLER REGISTERED")
            return ("", "")

    # register an elicitation for username/password
    def on_bearer_requested(self, on_bearer_elicitation):
        print(f"ON BEARER REQUESTED")
        self.on_bearer_elicitation = on_bearer_elicitation

    # call the elicitation and get the credentials
    async def elicit_bearer_credentials(self):
        print(f"ELICIT BEARER CREDENTIALS")
        if self.on_bearer_elicitation:
            bearer = await self.on_bearer_elicitation(self)
            return bearer
        else:
            print(f"NO BEARER HANDLER REGISTERED")
            return ""

    @classmethod
    def create_from_url(cls, base_url:str):
        return AuthenticatingNlipAsyncClient(base_url)

    async def Xasync_send(self, msg:NLIP_Message) -> NLIP_Message:
        response = await self.client.post(self.base_url, json=msg.to_dict(), timeout=120.0, follow_redirects=True)
        data = response.raise_for_status().json()
        nlip_msg = NLIP_Message(**data)
        return nlip_msg

    async def async_send(self, msg:NLIP_Message) -> NLIP_Message:
        self.recursion = 0
        return await self._async_send(msg)
        
    async def _async_send(self, msg:NLIP_Message) -> NLIP_Message:
        print(f"ASYNC_SEND")
        try:
            response = await self.client.post(self.base_url, json=msg.to_dict(), timeout=120.0, follow_redirects=True)
            response.raise_for_status() # raise an exception if status
            data = response.json()
            nlip_msg = NLIP_Message(**data)
            return nlip_msg

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                print(f"401 Headers:{e.response.headers}")
                self.recursion += 1
                if self.recursion > 4:
                    raise Exception(f"Too many login tries:{self.recursion}")
                else:
                    if e.response.headers.get('www-authenticate', None) is not None:
                        scheme = e.response.headers.get('www-authenticate')
                        print(f"Authentication Required:{scheme}.  Requesting Credentials")
                        if scheme == 'Basic':
                            future = self.elicit_login_credentials()
                            (username, password) = await future
                            self.add_basic_auth(username, password)
                        elif scheme.startswith('Digest'):
                            future = self.elicit_login_credentials()
                            (username, password) = await future
                            self.add_digest_auth(username, password)
                        elif scheme.startswith('Bearer'):
                            future = self.elicit_bearer_credentials()
                            bearer = await future
                            self.add_bearer_token(bearer)
                        else:
                            raise Exception(f"Unrecognized header: www-authenticate:{scheme}")

                        # send the message again with the authorization
                        return await self._async_send(msg)
                    else:
                        raise e

            else:
                raise e
        
