import jwt
import requests
import uuid


class TokenError(Exception):

    def __init__(self, message, status_code=400, *args, **kwargs):
        self.status_code = status_code
        Exception.__init__(self, *tuple([message] + list(args)), **kwargs)


class Mystique(object):

    __version__ = (0, 0, 1)

    HEADER_NAME = "X-Cerebro-Token"
    COOKIE = "mystique"
    SESSION = "session"
    TOKEN = "token"

    AZURE = "https://login.microsoftonline.com"
    AZURE_AUTHORISE = "{}/common/oauth2/authorize".format(AZURE)

    def __init__(self, client_id=None, client_secret=None, app_token=None,
                 auth_server=None, auth_secret=None,
                 bastion_server=None, bastion_secret=None,
                 data_server=None, data_secret=None):

        self.client_id = client_id
        self.client_secret = client_secret
        self.app_token = app_token

        self.auth_server = auth_server
        self.auth_secret = auth_secret
        self.bastion_server = bastion_server
        self.bastion_secret = bastion_secret
        self.data_server = data_server
        self.data_secret = data_secret

        self.redirect_uri = "{}/{}".format(self.auth_server, "oauth2")
        self.azure_token = "{}/{}/oauth2/token".format(
            self.AZURE, self.app_token)

    @classmethod
    def build(cls, env):
        """
        Makes it easy to invoke an instance of Mystique by simply passing in the
        environment:

          mystique = Mystique.build(os.eviron)
        """
        return cls(
            client_id=env.get("CLIENT_ID"),
            client_secret=env.get("CLIENT_SECRET"),
            app_token=env.get("APP_TOKEN"),
            auth_server=env.get("AUTH_SERVER"),
            auth_secret=env.get("AUTH_SECRET"),
            bastion_server=env.get("BASTION_SERVER"),
            bastion_secret=env.get("BASTION_SECRET"),
            data_server=env.get("DATA_SERVER"),
            data_secret=env.get("DATA_SECRET"),
        )

    # Auth

    def get_auth_url(self, state):
        """
        Strictly speaking, the `state` parameter is optional, but as it
        protects against XSS attacks, we're making it mandatory here.

        :param state:         (str) A random string, verified by the auth
                                    server when Azure bounces the user back
                                    there.
        """
        return requests.Request("GET", self.AZURE_AUTHORISE, params={
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "state": state
        }).prepare().url

    def get_auth_cookie(self, code):
        """
        Set the auth cookie before sending the response to the user.

        :param code:     (str)      The big long string that Azure sends back
                                    along with the client to the auth server.
        """
        return jwt.encode(
            {"code": code, "nonce": str(uuid.uuid4())},
            self.auth_secret
        )

    # Bastion

    def get_bastion_redirect_url(self, nxt):
        """
        The URL we bounce users too if they don't have a cookie.  Strictly
        speaking, this shouldn't happen because users should never come
        directly to the bastion, but it's entirely likely that the UI will hit
        a bastion URL as a means of testing whether the user has a cookie or
        not.

        :param nxt: (str) The URL you want the user to return to after she's
                          been authenticated.  Typically, this is the URL
                          they're trying to visit on the bastion host.
        """
        return requests.Request("GET", self.auth_server, params={
            "next": "{}{}".format(self.bastion_server, nxt)
        }).prepare().url

    def get_data_response(self, path, args, token):
        """
        Hit the data server with the request that hit the bastion server,
        taking care to include a header with the right auth data, signed by the
        bastion server.

        :param path: (str) The URL path
        :param args: (dict) The arguments (if any)
        :param token: (str) The jwt for auth on the data end
        """
        return requests.get(
            self.data_server + path,
            params=args,
            headers={
                self.HEADER_NAME: jwt.encode(
                    {self.TOKEN: token},
                    self.bastion_secret
                )
            }
        )

    def generate_bastion_cookie(self, headers):
        """
        The data server is expected to include a special header in all of its
        responses that we then need to convert to a cookie for the bastion's
        response to the client.

        :param headers: (dict) All of the headers returned from the data
                               server.
        """
        return headers[self.HEADER_NAME]

    # Data

    def get_token_from_headers(self, headers):
        """
        Try to find and decode the auth token data in the request header.

        :param headers: A dictionary of headers in the request.
        """

        # No header: fail
        if self.HEADER_NAME not in headers:
            raise TokenError("No bastion token specified", status_code=403)

        try:
            return jwt.decode(headers[self.HEADER_NAME], self.bastion_secret)
        except jwt.InvalidTokenError:
            raise TokenError("No valid bastion token found")

    def get_identity_from_nested_token(self, bastion):
        """
        This method isn't always necessary, as most requests will contain a
        session value rather than an auth token.  The first request however
        will only contain an auth token, so the data server will need to
        validate it against the Azure AD web service and return some identity
        information from what it finds there.

        :param bastion: (dict) The decoded jwt from the bastion request
        """

        if "token" not in bastion:
            raise TokenError("The bastion token was malformed")

        try:
            auth = jwt.decode(bastion[self.TOKEN], self.auth_secret)
        except jwt.InvalidTokenError:
            raise TokenError("No valid auth token found")

        if "code" not in auth:
            raise TokenError("The auth token was malformed")

        # Get user data from Azure
        response = requests.post(self.azure_token, {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": auth["code"],
            "grant_type": "authorization_code",
            "redirect_uri": self.redirect_uri,
            "resource": "https://graph.windows.net"
        })

        if response.status_code >= 300:
            raise TokenError(response.text, response.status_code)

        # Parse that user data for useful information
        return jwt.decode(response.json()["id_token"], verify=False)

    def generate_session_token(self, session):
        """
        The session id is created by the data server, but we roll it into a jwt
        before sending it back to the bastion server.  Mostly this is just a
        convenience so that when it comes back with a later request, we know
        that whatever is in the header, it's always a jwt, regardless of what
        it contains.

        :param session: (str) A session id
        """
        return jwt.encode({self.SESSION: session}, self.bastion_secret)
