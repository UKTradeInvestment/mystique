import jwt
import responses

from unittest import TestCase
from urllib.parse import urlparse

from ukti.datahub.mystique import Mystique, TokenError


class MystiqueTestCase(TestCase):

    def setUp(self):

        self.mystique = Mystique(
            client_id="client-id",
            client_secret="client-secret",
            app_token="app-token",
            auth_server="http://localhost:5000",
            auth_secret="auth-secret",
            bastion_server="http://localhost:5001",
            bastion_secret="bastion-secret",
            data_server="http://localhost:5002",
        )

        # Force the class variables to something we control for these tests

    def test_get_auth_url(self):
        self.assertEqual(
            set(urlparse(self.mystique.get_auth_url("state")).query.split("&")),
            {
                "response_type=code",
                "client_id=client-id",
                "redirect_uri=http%3A%2F%2Flocalhost%3A5000%2Foauth2",
                "state=state"
            }
        )

    def test_get_auth_cookie(self):
        code = "my-code"
        secret = "some secret"
        self.mystique.auth_secret = secret
        self.assertEqual(
            jwt.decode(self.mystique.get_auth_cookie(code), secret)["code"],
            code
        )

    def test_get_bastion_redirect_url(self):
        self.mystique.bastion_server = "http://localhost:5001"
        self.assertEqual(
            urlparse(self.mystique.get_bastion_redirect_url("/w00t")).query,
            "next={}".format("http%3A%2F%2Flocalhost%3A5001%2Fw00t")
        )

    @responses.activate
    def test_get_identity_from_nested_token(self):

        self.mystique.auth_secret = "secret"

        responses.add(
            responses.POST,
            "https://login.microsoftonline.com/app-token/oauth2/token",
            body='{"id_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJvaWQiO'
                 'jEyMywiZmFtaWx5X25hbWUiOiJGYW1pbHkiLCJnaXZlbl9uYW1lIjoiR2l2Z'
                 'W4ifQ.MDfAGcDi7XjNhbLnEkQHexOnbzPsSVbSfBRrjkVT4xI"}',
            status=200,
            content_type='application/json'
        )

        info = self.mystique.get_identity_from_nested_token({
            "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjb2RlIjoidGhpcyB"
                     "pcyBhIGNvZGUifQ.piTpeboWlE6pYu7t6hHI2mNECvuLtDNp2RAIDDoi"
                     "JP4"
        })

        self.assertEqual(info["oid"], 123)
        self.assertEqual(info["family_name"], "Family")
        self.assertEqual(info["given_name"], "Given")

        # Expected exceptions
        with self.assertRaises(TokenError):
            self.mystique.get_identity_from_nested_token({"not-a-token": "x"})
        with self.assertRaises(TokenError):
            self.mystique.get_identity_from_nested_token({"token": "broken"})
        with self.assertRaises(TokenError):
            self.mystique.get_identity_from_nested_token({
                "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJub3QiOiJhIHR"
                         "va2VuIn0.YxSUDNLukXozOo3JbXsr8XvCzAsa13ZK0vtF2nX-wn4"
            })
