# Mystique (library)

The Microsoft Active Directory library interface component of the multi-part
authentication system for Cerebro.


## Request Path

![Diagram of the Authentication Path](auth-path.png)

1. User visits the UI where we make the first request to the bastion
   host for user data.  This request should be rejected of course, since
   we presently don't have any cookie containing session data.

   Integration test at [bastion.tests.BastionTestCase.test_cookie_rejection](https://github.com/UKTradeInvestment/crm-veritas/blob/master/bastion/tests.py#L31)

2. The bastion server dropped a 400 bomb, rejecting the request on
   account of the fact that a cookie wasn't included.

3. The UI now gets to decide if they will simply bounce the user to
   the URL in the bastion server's response or if they'll modify the
   `next=` value first.  Either way, we bounce the user to the auth
   server, with a next= value so we know where to return them when
   they're ready.

   It's important to note that the redirect URL in the body of the
   bastion response is only a recommendation.  There's nothing
   stopping the UI server from setting `next=https://my-ui.com/xyz`.
   This is just where the auth server will drop a user once they have
   the auth token in their cookie jar.

   Integration test at [auth.tests.AuthTestCase.index](https://github.com/UKTradeInvestment/crm-veritas/blob/master/auth/tests.py#L28).

4. The user follows the redirect to Microsoft to do their authentication
   gymnastics.

5. Microsoft drops the user back at the auth server at a new url
   (`/oauth2`) with a very long string value (`code=`).

6. We take the arguments from the bounce from Micros~1 and make sure
   that everything looks legit, and if it does, we roll the value of
   `code=` into a jwt, stuff that into a cookie, and return the user
   to whatever they had in `next=`.

   Integration test at [auth.tests.AuthTestCase.oauth2](https://github.com/UKTradeInvestment/crm-veritas/blob/master/auth/tests.py#L60).

7. The UI sends a new request to the bastion server.  As this request
   is accompanied by a cookie, it's accepted.

   Integration test at [bastion.tests.BastionTestCase.test_good_data_response](https://github.com/UKTradeInvestment/crm-veritas/blob/master/bastion/tests.py#L62).

8. The bastion server creates another jwt using its own secret and
   stuffs the auth server jwt into it. It includes this in a header when
   it relays the request to the data server.

   Integration test at [bastion.tests.BastionTestCase.test_good_data_response](https://github.com/UKTradeInvestment/crm-veritas/blob/master/bastion/tests.py#L62).
   
9. The data server receives the request and checks for a session cookie,
   finding nothing, it then looks for an auth token, aka our
   aforementioned nested jwt.

   Finding the auth token, it then unpacks and verifies both the bastion
   signature and the auth signature, finally taking the Big Long String
   in there (originally `codee=`) and hits up Azure with a request
   asking for user data tied to that blob.

   Unit test at [veritas.tests.VeritasTestCase.test_get_identity_from_nested_token](https://github.com/UKTradeInvestment/crm-veritas/blob/master/veritas/tests.py#L55).

10. Azure responds with a bunch of user data bundled as another jwt
   which the data server then unpacks and uses to identify/create a user
   in its local data store.

   Unit test at [veritas.tests.VeritasTestCase.test_get_identity_from_nested_token](https://github.com/UKTradeInvestment/crm-veritas/blob/master/veritas/tests.py#L55).

11. The data server responds with the data requested, and includes a new
   session id to be passed up the chain to the browser.

12. The bastion server passes on this session id to the UI, where it can
   be used for future requests, allowing the data server to skip the
   network-intensive portion of step 9.


## Setup

We're using the super-handy [dotenv](https://github.com/theskumar/python-dotenv)
library, so setting up can either be done by setting environment
variables the old fashioned way or by placing the required values into
a filed called `/etc/veritas.conf`:

    AUTH_SERVER="http://localhost:5000"
    BASTION_SERVER="http://localhost:5001"
    DATA_SERVER="http://localhost:5002"

    AUTH_SECRET="this is a different secret"
    BASTION_SECRET="this is a secret"
    CLIENT_ID="<comes from Azure>"
    CLIENT_SECRET="<comes from Azure>"
    APP_TOKEN="<comes from Azure>"


## Running

There are three components here, but only one should be considered the
the actual Veritas server:

* `auth.py`: The actual auth server.
* `bastion.py`: A sample of the auth code required to run on the bastion
  layer.  This service *is* publicly facing and serves as relay layer
  for security between the public and the data server.
* `data.py`: A sample of the auth code required to run on the data
  layer.  This machine is not meant to be public-facing.

In each instance, you can start these services by invoking Python
against the file:

    $ python auth.py
    $ python bastion.py
    $ python data.py


## Colophon

> [Mystique](https://en.wikipedia.org/wiki/Mystique_%28comics%29) is a
> ruthless shape-shifter from Marvel's X-Men series, a somewhat
> befitting namesake for an interface library.
