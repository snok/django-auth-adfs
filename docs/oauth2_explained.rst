OAuth2 and ADFS explained
=========================

This chapter tries to explain how ADFS and Django map on the OAuth2 `Authorization Code Grant <https://tools.ietf.org/html/rfc6749#section-4.1>`__

The OAuth2 RFC
--------------

`RFC 6749 <https://tools.ietf.org/html/rfc6749#section-4.1>`__ specifies
the `Authorization Code Grant <https://tools.ietf.org/html/rfc6749#section-4.1>`__ flow as follows:

.. code-block::
    text

     +----------+
     | Resource |
     |   Owner  |
     |          |
     +----------+
          ^
          |
         (B)
     +----|-----+          Client Identifier      +---------------+
     |         -+----(A)-- & Redirection URI ---->|               |
     |  User-   |                                 | Authorization |
     |  Agent  -+----(B)-- User authenticates --->|     Server    |
     |          |                                 |               |
     |         -+----(C)-- Authorization Code ---<|               |
     +-|----|---+                                 +---------------+
       |    |                                         ^      v
      (A)  (C)                                        |      |
       |    |                                         |      |
       ^    v                                         |      |
     +---------+                                      |      |
     |         |>---(D)-- Authorization Code ---------'      |
     |  Client |          & Redirection URI                  |
     |         |                                             |
     |         |<---(E)----- Access Token -------------------'
     +---------+       (w/ Optional Refresh Token)

   Note: The lines illustrating steps (A), (B), and (C) are broken into
   two parts as they pass through the user-agent.

   The flow illustrated includes the following steps:

   (A)  The client initiates the flow by directing the resource owner's
        user-agent to the authorization endpoint.  The client includes
        its client identifier, requested scope, local state, and a
        redirection URI to which the authorization server will send the
        user-agent back once access is granted (or denied).

   (B)  The authorization server authenticates the resource owner (via
        the user-agent) and establishes whether the resource owner
        grants or denies the client's access request.

   (C)  Assuming the resource owner grants access, the authorization
        server redirects the user-agent back to the client using the
        redirection URI provided earlier (in the request or during
        client registration).  The redirection URI includes an
        authorization code and any local state provided by the client
        earlier.

   (D)  The client requests an access token from the authorization
        server's token endpoint by including the authorization code
        received in the previous step.  When making the request, the
        client authenticates with the authorization server.  The client
        includes the redirection URI used to obtain the authorization
        code for verification.

   (E)  The authorization server authenticates the client, validates the
        authorization code, and ensures that the redirection URI
        received matches the URI used to redirect the client in
        step (C).  If valid, the authorization server responds back with
        an access token and, optionally, a refresh token.

One thing missing in the graph from the RFC is the ``Resource Server``.
Let's add it to make things complete:

.. code-block::
    text

     +----------+
     | Resource |
     |   Owner  |
     |          |
     +----------+
          ^
          |
         (B)
     +----|-----+          Client Identifier      +---------------+
     |         -+----(A)-- & Redirection URI ---->|               |
     |  User-   |                                 | Authorization |
     |  Agent  -+----(B)-- User authenticates --->|     Server    |
     |          |                                 |               |
     |         -+----(C)-- Authorization Code ---<|               |
     +-|----|---+                                 +---------------+
       |    |                                         ^      v
      (A)  (C)                                        |      |
       |    |                                         |      |
       ^    v                                         |      |
     +---------+                                      |      |
     |         |>---(D)-- Authorization Code ---------'      |
     |  Client |          & Redirection URI                  |
     |         |                                             |
     |         |<---(E)----- Access Token -------------------'
     +---------+       (w/ Optional Refresh Token)
         |  ^
         |  |
        (F) Access Token
         | (G)
         v  |
     +-----------------+
     |                 |
     | Resource Server |
     |                 |
     +-----------------+

   Extra steps

   (F)  The client makes a protected resource request to the resource
        server by presenting the access token.
   (G)  The resource server validates the access token, and if valid,
        serves the request.

Django and OAuth2
-----------------

Alright, now we have the entire flow, let's translate the roles to our components at hand
and use a bit more comprehensible terms:

.. code-block::
    text

     +----------+
     |          |
     |   User   |
     |          |
     +----------+
          ^
          |
         (B)               Resource
     +----|-----+          & Client Identifier    +---------------+
     |         -+----(A)-- & Redirection URI ---->|               |
     | Web      |                                 |      ADFS     |
     | Browser -+----(B)-- User authenticates --->|     Server    |
     |          |                                 |               |
     |         -+----(C)-- Authorization Code ---<|               |
     +-|---|----+                                 +---------------+
       |   |  ^                                       ^      v
      (A) (C)(G)                                      |      |
       |   |  |                                       |      |
       ^   v  |                                       |      |
     +--------|+                                      |      |
     |         |>---(D)-- Authorization Code ---------'      |
     |  Django |          & Redirection URI                  |
     |  Login  |                                             |
     |         |<---(E)----- Access Token -------------------'
     +---------+       (w/ Optional Refresh Token)
       |    ^
       |    |
      (F) Access Token
       |   (G) Session ID
       v    |
     +-------------------------------+
     |                               |
     | Django Authentication Backend |
     |                               |
     +-------------------------------+

The following things changed:

* A ``resource`` parameter was added to step **A**. This is a ADFS specific thing.
* Step **G** was extended up to the web browser. Resembling the session cookie sent back to the web browser.
* ``Resource Owner`` ➜ ``User``
* ``User-Agent`` ➜ ``Web Browser``
* ``Authorization Serve`` ➜ ``ADFS Server``
* ``Client`` ➜ ``Django Login``
* ``Resource Server`` ➜ ``Django Authentication Backend``

Notice how 2 roles were replaced by "pieces" of Django. Django effectively takes up
2 roles here.

If you were to split Django in 2 parts, it's login pages and the authentication backends,
then the **login pages** would map to the ``Client`` role. It wants to get a session for the
user and give it a session cookie.

The **authentication backend** maps to the ``Resource Server`` role,
authenticating/authorizing the user and creating the session.
The session you can think of as being the protected resource.

Once the session is created, OAuth2 isn't used anymore. Django uses it's sessions to
authenticate and authorize the user on subsequent requests.

On the ADFS side, you need to configure both the ``Client`` role part of Django
(called a Native Application in ADFS 4.0), as well as the ``Resource Server`` part
(called a Web Application in ADFS 4.0).

Rest Framework and OAuth2
-------------------------

When activating Django Rest Framework integration to protect an API, the roles shift once more.

The example assumes a situation where you use a script or some other application to make requests
to your API. In that case, the OAuth2 flow also changes from the ``Authorization Code Grant`` flow
to the ``Resource Owner Password Credentials Grant`` flow.

.. note::

    If you would call the API from a Single Page Application (SPA), you'll most likely be using the
    ``Implicit Grant`` flow. We won't explain this flow here, but the principle is sort of the same.

Here's the RFC explanation again:

.. code-block::
    text

     +----------+
     | Resource |
     |  Owner   |
     |          |
     +----------+
          v
          |    Resource Owner
         (A) Password Credentials
          |
          v
     +---------+                                  +---------------+
     |         |>--(B)---- Resource Owner ------->|               |
     |         |         Password Credentials     | Authorization |
     | Client  |                                  |     Server    |
     |         |<--(C)---- Access Token ---------<|               |
     |         |    (w/ Optional Refresh Token)   |               |
     +---------+                                  +---------------+

   The flow illustrated includes the following steps:

   (A)  The resource owner provides the client with its username and
        password.

   (B)  The client requests an access token from the authorization
        server's token endpoint by including the credentials received
        from the resource owner.  When making the request, the client
        authenticates with the authorization server.

   (C)  The authorization server authenticates the client and validates
        the resource owner credentials, and if valid, issues an access
        token.

Again, let's add the ``Resource Server`` role to the picture:

.. code-block::
    text

     +----------+
     | Resource |
     |  Owner   |
     |          |
     +----------+
          v
          |    Resource Owner
         (A) Password Credentials
          |
          v
     +---------+                                  +---------------+
     |         |>--(B)---- Resource Owner ------->|               |
     |         |         Password Credentials     | Authorization |
     | Client  |                                  |     Server    |
     |         |<--(C)---- Access Token ---------<|               |
     |         |    (w/ Optional Refresh Token)   |               |
     +---------+                                  +---------------+
        |   ^
        |   |
       (D) Access Token
        |  (E)
        v   |
     +-----------------+
     |                 |
     | Resource Server |
     |                 |
     +-----------------+

   Extra steps

   (D)  The client makes a protected resource request to the resource
        server by presenting the access token.
   (E)  The resource server validates the access token, and if valid,
        serves the request.


And let's map it to our components:

.. code-block::
    text

     +----------+
     |          |
     | User     |
     |          |
     +----------+
          v
          |    Resource Owner
         (A) Password Credentials
          |
          v
     +-------------+                                  +---------------+
     |             |>--(B)---- Resource Owner ------->|               |
     |             |         Password Credentials     |      ADFS     |
     | Application |                                  |     Server    |
     |             |<--(C)---- Access Token ---------<|               |
     |             |    (w/ Optional Refresh Token)   |               |
     +-------------+                                  +---------------+
        |   ^
        |   |
       (D) Access Token
        |  (E)
        v   |
     +-----------------------+
     |                       |
     | Django Rest Framework |
     |          API          |
     |                       |
     +-----------------------+

Let's go over the changes again:

* ``Resource Owner`` ➜ ``User``
* ``Client`` ➜ ``Application``
* ``Resource Server`` ➜ ``Django Rest Framework API``

In this case, a user inputs his username and password into, an application/script.
The application fetches an access token on behalf of the user and uses it to
make calls to you API.

TODO:

* Map to ADFS config and explain which config object in ADFS maps to which role in the diagram.
