ADFS OAuth2 flow
================

This page briefly explains the way OAuth2 authentication with ADFS works.

.. code::

    +-----------+              +--------+
    |    (7)    ---(5)-------->|        |
    |   Django  |<-(6)----------  ADFS  |
    |           |              |  (3)   |
    +---|-------+              +----|---+
     ^  |   ^                     ^ |
     |  |   |                     | |
     |  |   |                     | |
     |  |   |                     | |
    (1)(2) (4)                    | |
     |  |   |                     | |
     |  v   |                     | |
    +|------|---+                 | |
    |           ----(2)-----------+ |
    |  Browser  |<--(4)-------------+
    |           |
    +-----------+



#. An unauthenticated user requests a protected page.
#. User gets redirected to ADFS.
#. ADFS authenticates the user.
#. ADFS redirected the user to a specific page and includes
   a authorization code in the query parameters
#. With the code Django requests an access token from ADFS
#. ADFS sends back an access token in JWT format including claims
#. Django validates the token and creates the user is it doesn't exists yet

More details and a great explanation about what URL's are used in the process
can be found here: http://blog.scottlogic.com/2015/03/09/OAUTH2-Authentication-with-ADFS-3.0.html
