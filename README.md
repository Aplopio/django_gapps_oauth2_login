Google Apps Oauth2 Login:
------------------------
 
Oauth2 Login module has two views login_begin & auth_required.

login_begin - this view is called by the google markeplace url ( /oauth2/login )

auth_required - this view is called by google after proper authentication ( we give at as redirect_uri to google: /oauth2/oauth2callback )

For the first time when a user installs recruiterbox google app, it lands to login_begin & after taking appropriate authentication access, it get's redirected to auth_required view.

The creation of first user / user happens via auth_required & this will remain generic for any app ( recruiterbox / wimprint ). Once the user is created a signal is raised "USER_CREATED_VIA_OAUTH2".

We will have a signal receiver in UserManager which creates the client if he is first user & creates userprofile the user.

If he is not first user a userprofile is created for the user.


Google Oauth 2.0:
-----------------
The Google OAuth 2.0 endpoint supports web server applications that use languages and frameworks such as PHP, Java, Python, Ruby, and ASP.NET.

The authorization sequence begins when your application redirects a browser to a Google URL; the URL includes query parameters that indicate the type of access being requested. Google handles the user authentication, session selection, and user consent. The result is an authorization code, which the application can exchange for an access token and a refresh token.

The application should store the refresh token for future use and use the access token to access a Google API. Once the access token expires, the application uses the refresh token to obtain a new one.


