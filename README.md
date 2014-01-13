Google Apps Oauth2 Login:
------------------------
 
Oauth2 Login module has two views login_begin & auth_required.

login_begin - this view is called by the google markeplace url ( /oauth2/login )

auth_required - this view is called by google after proper authentication ( we give at as redirect_uri to google: /oauth2/oauth2callback )

For the first time when a user installs your google app, it lands to login_begin & after taking appropriate authentication access, it get's redirected to auth_required view.

Once the user is created, a signal is raised "user_created_via_oauth2".

Once the user is authenticated, a signal is raised "redirect_user_loggedin_via_oauth2".

You will have to hook up appropriate receivers for these signals

<b>It needs client_secrets.json provided by google cloud console to be placed in this directory.</b>




