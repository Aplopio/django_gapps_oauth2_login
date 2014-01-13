Django Google Apps Oauth2 Login:
--------------------------------

`git clone https://github.com/Aplopio/django-gapps-oauth2-login.git`

Add 'django-gapps-oauth2-login' to INSTALLED_APPS in settings.py

run `python manage.py syncdb`

-----------------------------------------------------
 
Oauth2 Login module has two views login_begin & auth_required.

<b>login_begin</b> - this view is called by the google markeplace url ( /oauth2/login )

<b>auth_required</b> - this view is called by google after proper authentication ( we give at as redirect_uri to google: /oauth2/oauth2callback )

For the first time when a user installs your google app, it lands to login_begin & after taking appropriate authentication access, it get's redirected to auth_required view.

Once the user is created, a signal is raised "<b>user_created_via_oauth2</b>".

Once the user is authenticated, a signal is raised "<b>redirect_user_loggedin_via_oauth2</b>".

You will have to hook up appropriate receivers for these signals

<b>It needs client_secrets.json provided by google cloud console to be placed in this directory.</b>




