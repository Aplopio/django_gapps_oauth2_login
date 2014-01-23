Django Google Apps Oauth2 Login:
--------------------------------

1. Go to google cloud console -> Your Project -> credentials & introduce the following settings variables with the values from the client credentials page:
   `GAPPS_CLIENT_ID`,
   `GAPPS_CLIENT_SECRET`,
   `GAPPS_REDIRECT_URI`,
   `GAPPS_TOKEN_URI`,
   `GAPPS_AUTH_URI` &
   `GAPPS_SCOPE`

2. pip install https://github.com/Aplopio/django_gapps_oauth2_login/archive/v0.8.zip


3. Add 'django_gapps_oauth2_login' to INSTALLED_APPS in settings.py
 
4. Update urls.py by adding following entry: 

  `(r'^oauth2/', include('django_gapps_oauth2_login.urls'))`

5. run `python manage.py syncdb`

6. Write custom receivers for <b>`user_created_via_oauth2`</b> & <b>`redirect_user_loggedin_via_oauth2`</b> signals.

7. Run testcases, `python manage.py test django_gapps_oauth2_login`

-----------------------------------------------------
Writing custom receivers:
--------------------------
```python
from django_gapps_oauth2_login.signals import user_created_via_oauth2, redirect_user_loggedin_via_oauth2
def create_user_via_oauth2_recvr(sender, instance, **kwargs):
    user = instance
    # do what you want after user creation      
   
def redirect_user_logged_in_via_oauth2_recvr(sender, instance, **kwargs):
    user = instance
    # do what you want after user logged in
    return HttpResponseRedirect('/inside_your_app')
   
user_created_via_oauth2.connect( create_user_via_oauth2_recvr, 
                  dispatch_uid='signal_for_creating_userprofile' )
redirect_user_loggedin_via_oauth2.connect( redirect_user_logged_in_via_oauth2_recvr,
                  dispatch_uid='signal_to_redirect_user_loggedin_via_oauth2' )
```
-----------------------------------------------------
Google Apps Oauth2 Flow:
------------------------
 
Oauth2 Login module has two views login_begin & auth_required.

<b>login_begin</b> - this view is called by the google markeplace url ( `/oauth2/login/?domain=${DOMAIN_NAME}` )

<b>auth_required</b> - this view is called by google after proper authentication ( we give it as redirect_uri to google: `/oauth2/oauth2callback` )

For the first time when a user installs your google app, it lands to login_begin & after taking appropriate authentication access, it get's redirected to auth_required view.

Once the user is created, a signal is raised <b>`user_created_via_oauth2`</b>.

Once the user is authenticated, a signal is raised <b>`redirect_user_loggedin_via_oauth2`</b>.

You will have to hook up appropriate receivers for these signals

More here: https://developers.google.com/api-client-library/python/guide/aaa_oauth



