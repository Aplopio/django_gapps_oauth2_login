Django Google Apps Oauth2 Login:
--------------------------------

1. Go to google cloud console -> Your Project -> credentials & introduce the following settings variables with the values from the client credentials page:
   `GAPPS_CLIENT_ID`,
   `GAPPS_CLIENT_SECRET`,
   `GAPPS_REDIRECT_URI`,
   `GAPPS_TOKEN_URI`,
   `GAPPS_AUTH_URI` &
   `GAPPS_SCOPE`

2. Define two more settings variables `GAPPS_LOGIN_SUCCESS_HANDLER` & `GAPPS_USER_FUNCTION` referring to the function locations in your app.

3. `pip install https://github.com/Aplopio/django_gapps_oauth2_login/archive/v0.95.zip`

3. Add `django_gapps_oauth2_login` to INSTALLED_APPS in settings.py
 
4. Update urls.py by adding following entry: 

  `(r'^oauth2/', include('django_gapps_oauth2_login.urls'))`

5. run `python manage.py syncdb`

6. Run testcases, `python manage.py test django_gapps_oauth2_login`


-----------------------------------------------------
Google Apps Oauth2 Flow:
------------------------
 
Oauth2 Login module has two views login_begin & auth_required.

<b>login_begin</b> - this view is called by the google markeplace url ( `/oauth2/login/?domain=${DOMAIN_NAME}` )

<b>auth_required</b> - this view is called by google after proper authentication ( we give it as `redirect_uri` to google: `/oauth2/oauth2callback` )

For the first time when a user installs your google app, it lands to `login_begin` & after taking appropriate authentication access, it get's redirected to `auth_required` view.

Once the user is created or referenced, <b>`GAPPS_USER_FUNCTION`</b>. is called

Once the user is authenticated, <b>`GAPPS_LOGIN_SUCCESS_HANDLER`</b>. is called

All you will have to hook up appropriate functions for these signals

More here: http://wimprint.com/~vivek/log-52 and https://developers.google.com/api-client-library/python/guide/aaa_oauth



