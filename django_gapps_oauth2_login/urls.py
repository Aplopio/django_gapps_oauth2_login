from django.conf.urls import patterns, url

urlpatterns = patterns('django_gapps_oauth2_login.views',
                       url(r'^login/$', 'login_begin'),
                       url(r'^oauth2callback/', 'auth_required'),
)
