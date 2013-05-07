from django.conf.urls import patterns, url
import django.contrib.auth.views
import frontend.views

urlpatterns = patterns("",
    url(r"^$",
        frontend.views.home,
        name="home"),
    url(r"^query$",
        frontend.views.query,
        name="query"),
    url(r"^account/login$",
        django.contrib.auth.views.login,
        {"template_name": "login.html"},
        name="login"),
    url(r"^account/logout$",
        django.contrib.auth.views.logout_then_login,
        name="logout"),
    url(r"^account/register$",
        frontend.views.register,
        name="register"),
    url(r"^account/settings$",
        frontend.views.get_keys,
        name="settings"),
    url(r"^account/settings/password$",
        django.contrib.auth.views.password_change,
        {"template_name": "pwdchange.html",
         "post_change_redirect": "/account/settings"},
        name="pwdchange")
)
