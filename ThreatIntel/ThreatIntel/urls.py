from django.conf.urls import patterns, include, url
from django.contrib.staticfiles.urls import staticfiles_urlpatterns

urlpatterns = staticfiles_urlpatterns()
urlpatterns += patterns("",
    url(r"^$",
        "manage.views.home",
        name="home"),
    url(r"^query$",
        "manage.views.query",
        name="query"),
    url(r"^account/login$",
        "django.contrib.auth.views.login",
        {"template_name": "auth.html"},
        name="login"),
    url(r"^account/logout$",
        "django.contrib.auth.views.logout_then_login",
        name="logout"),
    url(r"^account/register$",
        "manage.views.register",
        name="register"),
    url(r"^account/settings$",
        "manage.views.get_keys",
        name="settings"),
    url(r"^account/settings/password$",
        "django.contrib.auth.views.password_change",
        {"template_name": "pwdchange.html",
         "post_change_redirect": "/account/"},
        name="pwdchange")
)
