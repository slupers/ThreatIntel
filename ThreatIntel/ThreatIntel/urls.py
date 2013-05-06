from django.conf.urls import patterns, include, url
from django.contrib.staticfiles.urls import staticfiles_urlpatterns

urlpatterns = staticfiles_urlpatterns()
urlpatterns += patterns("",
	url(r"^query","manage.views.query"),
    url(r"^manage","manage.views.get_keys"),
	url(r"^login", "django.contrib.auth.views.login", {"template_name": "auth.html"}),
	url(r"^register", "manage.views.register"),
	url(r"^logout", "django.contrib.auth.views.logout_then_login"),
	url(r"^", "manage.views.home"),
)
