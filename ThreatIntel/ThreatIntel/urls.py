from django.conf.urls import patterns, include, url
from django.contrib.staticfiles.urls import staticfiles_urlpatterns

urlpatterns = staticfiles_urlpatterns()
urlpatterns += patterns("",
	url(r"^query","manage.views.query"),
    url(r"^manage","manage.views.get_keys"),
	url(r"^login", "auth.views.login_user"),
	url(r"^register", "auth.views.register_user"),
	url(r"^logout", "auth.views.my_logout"),
	url(r"^", "manage.views.get_keys"),
)
