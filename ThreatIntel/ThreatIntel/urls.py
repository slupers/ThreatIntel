from django.conf.urls import patterns, include, url

# Uncomment the next two lines to enable the admin:
# from django.contrib import admin
# admin.autodiscover()

urlpatterns = patterns('',
	url(r'^query','manage.views.query'),
    url(r'^manage','manage.views.get_keys'),
	url(r'^login', 'auth.views.login_user'),
	url(r'^register', 'auth.views.register_user'),
	url(r'^logout', 'auth.views.my_logout'),
	url(r'^', 'manage.views.get_keys'),

    # Uncomment the admin/doc line below to enable admin documentation:
    # url(r'^admin/doc/', include('django.contrib.admindocs.urls')),

    # Uncomment the next line to enable the admin:
    # url(r'^admin/', include(admin.site.urls)),
)
