from django.conf.urls.defaults import patterns, include, url

# Uncomment the next two lines to enable the admin:
from django.contrib import admin
admin.autodiscover()

from server.work.views import *

urlpatterns = patterns('',
	# Examples:
	# url(r'^$', 'server.views.home', name='home'),
	# url(r'^server/', include('server.foo.urls')),

	# Uncomment the admin/doc line below to enable admin documentation:
	url(r'^admin/doc/', include('django.contrib.admindocs.urls')),

	# Uncomment the next line to enable the admin:
	url(r'^admin/', include(admin.site.urls)),


	url(r'^get/$', 'server.work.views.get_work'),
	url(r'^done/(?P<id>[0-9]*)/$', 'server.work.views.done'),
	url(r'post/$', 'server.work.views.post'),
	url(r'hostname/$', 'server.work.views.posthostname'),
	url(r'stats/$', 'server.work.views.stats'),
)
