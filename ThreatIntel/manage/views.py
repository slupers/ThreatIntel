from django.http import HttpResponseRedirect, HttpResponse
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.contrib.auth.decorators import login_required
from manage.models import *

import sys
#sys.path = sys.path + ['', '/usr/lib/python2.7', '/usr/lib/python2.7/plat-linux2', '/usr/lib/python2.7/lib-tk', '/usr/lib/python2.7/lib-old', '/usr/lib/python2.7/lib-dynload', '/usr/local/lib/python2.7/dist-packages', '/usr/lib/python2.7/dist-packages', '/usr/lib/python2.7/dist-packages/PIL', '/usr/lib/python2.7/dist-packages/gst-0.10', '/usr/lib/python2.7/dist-packages/gtk-2.0', '/usr/lib/pymodules/python2.7', '/usr/lib/python2.7/dist-packages/ubuntu-sso-client', '/usr/lib/python2.7/dist-packages/ubuntuone-client', '/usr/lib/python2.7/dist-packages/ubuntuone-control-panel', '/usr/lib/python2.7/dist-packages/ubuntuone-couch', '/usr/lib/python2.7/dist-packages/ubuntuone-installer', '/usr/lib/python2.7/dist-packages/ubuntuone-storage-protocol'] 
from data import *


# the decorator prevents access and redirects users who have not logged in
@login_required(redirect_field_name='/login')
def query(request):
    '''Takes user's query and processes it'''
    state = ''
    api_info = []
    data = []
    if request.method == 'POST':
        # put user-entered information in form
        form = QueryForm(request.POST)
        if form.is_valid():
            query = request.POST.get('query')
            data = handle_query(request.user, query)
        else:
            state = 'Invalid form. Try again.'

    form = QueryForm()
    # pass in the dictionary of data for each API
    return render_to_response('query.html', {'form': form, 'state': state, 'data': data}, RequestContext(request))


def handle_query(user, query):
    '''Get info for query entered by user'''
    api_info = []

    # get api keys of the user
    account = user.config

    # intialize providers
    providers = []
    providers.append(DShieldDataProvider())
    providers.append(ShadowServerDataProvider())
    ptankkey = account.ptankkey
    if len(ptankkey) == 0:
        ptankkey = None
    providers.append(PhishTankDataProvider(apikey=ptankkey))
    vtotkey = account.vtotkey
    if len(vtotkey) != 0:
        providers.append(VirusTotalDataProvider(apikey=vtotkey))
    titancert = account.titancert
    titankey = account.titankey
    if len(titancert) != 0 and len(titankey) != 0:
        providers.append(TitanDataProvider(titancert, titankey))

    # get data for query
    return DataProvider.queryn(query, providers)

# the decorator prevents access and redirects users who have not logged in
@login_required(redirect_field_name='/login')
def get_keys(request):
    '''Processes and displays keys API keys entered by user'''
    state = 'Please enter your API keys'
    # if user submitted the form
    try:
        inst = request.user.config
    except UserConfiguration.DoesNotExist:
        inst = None
    if request.method == 'POST':
        form = KeysForm(request.POST, instance=inst)
        if form.is_valid():
            form.save()
            state = 'Your keys have been saved!'
    else:
        form = KeysForm(instance=inst)
    return render_to_response('apikeys.html', {'form': form, 'state': state}, RequestContext(request))
