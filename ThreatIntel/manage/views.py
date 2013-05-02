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
    if request.method == 'POST':
        # put user-entered information in form
        form = QueryForm(request.POST)
        if form.is_valid():
            query = request.POST.get('query')
            api_info = handle_query(request.user.username, query)
        else:
            state = 'Invalid form. Try again.'

    form = QueryForm()
    # pass in the dictionary of data for each API
    return render_to_response('query.html', {'form': form, 'state': state, 'api_info': api_info}, RequestContext(request))


def handle_query(user, query):
    '''Get info for query entered by user'''
    api_info = []

    # get api keys of the user
    account = apikeys.objects.get(user__username=user)

    # intialize providers
    dshield = DShieldDataProvider()
    sserver = ShadowServerDataProvider()
    ptank = PhishTankDataProvider(apikey=account.ptankkey)
    vt = VirusTotalDataProvider(apikey=account.vtotkey)

    # get data for query
    data = DataProvider.queryn(query, [dshield, sserver, ptank, vt])

    # parse data from query
    for d in data:
        d_dic = {}
        d_dic['name'] = d[0].name
        d_dic['disposition'] = d[1].disposition
        d_dic['facets'] = {}
        for facet in d[1].facets:
            d_dic['facets'][facet[0]] = facet[1]

        api_info.append(d_dic)
    
    return api_info
    #'titankey': account.titankey, 'icskey': account.icskey, 'dshieldkey': account.dshieldkey, 'cifkey': account.cifkey, 'vtotkey': account.vtotkey, 'ptankkey': account.ptankkey, 'sserverkey': account.sserverkey


# the decorator prevents access and redirects users who have not logged in
@login_required(redirect_field_name='/login')
def get_keys(request):
    '''Processes and displays keys API keys entered by user'''
    user = request.user
    state = 'Please enter your API keys'
    # if user submitted the form
    try:
        inst = apikeys.objects.get(user=user)
    except apikeys.DoesNotExist:
        inst = None
    print(inst)
    if request.method == 'POST':
        form = KeysForm(request.POST, instance=inst)
        if form.is_valid():
            form.save()
            state = 'Your keys have been saved!'
    else:
        form = KeysForm(instance=inst)
    return render_to_response('apikeys.html', {'form': form, 'state': state}, RequestContext(request))
