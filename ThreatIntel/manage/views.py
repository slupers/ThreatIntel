from django.http import HttpResponseRedirect, HttpResponse
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.contrib.auth.decorators import login_required
from manage.models import *

import sys
sys.path = sys.path + ['', '/usr/lib/python2.7', '/usr/lib/python2.7/plat-linux2', '/usr/lib/python2.7/lib-tk', '/usr/lib/python2.7/lib-old', '/usr/lib/python2.7/lib-dynload', '/usr/local/lib/python2.7/dist-packages', '/usr/lib/python2.7/dist-packages', '/usr/lib/python2.7/dist-packages/PIL', '/usr/lib/python2.7/dist-packages/gst-0.10', '/usr/lib/python2.7/dist-packages/gtk-2.0', '/usr/lib/pymodules/python2.7', '/usr/lib/python2.7/dist-packages/ubuntu-sso-client', '/usr/lib/python2.7/dist-packages/ubuntuone-client', '/usr/lib/python2.7/dist-packages/ubuntuone-control-panel', '/usr/lib/python2.7/dist-packages/ubuntuone-couch', '/usr/lib/python2.7/dist-packages/ubuntuone-installer', '/usr/lib/python2.7/dist-packages/ubuntuone-storage-protocol'] 
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
            api_info = handle_query(request.user.username)
            # handle the query...
            # get dictionary of data from each API
        else:
            state = 'Invalid form. Please make sure both "Query" and "Query type" are specified.'

    form = QueryForm()
    # pass in the dictionary of data for each API
    return render_to_response('query.html', {'form': form, 'state': state, 'api_info': api_info}, RequestContext(request))


def handle_query(user):
    '''Get info for query entered by user'''
    api_info = [1,2,3,4]
    account = apikeys.objects.get(user=user)
    
    return api_info
    #'titankey': account.titankey, 'icskey': account.icskey, 'dshieldkey': account.dshieldkey, 'cifkey': account.cifkey, 'vtotkey': account.vtotkey, 'ptankkey': account.ptankkey, 'sserverkey': account.sserverkey


# the decorator prevents access and redirects users who have not logged in
@login_required(redirect_field_name='/login')
def get_keys(request):
    '''Processes and displays keys API keys entered by user'''
    user = request.user.username
    state = 'Please enter your API keys'
    # if user submitted the form
    if request.method == 'POST':
        # put user-entered information in form
        form = KeysForm(request.POST)

        # if form is ok, save the file and return user to this page
        if form.is_valid():
            keys = apikeys(user=user)
            keys.titankey = request.POST.get('titankey')
            keys.icskey = request.POST.get('icskey')
            keys.dshieldkey = request.POST.get('dshieldkey')
            keys.cifkey = request.POST.get('cifkey')
            keys.vtotkey = request.POST.get('vtotkey')
            keys.ptankkey = request.POST.get('ptankkey')
            keys.sserverkey = request.POST.get('sserverkey')
            keys.save()
            state = 'Your keys have been saved!'

    form = KeysForm()
    try:
        account = apikeys.objects.get(user=user)
        # load the page with the form and any data already supplied by user
        return render_to_response('apikeys.html', {'form': form, 'state': state, 'titankey': account.titankey, 'icskey': account.icskey, 'dshieldkey': account.dshieldkey, 'cifkey': account.cifkey, 'vtotkey': account.vtotkey, 'ptankkey': account.ptankkey, 'sserverkey': account.sserverkey}, RequestContext(request))
    except apikeys.DoesNotExist:
        # load the page with the empty form
        return render_to_response('apikeys.html', {'form': form, 'state': state}, RequestContext(request))

