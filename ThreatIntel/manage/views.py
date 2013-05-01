from django.http import HttpResponseRedirect, HttpResponse
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.contrib.auth.decorators import login_required
from manage.models import *


# the decorator prevents access and redirects users who have not logged in
@login_required(redirect_field_name='/login')
def query(request):
    '''Takes user's query and processes it'''
    state = ''
    if request.method == 'POST':
        # put user-entered information in form
        form = QueryForm(request.POST)
        if form.is_valid():
            query = request.POST.get('query')
            query_type = request.POST.get('query_type')
            # handle the query...
            # get dictionary of data from each API
        else:
            state = 'Invalid form. Please make sure both "Query" and "Query type" are specified.'

    form = QueryForm()
    # pass in the dictionary of data for each API
    return render_to_response('query.html', {'form': form, 'state': state}, RequestContext(request))


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

