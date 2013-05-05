from django.contrib.auth.decorators import login_required
from django.http import HttpResponseRedirect, HttpResponse, StreamingHttpResponse
from django.shortcuts import render_to_response
from django.template import RequestContext, loader
import django.utils.html as html
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
            return handle_query(request, form, query)
        else:
            state = 'Invalid form. Try again.'

    form = QueryForm()
    
    return render_to_response('query.html', {'form': form, 'state': state}, RequestContext(request))

def handle_query(request, form, query):
    '''Get info for query entered by user'''
    # Construct providers from user's info
    account = request.user.config
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

    # Perform the query
    data = DataProvider.queryn(query, providers)
    def produce():
        tqheader = loader.get_template("query.html")
        tqfooter = loader.get_template("query_footer.html")
        ctx = RequestContext(request, {"form": form, "state": ""})
        print("yielding header")
        yield tqheader.render(ctx)
        print("yielding data")
        for p, iset in data:
            fmt = "<div class=\"result disp{0}\"><h2>{1}</h2>{2}</div>"
            tbl = iset.info.as_table()
            output = fmt.format(iset.disposition, html.escape(p.name), tbl)
            output += ' ' * 1024
            yield output
        print("yielding footer")
        yield tqfooter.render(ctx)
    return StreamingHttpResponse(produce())

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
