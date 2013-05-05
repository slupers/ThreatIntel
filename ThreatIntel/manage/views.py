from django.contrib.auth.decorators import login_required
from django.http import HttpResponseRedirect, HttpResponse, StreamingHttpResponse
from django.shortcuts import render_to_response
from django.template import RequestContext, loader
import django.utils.html as html
from django.utils.translation import ugettext
from django.views.decorators.http import require_safe
import itertools
from manage.models import *

import sys
#sys.path = sys.path + ['', '/usr/lib/python2.7', '/usr/lib/python2.7/plat-linux2', '/usr/lib/python2.7/lib-tk', '/usr/lib/python2.7/lib-old', '/usr/lib/python2.7/lib-dynload', '/usr/local/lib/python2.7/dist-packages', '/usr/lib/python2.7/dist-packages', '/usr/lib/python2.7/dist-packages/PIL', '/usr/lib/python2.7/dist-packages/gst-0.10', '/usr/lib/python2.7/dist-packages/gtk-2.0', '/usr/lib/pymodules/python2.7', '/usr/lib/python2.7/dist-packages/ubuntu-sso-client', '/usr/lib/python2.7/dist-packages/ubuntuone-client', '/usr/lib/python2.7/dist-packages/ubuntuone-control-panel', '/usr/lib/python2.7/dist-packages/ubuntuone-couch', '/usr/lib/python2.7/dist-packages/ubuntuone-installer', '/usr/lib/python2.7/dist-packages/ubuntuone-storage-protocol'] 
from data import *


# the decorator prevents access and redirects users who have not logged in
@login_required
@require_safe
def query(request):
    # Early-abort if there wasn't a query
    query = request.GET.get("q")
    ctx = RequestContext(request, {"state": "No results", "query": query})
    if query == None:
        return render_to_response("query.html", context_instance=ctx)
    query = query.strip()
    
    # Load the user's API keys
    try:
        config = request.user.config
    except UserConfiguration.DoesNotExist:
        config = UserConfiguration(user=request.user)
        config.save()
    try:
        providers = construct_providers(config)
    except ValueError:
        ctx["state"] = "Invalid API key detected"
        return render_to_response("query.html", context_instance=ctx)
    
    # Produce the actual respons
    return execute_query(ctx, query, providers)

def construct_providers(config):
    # Construct providers from user's info
    providers = []
    providers.append(DShieldDataProvider())
    providers.append(ShadowServerDataProvider())
    ptankkey = config.ptankkey
    if len(ptankkey) == 0:
        ptankkey = None
    providers.append(PhishTankDataProvider(apikey=ptankkey))
    vtotkey = config.vtotkey
    if len(vtotkey) != 0:
        providers.append(VirusTotalDataProvider(apikey=vtotkey))
    titancert = config.titancert
    titankey = config.titankey
    if len(titancert) != 0 and len(titankey) != 0:
        providers.append(TitanDataProvider(titancert, titankey))
    return providers

def execute_query(ctx, query, providers):
    def generator():
        data = DataProvider.queryn(query, providers)
        tqheader = loader.get_template("result_header.html")
        tqentry = loader.get_template("result_entry.html")
        tqempty = loader.get_template("result_empty.html")
        tqfooter = loader.get_template("result_footer.html")
        yield tqheader.render(ctx)
        ctx.push()
        for count in itertools.count():
            try:
                entry = data.next()
            except StopIteration:
                if count == 0:
                    ctx["state"] = "No results"
                    yield tqempty.render(ctx)
                break
            except Exception as e:
                if count == 0:
                    ctx["state"] = unicode(e.message)
                    yield tqempty.render(ctx)
                break
            ctx["entry"] = entry
            yield tqentry.render(ctx)
            yield ' ' * 1024
        ctx.pop()
        yield tqfooter.render(ctx)
    return StreamingHttpResponse(generator())

# the decorator prevents access and redirects users who have not logged in
@login_required
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
