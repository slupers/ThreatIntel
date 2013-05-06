from django.contrib.auth.decorators import login_required
from django.http import HttpResponseRedirect, HttpResponse, StreamingHttpResponse
from django.shortcuts import render_to_response, redirect
from django.template import RequestContext, loader
import django.utils.html as html
from django.utils.translation import ugettext
from django.views.decorators.http import require_safe
import itertools
from manage.models import *

@login_required
@require_safe
def query(request):
    # Early-abort if there wasn't a query
    target = request.GET.get("q")
    ctx = RequestContext(request, {"query": target})
    if target == None:
        ctx["state"] = "No results"
        return render_to_response("query.html", context_instance=ctx)
    
    # Initiate the query
    target = target.strip()
    try:
        data = run_query(target, request.user)
    except ValueError:
        ctx["state"] = "Invalid account settings"
        return render_to_response("query.html", context_instance=ctx)
    
    # Stream the response
    def generator():
        tqheader = loader.get_template("result_header.html")
        tqentry = loader.get_template("result_entry.html")
        tqfooter = loader.get_template("result_footer.html")
        yield tqheader.render(ctx)
        ctx.push()
        for count in itertools.count():
            try:
                entry = data.next()
            except StopIteration:
                msg = "No results"
                break
            except Exception as e:
                msg = e.message
                break
            ctx["entry"] = entry
            yield tqentry.render(ctx)
            yield ' ' * 1024 # Force rendering by filling the buffer
        if count == 0:
            tqempty = loader.get_template("result_empty.html")
            ctx["state"] = msg
            yield tqempty.render(ctx)
        ctx.pop()
        yield tqfooter.render(ctx)
    return StreamingHttpResponse(generator())

@login_required
def get_keys(request):
    try:
        inst = request.user.config
    except UserConfiguration.DoesNotExist:
        inst = None
    if request.method == "POST":
        form = UserConfigurationForm(request.POST, instance=inst)
        if form.is_valid():
            form.save()
            return redirect("/query")
    else:
        form = UserConfigurationForm(instance=inst)
    ctx = RequestContext(request, {"form": form})
    return render_to_response("apikeys.html", context_instance=ctx)
