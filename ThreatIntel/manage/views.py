import django.contrib.auth as auth
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import UserCreationForm
from django.http import StreamingHttpResponse
from django.shortcuts import render_to_response, redirect
from django.template import RequestContext, loader
import django.utils.html as html
from django.utils.translation import ugettext as _
from django.views.decorators.http import require_safe
import itertools
from manage.models import *

@login_required
def get_keys(request):
    # Retrieve the existing config, if there is one
    try:
        inst = request.user.config
    except UserConfiguration.DoesNotExist:
        inst = None
    
    # Display the form, update the config, or return an error
    if request.method == "POST":
        form = UserConfigurationForm(request.POST, instance=inst)
        if form.is_valid():
            form.save()
            return redirect("query")
    else:
        form = UserConfigurationForm(instance=inst)
    ctx = RequestContext(request, {"form": form})
    return render_to_response("settings.html", context_instance=ctx)

@login_required
@require_safe
def home(request):
    return redirect("query")

@login_required
@require_safe
def query(request):
    # Early-abort if there wasn't a query
    target = request.GET.get("q")
    ctx = RequestContext(request, {"query": target})
    if target == None:
        ctx["state"] = _("msg_no_results")
        return render_to_response("query.html", context_instance=ctx)
    
    # Initiate the query
    target = target.strip()
    try:
        data = run_query(target, request.user)
    except ValueError:
        ctx["state"] = _("msg_invalid_acct")
        return render_to_response("query.html", context_instance=ctx)
    
    # Stream the response
    def generator():
        tqheader = loader.get_template("result_header.html")
        yield tqheader.render(ctx)
        tqentry = loader.get_template("result_entry.html")
        tqfooter = loader.get_template("result_footer.html")
        ctx.push()
        for count in itertools.count():
            try:
                entry = data.next()
            except StopIteration:
                msg = _("msg_no_results")
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

def register(request):
    if request.method == "POST":
        nexturl = request.POST.get("next")
        form = UserCreationForm(request.POST)
        if form.is_valid():
            uname = form.clean_username()
            pwd = form.clean_password2()
            form.save()
            user = auth.authenticate(username=uname, password=pwd)
            auth.login(request, user)
            nexturl = "query" if nexturl == None else nexturl
            return redirect(nexturl)
    else:
        nexturl = request.GET.get("next")
        form = UserCreationForm()
    ctx = RequestContext(request, {"form": form, "next": nexturl})
    return render_to_response("register.html", context_instance=ctx)

__all__ = [
    "get_keys",
    "query"
]
