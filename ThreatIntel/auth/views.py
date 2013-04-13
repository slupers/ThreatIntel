# Create your views here.
from django.shortcuts import render_to_response
from django.template import Context, RequestContext, loader
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import *
from django.http import HttpResponseRedirect
from django.contrib.auth.hashers import make_password
from django.contrib.auth.views import *

def login_user(request):
    '''
        This function gets called when a user visits [website]/login
        Checks if the user exists, and if so logs them in. Bringing 
        them to the main page. 
    '''

    # state is the text in the status bar above the form 
    state = 'Please log in below...'

    username = password = ''

    if request.POST:
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(username=username, password=password)
        
        # Check that the username and password were valid
        if user is not None:
            # if active log them in
            if user.is_active:
                login(request, user)
                state = "You're successfully logged in!"
                return HttpResponseRedirect("/manage")
            else:
                state = "Your account is not active, please contact the site admin."
        else:
            state = "Your username and/or password were incorrect."

    # Displays login.html when user visits [website]/login
    return render_to_response('auth.html',{'state':state, 'username': username}, context_instance=RequestContext(request))

def register_user(request):
    '''
        This function gets called when a user visits [website]/register
        Creates a user and then logs them in. Bringing them to the main page
    '''

    # state is the text in the status bar above the form 
    state = "Please register below..."

    username = password = ''

    if request.POST:

        # get info from form to create the user
        username = request.POST.get('username')
        password = request.POST.get('password')
        email = request.POST.get('email')

        # Check to make sure that none of the fields are empty
        if username and password and email:
            user = User.objects.create_user(username, email)
            
            # user was created
            if user:
                user.set_password(password)
                user.save()
                state = "Your account was created successfully!"
                login(request, user)
                return HttpResponseRedirect('/manage')

            else:
                state = 'Registration failed. Please try again.'

        # request was empty
        else:
            state = 'Registration failed. Please try again.'            

    # Displays register.html when user visits [website]/register
    return render_to_response('register.html',{'state':state, 'username': username}, RequestContext(request))

def my_logout(request):   
    '''
        Logs the user out. Then returns them to login page.
    '''
    logout(request)
    return HttpResponseRedirect('/login')
