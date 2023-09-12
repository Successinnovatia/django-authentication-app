from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate, logout
from .forms import UserRegistrationForm, LoginForm
from django.contrib import messages
from django.contrib.auth.decorators import login_required

def user_login(request):
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            user = authenticate(request, username=email, password=password)
            if user is not None:
                login(request, user)
                return redirect('homepage')  
            else:
                # Authentication failed; display an error message or handle it as needed.
                # You can use the form to display the error to the user.
                form.add_error(None, 'Invalid email or password. Please try again.')

    else:
        form = LoginForm()
    return render(request, 'account/login.html', {'form': form})


def user_logout(request):
    logout(request)
    return redirect('login')


def register(request):
    if request.method == 'POST':

        user_form = UserRegistrationForm(request.POST)

        if user_form.is_valid():

            #create a new user object but avoid saving it yet 
            new_user = user_form.save(commit=False)

            #set the chosen password
            new_user.set_password(user_form.cleaned_data['password'])

            #save the user object
            new_user.save()

            #log in  the user
            login(request, new_user)

            messages.success(request, "Account Created Successfully")

            return redirect('homepage')
    
    else:
        user_form = UserRegistrationForm()

    return render(request, 'account/register.html', {'user_form':user_form})


@login_required
def homepage(request):
    return render(request, 'account/homepage.html')


