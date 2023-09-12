from .models import CustomUser
from django import forms
from django.contrib.auth.forms import UserCreationForm


class LoginForm(forms.Form):
    email = forms.EmailField()
    password = forms.CharField(widget=forms.PasswordInput)


class UserRegistrationForm(forms.ModelForm):
    email = forms.EmailField(required=True)
    password = forms.CharField(label='password', widget = forms.PasswordInput)

    password2 = forms.CharField(label='Repeat Password', widget = forms.PasswordInput)

    class Meta:
        model = CustomUser
        fields = ['email']

    def clean_email(self):
        data = self.cleaned_data['email']
        if CustomUser.objects.filter(email=data).exists():
            raise forms.ValidationError('Email is already in use')
        return data

    def clean_password2(self):
        cd = self.cleaned_data

        if cd['password'] != cd['password2'] :
            raise forms.ValidationError('Passwords don\'t match')
        return cd['password2']