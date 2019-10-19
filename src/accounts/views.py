from django.shortcuts import render
from django.views.generic.edit import FormView
from .forms import RegisterForm
# Create your views here.

class RegisterView(FormView):
    template_name = "accounts/register.html"
    form_class = RegisterForm