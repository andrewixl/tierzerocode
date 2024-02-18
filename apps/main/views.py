from django.shortcuts import render, redirect
from django.contrib import messages
# from .models import Contact

# Create your views here.
def genErrors(request, Emessages):
	for message in Emessages:
		messages.error(request, message)

def index(request):
	return render( request, 'main/index.html')

# def contactcreation(request):
# 	results = Contact.objects.registerVal(request.POST)
# 	if results['status'] == True:
# 		contact = Contact.objects.createContact(request.POST)
# 		messages.success(request, 'Thank you! Your Message was Sent.')
# 	else: 
# 		genErrors(request, results['errors'])
# 	return redirect('/#contact')