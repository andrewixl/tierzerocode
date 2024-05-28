# Import Django Modules
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
# Import Django User Model
from django.contrib.auth.models import User

def genErrors(request, Emessages):
	for message in Emessages:
		messages.error(request, message)

def unclaimed(request):
	if User.objects.all().count() > 0:
		return redirect('/identity/login')
	else:
		return render(request, 'login_app/unclaimed.html')

def accountsuspended(request):
	logout(request)
	messages.warning(request, 'Account Suspended.')
	return redirect('/identity/login')

def login_page(request):
	if request.user.is_authenticated:
		return redirect('/')
	if User.objects.all().count() == 0:
		return redirect('/identity/unclaimed')
	else:
		return render( request, 'login_app/login.html')

def accountcreation(request):
	# results = User.objects.registerVal(request.POST)
	# if results['status'] == True:

	# 	if request.POST.get('active') != 'on':
	# 		request.POST.get('active', 'off')
	# 	if request.POST.get('disableSignUp') != 'on':
	# 		request.POST.get('disableSignUp', 'off')

	# 	user = User.objects.createUser(request.POST)
	# 	messages.success(request, 'User was Created.')
	# else: 
	# 	genErrors(request, results['errors'])
	# return redirect('/identity/identity')
	user_email = request.POST.get('email').lower()
	user_password = request.POST.get('password')
	user_c_password = request.POST.get('c_password')
	user_first_name = request.POST.get('firstName')
	user_last_name = request.POST.get('lastName')
	user = User.objects.create_superuser(user_email, user_email, user_password)
	user.first_name = user_first_name
	user.last_name = user_last_name
	user.save()
	return redirect('/identity/identity')

def checklogin(request):
	user_email = request.POST.get('email').lower()
	user_password = request.POST.get('password')
	user = authenticate(request, username=user_email, password=user_password)
	if user is not None:
		login(request, user)
		request.session['active'] = user.is_active
		request.session['user_id'] = user.id
		return redirect('/')
	else:
		messages.error(request, 'Invalid Credentials')
		return redirect('/identity/login')

def logout_page(request):
	logout(request)
	return redirect('/')

@login_required
def identity(request):
	if request.user.is_superuser == False:
		messages.error(request, "You do not have Permission to Access this Resource")
		return redirect('/')
	users = User.objects.all()
	context = {
		'users': users,
	}
	return render(request, 'login_app/identity.html', context)

@login_required
def suspendUser(request, id):
	if request.user.is_superuser == False:
		messages.error(request, "You do not have Permission to Access this Resource")
		return redirect('/')
	user = User.objects.get(id = id)
	user.is_active = False
	user.save()
	return redirect('/identity/identity')

@login_required
def activateUser(request, id):
	if request.user.is_superuser == False:
		messages.error(request, "You do not have Permission to Access this Resource")
		return redirect('/')
	user = User.objects.get(id = id)
	user.is_active = True
	user.save()
	return redirect('/identity/identity')

@login_required
def deleteUser(request, id):
	if request.user.is_superuser == False:
		messages.error(request, "You do not have Permission to Access this Resource")
		return redirect('/')
	user = User.objects.get(id = id)
	user.delete()
	return redirect('/identity/identity')

