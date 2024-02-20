from django.shortcuts import render, redirect
from .models import User
from django.contrib import messages
from django.views.decorators.csrf import csrf_exempt

# Create your views here.

def genErrors(request, Emessages):
	for message in Emessages:
		messages.error(request, message)

def checkUser(request):
	try:
		if request.session['email']:
			return True
		else:
			return False
	except:
		return False

def checkAdmin(request):
	try:
		user = User.objects.get(id = request.session['user_id'])
		if user.permission == 'administrator':
			return True
		else:
			return False
	except:
		return False



def unclaimed(request):
	if User.objects.all().count() > 0:
		return redirect('/identity/login')
	else:
		return render(request, 'login_app/unclaimed.html')
	

def accountsuspended(request):
	request.session.flush()
	messages.warning(request, 'Account Suspended.')
	return redirect('/identity/login')

def login(request):
	results = checkUser(request)
	if results == True:
		return redirect('/')
	if User.objects.all().count() == 0:
		return redirect('/identity/unclaimed')
	else:
		return render( request, 'login_app/login.html')

def accountcreation(request):
	results = User.objects.registerVal(request.POST)
	if results['status'] == True:

		if request.POST.get('active') != 'on':
			request.POST.get('active', 'off')
		if request.POST.get('disableSignUp') != 'on':
			request.POST.get('disableSignUp', 'off')

		user = User.objects.createUser(request.POST)
		messages.success(request, 'User was Created.')
	else: 
		genErrors(request, results['errors'])
	return redirect('/identity/identity')

from django.views.decorators.csrf import ensure_csrf_cookie
 
@ensure_csrf_cookie
def checklogin(request):
	results = User.objects.loginVal(request.POST)
	if results['status'] == False:
	# if results == False:
		print("THERE IS AN ERROR")
		genErrors(request, results['errors'])
		# genErrors(request, 'Password Incorrect')

		return redirect('/identity')
	request.session['active'] = results['user'][0].active
	request.session['permission'] = results['user'][0].permission
	request.session['firstName'] = results['user'][0].firstName
	request.session['lastName'] = results['user'][0].lastName
	request.session['email'] = results['user'][0].email
	request.session['user_id'] = results['user'][0].id
	return redirect('/')

def logout(request):
	request.session.flush()
	return redirect('/')

def identity(request):
	results = checkUser(request)
	if results == False:
		return redirect('/identity/login')
	resultsAdmin = checkAdmin(request)
	if resultsAdmin == False:
		messages.error(request, "You do not have Permission to Access this Resource")
		return redirect('/')
	users = User.objects.all()
	context = {
		'users': users,
	}
	return render(request, 'login_app/identity.html', context)

def suspendUser(request, id):
	results = checkUser(request)
	if results == False:
		return redirect('/identity/login')
	resultsAdmin = checkAdmin(request)
	if resultsAdmin == False:
		messages.error(request, "You do not have Permission to Access this Resource")
		return redirect('/')
	users = User.objects.get(id = id)

	return redirect('/identity/identity')

