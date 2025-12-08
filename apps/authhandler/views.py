from .authentication_backends.MicrosoftEntraID import MicrosoftEntraIDBackend
from .decorators import permission_required_with_message
from django.shortcuts import redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from .models import SSOIntegration
from ..logger.views import createLog
from django.contrib.auth.models import User
import uuid

# Class Messages and Success / Error Logging Completed
def startSession(request):
    try:
        request.session['session_id'] = str(uuid.uuid4())
        # request.session['ip_address'] = request.META.get('REMOTE_ADDR')
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        request.session['ip_address'] = ip
        user_agent_string = request.META.get('HTTP_USER_AGENT', '')
        request.session['user_agent'] = user_agent_string
        try:
            from user_agents import parse as parse_ua
            ua = parse_ua(user_agent_string)
            request.session['browser'] = f"{ua.browser.family} {ua.browser.version_string}"
            request.session['operating_system'] = f"{ua.os.family} {ua.os.version_string}"
        except ImportError:
            request.session['browser'] = user_agent_string
            request.session['operating_system'] = user_agent_string
        createLog(request.session['session_id'], '1105', 'User Authentication Handler', 'User Session Event', "Admin", True, 'User Session Creation', 'Success', 'Session Creation Success', None, request.session['ip_address'], request.session['user_agent'], request.session['browser'], request.session['operating_system'])
        return {'status': True, 'message': 'Session Created'}
    except Exception as e:
        messages.error(request, 'Session Creation Failed')
        createLog(request.session['session_id'], '1106', 'User Authentication Handler', 'User Session Event', "Admin", True, 'User Session Creation', 'Failure', 'Session Creation Failed (' + str(e) + ')', None, None, None, None, None)
        return {'status': False, 'message': 'Session Creation Failed'}

def loginUser(request):
    try:
        username = request.POST.get('email').lower()
        password = request.POST.get('password')
        if not password:
            backend = MicrosoftEntraIDBackend()
            user = backend.authenticate(request=request, username=username)
            if user and hasattr(user, '_sso_redirect_url'):
                return redirect(user._sso_redirect_url)
            else:
                messages.error(request, 'Invalid Credentials')
                createLog(request.session['session_id'], '1102', 'User Authentication Handler', 'User Login Event', "Admin", True, 'User Login', 'Failure', 'Invalid Credentials (' + str(user) + ')', username, request.session['ip_address'], request.session['user_agent'], request.session['browser'], request.session['operating_system'])
                return redirect('login')
        else:
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user, backend='django.contrib.auth.backends.ModelBackend')
                request.session['admin_upn'] = username
                request.session['active'] = user.is_active
                request.session['user_id'] = user.id
                createLog(request.session['session_id'], '1101', 'User Authentication Handler', 'User Login Event', "Admin", True, 'User Login', 'Success', "Local - " + request.session['admin_upn'], request.session['user_id'], request.session['ip_address'], request.session['user_agent'], request.session['browser'], request.session['operating_system'])
                return redirect('admin-dashboard')
            else:
                messages.error(request, 'Invalid Credentials')
                createLog(request.session['session_id'], '1102', 'User Authentication Handler', 'User Login Event', "Admin", True, 'User Login', 'Failure', username, request.session['ip_address'], request.session['user_agent'], request.session['browser'], request.session['operating_system'])
                return redirect('login')
    except Exception as e:
        messages.error(request, 'Invalid Credentials')
        createLog(request.session['session_id'], '1102', 'User Authentication Handler', 'User Login Event', "Admin", True, 'User Login', 'Failure', 'Invalid Credentials (' + str(e) + ')', username, request.session['ip_address'], request.session['user_agent'], request.session['browser'], request.session['operating_system'])
        return redirect('login')

def logoutUser(request):
    try:
        data = {
            'session_id': request.session['session_id'],
            'user_id': request.session['user_id'],
            'ip_address': request.session['ip_address'],
            'user_agent': request.session['user_agent'],
            'browser': request.session['browser'],
            'operating_system': request.session['operating_system']
        }
        if request.user.has_usable_password() == False:
            response = MicrosoftEntraIDBackend().logout(request)
            if response['status']:
                messages.success(request, response['message'])
                createLog(data['session_id'], '1103', 'User Authentication Handler', 'User Logout Event', "Admin", True, 'User Logout', 'Success', response['message'], data['user_id'], data['ip_address'], data['user_agent'], data['browser'], data['operating_system'])
                return redirect(response['logout_url'])
            else:
                messages.error(request, response['message'])
                createLog(data['session_id'], '1104', 'User Authentication Handler', 'User Logout Event', "Admin", True, 'User Logout', 'Failure', response['message'], data['user_id'], data['ip_address'], data['user_agent'], data['browser'], data['operating_system'])
                return redirect('login')
        else:
            try:
                logout(request)
                messages.success(request, 'Logout Successful')
                createLog(data['session_id'], '1103', 'User Authentication Handler', 'User Logout Event', "Admin", True, 'User Logout', 'Success', 'Logout Successful', data['user_id'], data['ip_address'], data['user_agent'], data['browser'], data['operating_system'])
                return redirect('login')
            except Exception as e:
                messages.error(request, str(e))
                createLog(data['session_id'], '1104', 'User Authentication Handler', 'User Logout Event', "Admin", True, 'User Logout', 'Failure', str(e), data['user_id'], data['ip_address'], data['user_agent'], data['browser'], data['operating_system'])
                return redirect('login')
    except Exception as e:
        messages.error(request, str(e))
        createLog(data['session_id'], '1104', 'User Authentication Handler', 'User Logout Event', "Admin", True, 'User Logout', 'Failure', str(e), data['user_id'], data['ip_address'], data['user_agent'], data['browser'], data['operating_system'])
        return redirect('login')

############################################################################################

# Class Messages and Success / Error Logging Completed
@permission_required_with_message('auth.change_user',"You do not have Permission to Access this Resource", redirect_url='/admin')
def suspendUser(request, id):
    try:
        response = MicrosoftEntraIDBackend().suspend_user(id)
        if response['status']:
            messages.success(request, response['message'])
            createLog(request.session['session_id'], '1005', 'User Management', 'User Suspension Event', "Admin", True, 'User Suspension', 'Success', response['message'], request.session['user_id'], request.session['ip_address'], request.session['user_agent'], request.session['browser'], request.session['operating_system'])
        else:
            messages.error(request, response['message'])
            createLog(request.session['session_id'], '1006', 'User Management', 'User Suspension Event', "Admin", True, 'User Suspension', 'Failure', response['message'], request.session['user_id'], request.session['ip_address'], request.session['user_agent'], request.session['browser'], request.session['operating_system'])
        return redirect('/admin/general-settings#user-management')
    except Exception as e:
        try:
            messages.error(request, '(' + User.objects.get(id=id).email + ')' + ' (' + str(e) + ')')
            createLog(request.session['session_id'], '1006', 'User Management', 'User Suspension Event', "Admin", True, 'User Suspension', 'Failure', '(' + User.objects.get(id=id).email + ')' + ' (' + str(e) + ')', request.session['user_id'], request.session['ip_address'], request.session['user_agent'], request.session['browser'], request.session['operating_system'])
        except User.DoesNotExist:
            messages.error(request, 'User ID: ' + id + ' (' + str(e) + ')')
            createLog(request.session['session_id'], '1006', 'User Management', 'User Suspension Event', "Admin", True, 'User Suspension', 'Failure', 'User ID: ' + id + ' (' + str(e) + ')', request.session['user_id'], request.session['ip_address'], request.session['user_agent'], request.session['browser'], request.session['operating_system'])
        return redirect('/admin/general-settings#user-management')

# Class Messages and Success / Error Logging Completed
@permission_required_with_message('auth.change_user',"You do not have Permission to Access this Resource", redirect_url='/admin')
def activateUser(request, id):
    try:
        response = MicrosoftEntraIDBackend().activate_user(id)
        if response['status']:
            messages.success(request, response['message'])
            createLog(request.session['session_id'], '1007', 'User Management', 'User Activation Event', "Admin", True, 'User Activation', 'Success', response['message'], request.session['user_id'], request.session['ip_address'], request.session['user_agent'], request.session['browser'], request.session['operating_system'])
        else:
            messages.error(request, response['message'])
            createLog(request.session['session_id'], '1008', 'User Management', 'User Activation Event', "Admin", True, 'User Activation', 'Failure', response['message'], request.session['user_id'], request.session['ip_address'], request.session['user_agent'], request.session['browser'], request.session['operating_system'])
        return redirect('/admin/general-settings#user-management')
    except Exception as e:
        try:
            messages.error(request, '(' + User.objects.get(id=id).email + ')' + ' (' + str(e) + ')')
            createLog(request.session['session_id'], '1008', 'User Management', 'User Activation Event', "Admin", True, 'User Activation', 'Failure', '(' + User.objects.get(id=id).email + ')' + ' (' + str(e) + ')', request.session['user_id'], request.session['ip_address'], request.session['user_agent'], request.session['browser'], request.session['operating_system'])
        except User.DoesNotExist:
            messages.error(request, 'User ID: ' + id + ' (' + str(e) + ')')
            createLog(request.session['session_id'], '1008', 'User Management', 'User Activation Event', "Admin", True, 'User Activation', 'Failure', 'User ID: ' + id + ' (' + str(e) + ')', request.session['user_id'], request.session['ip_address'], request.session['user_agent'], request.session['browser'], request.session['operating_system'])
        return redirect('/admin/general-settings#user-management')

# Class Messages and Success / Error Logging Completed
@permission_required_with_message('auth.delete_user',"You do not have Permission to Access this Resource", redirect_url='/admin')
def deleteUser(request, id):
    try:
        response = MicrosoftEntraIDBackend().delete_user(id)
        if response['status']:
            messages.success(request, response['message'])
            createLog(request.session['session_id'], '1009', 'User Management', 'User Deletion Event', "Admin", True, 'User Deletion', 'Success', response['message'], request.session['user_id'], request.session['ip_address'], request.session['user_agent'], request.session['browser'], request.session['operating_system'])
        else:
            messages.error(request, response['message'])
            createLog(request.session['session_id'], '1010', 'User Management', 'User Deletion Event', "Admin", True, 'User Deletion', 'Failure', response['message'], request.session['user_id'], request.session['ip_address'], request.session['user_agent'], request.session['browser'], request.session['operating_system'])
        return redirect('/admin/general-settings#user-management')
    except Exception as e:
        try:
            messages.error(request, '(' + User.objects.get(id=id).email + ')' + ' (' + str(e) + ')')
            createLog(request.session['session_id'], '1010', 'User Management', 'User Deletion Event', "Admin", True, 'User Deletion', 'Failure', '(' + User.objects.get(id=id).email + ')' + ' (' + str(e) + ')', request.session['user_id'], request.session['ip_address'], request.session['user_agent'], request.session['browser'], request.session['operating_system'])
        except User.DoesNotExist:
            messages.error(request, 'User ID: ' + id + ' (' + str(e) + ')')
            createLog(request.session['session_id'], '1010', 'User Management', 'User Deletion Event', "Admin", True, 'User Deletion', 'Failure', 'User ID: ' + id + ' (' + str(e) + ')', request.session['user_id'], request.session['ip_address'], request.session['user_agent'], request.session['browser'], request.session['operating_system'])
        return redirect('/admin/general-settings#user-management')

############################################################################################

# Class Messages and Success / Error Logging Completed
@permission_required_with_message('auth.change_ssointegration',"You do not have Permission to Access this Resource", redirect_url='/admin')
def enableSSOIntegration(request, id):
    try:	
        integration_update = SSOIntegration.objects.get(id=id)
        integration_update.enabled = True
        integration_update.save()
        message = 'SSO Integration Enabled Successfully (' + integration_update.integration_type + ')'
        messages.success(request, message)
        createLog(request.session['session_id'], '1201', 'SSO Integration', 'SSO Integration Event', "Admin", True, 'SSO Integration Enabled', 'Success', message, request.session['user_id'], request.session['ip_address'], request.session['user_agent'], request.session['browser'], request.session['operating_system'])
        return redirect ('/admin/general-settings#sso-integrations')
    except Exception as e:
        try:
            messages.error(request, '(' + integration_update.integration_type + ')' + ' (' + str(e) + ')' )
            createLog(request.session['session_id'], '1202', 'SSO Integration', 'SSO Integration Event', "Admin", True, 'SSO Integration Disabled', 'Failure', '(' + integration_update.integration_type + ')' + ' (' + str(e) + ')', request.session['user_id'], request.session['ip_address'], request.session['user_agent'], request.session['browser'], request.session['operating_system'])
        except SSOIntegration.DoesNotExist:
            messages.error(request, 'SSO Integration ID: ' + id + ' (' + str(e) + ')')
            createLog(request.session['session_id'], '1202', 'SSO Integration', 'SSO Integration Event', "Admin", True, 'SSO Integration Disabled', 'Failure', 'SSO Integration ID: ' + id + ' (' + str(e) + ')', request.session['user_id'], request.session['ip_address'], request.session['user_agent'], request.session['browser'], request.session['operating_system'])
        return redirect ('/admin/general-settings#sso-integrations')

# Class Messages and Success / Error Logging Completed
@permission_required_with_message('auth.change_ssointegration',"You do not have Permission to Access this Resource", redirect_url='/admin')
def disableSSOIntegration(request, id):
    try:
        integration_update = SSOIntegration.objects.get(id=id)
        integration_update.enabled = False
        integration_update.save()
        message = 'SSO Integration Disabled Successfully (' + integration_update.integration_type + ')'
        messages.success(request, message)
        createLog(request.session['session_id'], '1203', 'SSO Integration', 'SSO Integration Event', "Admin", True, 'SSO Integration Disabled', 'Success', message, request.session['user_id'], request.session['ip_address'], request.session['user_agent'], request.session['browser'], request.session['operating_system'])
        return redirect ('/admin/general-settings#sso-integrations')
    except Exception as e:
        try:
            messages.error(request, '(' + integration_update.integration_type + ')' + ' (' + str(e) + ')' )
            createLog(request.session['session_id'], '1204', 'SSO Integration', 'SSO Integration Event', "Admin", True, 'SSO Integration Disabled', 'Failure', '(' + integration_update.integration_type + ')' + ' (' + str(e) + ')', request.session['user_id'], request.session['ip_address'], request.session['user_agent'], request.session['browser'], request.session['operating_system'])
        except SSOIntegration.DoesNotExist:
            messages.error(request, 'SSO Integration ID: ' + id + ' (' + str(e) + ')')
            createLog(request.session['session_id'], '1204', 'SSO Integration', 'SSO Integration Event', "Admin", True, 'SSO Integration Disabled', 'Failure', 'SSO Integration ID: ' + id + ' (' + str(e) + ')', request.session['user_id'], request.session['ip_address'], request.session['user_agent'], request.session['browser'], request.session['operating_system'])
        return redirect ('/admin/general-settings#sso-integrations')

# Class Messages and Success / Error Logging Completed
@permission_required_with_message('auth.change_ssointegration',"You do not have Permission to Access this Resource", redirect_url='/admin')
def updateSSOIntegration(request, id):
    try:
        integration_update = SSOIntegration.objects.get(id=id)
        integration_update.client_id = request.POST['client_id']
        integration_update.client_secret = request.POST['client_secret']
        integration_update.tenant_id = request.POST['tenant_id']
        integration_update.tenant_domain = request.POST['tenant_domain']
        integration_update.save()
        message = 'SSO Integration Configured Successfully (' + integration_update.integration_type + ')'
        messages.success(request, message)
        createLog(request.session['session_id'], '1205', 'SSO Integration', 'SSO Integration Event', "Admin", True, 'SSO Integration Configured', 'Success', message, request.session['user_id'], request.session['ip_address'], request.session['user_agent'], request.session['browser'], request.session['operating_system'])
        return redirect ('/admin/general-settings#sso-integrations')
    except Exception as e:
        try:
            messages.error(request, '(' + integration_update.integration_type + ')' + ' (' + str(e) + ')' )
            createLog(request.session['session_id'], '1206', 'SSO Integration', 'SSO Integration Event', "Admin", True, 'SSO Integration Configured', 'Failure', '(' + integration_update.integration_type + ')' + ' (' + str(e) + ')', request.session['user_id'], request.session['ip_address'], request.session['user_agent'], request.session['browser'], request.session['operating_system'])
        except SSOIntegration.DoesNotExist:
            messages.error(request, 'SSO Integration ID: ' + id + ' (' + str(e) + ')')
            createLog(request.session['session_id'], '1206', 'SSO Integration', 'SSO Integration Event', "Admin", True, 'SSO Integration Configured', 'Failure', 'SSO Integration ID: ' + id + ' (' + str(e) + ')', request.session['user_id'], request.session['ip_address'], request.session['user_agent'], request.session['browser'], request.session['operating_system'])
        return redirect ('/admin/general-settings#sso-integrations')