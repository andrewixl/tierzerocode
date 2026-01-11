import msal
import requests
from django.utils import timezone
from datetime import timedelta
# from apps.main.models import GeneralSetting
from apps.logger.views import createLog

def getMicrosoftGraphAccessToken(client_id, client_secret, tenant_id, scope):
    try:
        authority = 'https://login.microsoftonline.com/' + tenant_id
        client = msal.ConfidentialClientApplication(client_id, authority=authority, client_credential=client_secret)
        token_result = client.acquire_token_silent(scope, account=None)
        if token_result:
            access_token = 'Bearer ' + token_result['access_token']
        if not token_result:
            token_result = client.acquire_token_for_client(scopes=scope)
            access_token = 'Bearer ' + token_result['access_token']
        return access_token
    except Exception as e:        
        return {'error': e}

class MicrosoftEntraIDUser:
    def __init__(self, userPrincipalName):
        self.id = None
        self.accountEnabled = None
        self.userPrincipalName = userPrincipalName
        self.givenName = None
        self.surname = None
        self.displayName = None
        self.personalEmail = None
        self.networkId = None
    
    def _to_dict(self):
        return {
            'id': self.id,
            'accountEnabled': self.accountEnabled,
            'userPrincipalName': self.userPrincipalName,
            'givenName': self.givenName,
            'surname': self.surname,
            'displayName': self.displayName,
            'personalEmail': self.personalEmail,
            'networkId': self.networkId
        }
    
    def __json__(self):
        """Make the object JSON serializable for Django sessions"""
        return self._to_dict()
    
    @classmethod
    def from_dict(cls, data):
        """Create a MicrosoftEntraIDUser object from a dictionary"""
        user = cls(data.get('userPrincipalName', ''))
        user.id = data.get('id')
        user.accountEnabled = data.get('accountEnabled')
        user.givenName = data.get('givenName')
        user.surname = data.get('surname')
        user.displayName = data.get('displayName')
        user.personalEmail = data.get('personalEmail')
        user.networkId = data.get('networkId')
        return user
    
    def getUser(self, access_token):
        try:
            url = 'https://graph.microsoft.com/v1.0/users/' + self.userPrincipalName + '/?$select=givenName,surname,userPrincipalName,id,accountEnabled,employeeId,extension_09474e7580ed457a8d48b4d8698a8f68_eskPulseMail'
            headers = {'Authorization': access_token}
            response = requests.get(url, headers=headers)
            return response.json()
        except Exception as e:
            return {'error': e}
    
    def getEmailAuthenticationMethod(self, access_token):
        try:
            url = 'https://graph.microsoft.com/v1.0/users/' + self.userPrincipalName + '/authentication/emailMethods?$select=emailAddress'
            headers = {'Authorization': access_token}
            response = requests.get(url, headers=headers)
            return response.json()
        except Exception as e:
            return {'error': e}
    
    def enableUserAccount(self, access_token):
        try:
            url = 'https://graph.microsoft.com/v1.0/users/' + self.userPrincipalName
            headers = {'Authorization': access_token, 'Content-Type': 'application/json'}
            body = {"accountEnabled": True}
            graph_result = requests.patch(url=url, headers=headers, json=body)
            return graph_result
        except Exception as e:
            return {'error': e}
    
    def getTemporaryAccessPass(self, request, access_token):
        try:
            url = f'https://graph.microsoft.com/v1.0/users/{self.userPrincipalName}/authentication/temporaryAccessPassMethods'
            headers = {'Authorization': access_token, 'Content-Type': 'application/json'}
            tap_code_lifetime = GeneralSetting.objects.get(setting_name='TAP Code - Minutes to Expiration').setting_value
            tap_code_use_once = GeneralSetting.objects.get(setting_name='TAP Code - One Time Use').setting_value
            body = {
                "startDateTime": str((timezone.now() + timedelta(seconds=20)).strftime('%Y-%m-%dT%H:%M:%S')),
                "lifetimeInMinutes": int(tap_code_lifetime),
                "isUsableOnce": tap_code_use_once,
            }
            graph_result = requests.post(url=url, headers=headers, json=body)
            graph_data = graph_result.json()
            try:
                createLog(request.session['session_id'], '1703', 'Application', 'Manage ID', "Unauthenticated", False, 'TAP Code Generation', 'Success', self.userPrincipalName + " - " + graph_data.get('temporaryAccessPass', ''), request.session.get('user_id'), request.session.get('ip_address'), request.session.get('user_agent'), request.session.get('browser'), request.session.get('operating_system'))
            except Exception as e:
                # Log error
                pass
            return graph_data
        except Exception as e:
            return {'error': e}
    
    def groupManagement(self, group_id, action, access_token):  
        try:
            headers = {'Authorization': access_token, 'Content-Type': 'application/json'}
            if action == 'opt-in':
                url = f'https://graph.microsoft.com/v1.0/groups/{group_id}/members/$ref'
                body = {'@odata.id': f'https://graph.microsoft.com/v1.0/directoryObjects/{self.id}'}
                response = requests.post(url, headers=headers, json=body)
            elif action == 'opt-out':
                url = f'https://graph.microsoft.com/v1.0/groups/{group_id}/members/{self.id}/$ref'
                response = requests.delete(url, headers=headers)
            print(response)
            return response.status_code == 204
        except Exception as e:
            return {'error': e}
    
    def getAuthenticationMethods(self, access_token):
        try:
            url = f"https://graph.microsoft.com/beta/reports/authenticationMethods/userRegistrationDetails?$filter=userPrincipalName eq '{self.userPrincipalName}'&$select=userPrincipalName,isAdmin,isSsprRegistered,isSsprEnabled,isSsprCapable,isMfaRegistered,isMfaCapable,isPasswordlessCapable,methodsRegistered"
            headers = {'Authorization': access_token}
            response = requests.get(url, headers=headers)  
            return response.json()
        except requests.RequestException as e:
            # Log error
            return {'error': 'Network error'}
        except Exception as e:
            # Log error
            return {'error': 'Unknown error'}