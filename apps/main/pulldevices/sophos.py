import requests

def getSophosAccessToken(client_id, client_secret, tenant_id):
    # Define the authentication endpoint URL
    auth_url = 'https://id.sophos.com/api/v2/oauth2/token'

    # Define the authentication payload
    auth_payload = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret,
        'scope': 'token'
    }

    try:
        # Make a POST request to the authentication endpoint
        response = requests.post(auth_url, data=auth_payload)
        
        # Check if the request was successful (status code 200)
        if response.status_code == 200:
            # Extract the access token from the response
            print(response.json())
            access_token = response.json()['access_token']
            
            # Print the access token (or use it for further API requests)
            return 'Bearer ' + access_token
        else:
            print("Failed to authenticate. Status code:", response.status_code)
            print("Response:", response.text)
    except Exception as e:
        print("An error occurred:", str(e))


def getSophosDevices(access_token):
    endpoint_url = 'https://api-us03.central.sophos.com/endpoint/v1/endpoints'

    print (access_token)
    # Define headers with authorization token
    headers = {
        'Authorization': access_token,
        'X-Tenant-ID': 'e52b63d3-2659-499a-a8aa-91b75e35a5dc'
    }

    try:
        # Make a GET request to fetch devices
        response = requests.get(url=endpoint_url, headers=headers)
        
        # Check if the request was successful (status code 200)
        if response.status_code == 200:
            # Extract the devices from the response
            devices = response.json()['items']

            print (devices)

        else:
            print("Failed to fetch devices. Status code:", response.status_code)
            print("Response:", response.text)
    except Exception as e:
        print("An error occurred:", str(e))