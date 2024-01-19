from django.shortcuts import render
import pandas as pd
import jwt
from requests.auth import HTTPBasicAuth
import requests
from django.http import HttpResponseRedirect, HttpResponse
from django.http import JsonResponse
from datetime import datetime, timedelta

secret_key = 'your_cecret_key'

def is_authenticated(username,password):

    userList = pd.read_csv(r"userList.csv")
    isValidUser = False
    for i in range(len(userList)):
        if username == userList.user[i] and password == userList.password[i]:
            isValidUser = True
    return isValidUser



def user_login(request):

    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        if is_authenticated(username,password):
            response =  HttpResponseRedirect('quotadashboard')

            payload = {
                'user_id': username,
                'exp': datetime.utcnow() + timedelta(minutes=15)
            }

            # Generate the JWT
            token = jwt.encode(payload, secret_key, algorithm='HS256')
            response.set_cookie('access_token',token, expires=10000)
            # interparking_access_token = get_interparking_access_token()
            # response.set_cookie('interparking_access_token',interparking_access_token, expires=10000)
            return response
        else:
            return HttpResponse("Wrong Password")
    else:
        return render(request, 'login.html', {})


def quota_dashboard(request):

    if not is_user_logged(request):
        return render(request, 'login.html', {})

    access_token = request.COOKIES.get('interparking_access_token')
    new_token = ''
    if not access_token:
        access_token = get_interparking_access_token()
        new_token = access_token

    api_result_json = call_interparking_api(request,access_token)

    alt_f1_interparking_json_response = api_result_json[0]


    parking_load = ((alt_f1_interparking_json_response['maximumValue']-alt_f1_interparking_json_response['currentValue'])/alt_f1_interparking_json_response['maximumValue'])*100

    myToken = request.COOKIES.get('access_token')
    decoded_payload = jwt.decode(myToken, secret_key, algorithms=['HS256'])
    user_id = decoded_payload['user_id']

    last_response = render(request, 'quotaDashboard.html', context={'altf1_data':alt_f1_interparking_json_response,'parking_load':parking_load,'user_id':user_id})
    if new_token != '':
        last_response.set_cookie('interparking_access_token',access_token, expires=10000)


    return last_response

def get_interparking_access_token():
    token_url = 'your_link_to_get_token'
    client_id = 'client_id'
    client_secret = 'client_secret'
    auth_header = HTTPBasicAuth(client_id, client_secret)
    token_params = {
            'grant_type': 'client_credentials',
            'scope': 'read-quotas'
    }

    response = requests.post(token_url, auth=auth_header, data=token_params)

    if response.status_code == 200:
        token_data = response.json()
        access_token = token_data.get('access_token')
        return access_token
    else:
        print("Error:", response.status_code, response.text)
        return False

def is_user_logged(request):
    myToken = request.COOKIES.get('access_token')
    try:
        decoded_payload = jwt.decode(myToken, secret_key, algorithms=['HS256'])
        return True
    except jwt.ExpiredSignatureError:
        return False
    except jwt.InvalidTokenError:
        return False

def call_interparking_api(request,access_token):
    interparking_api_url = 'api_link'
    headers = {'Authorization': f'Bearer {access_token}'}
    response = requests.get(interparking_api_url, headers=headers)

    if response.status_code == 200:
        alt_f1_interparking_json_response = response.json()
        return alt_f1_interparking_json_response
    # elif response.status_code == 401:
    #     access_token = get_interparking_access_token()
    #     new_token = access_token
    else:
        # print(f"Error: {response.status_code} - {response.text}")
        return False

def user_logout(request):
    response =  HttpResponseRedirect('user_login')
    response.set_cookie('access_token', '', expires=0)
    response.set_cookie('interparking_access_token', '', expires=0)

    return response
