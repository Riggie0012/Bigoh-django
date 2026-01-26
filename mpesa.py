import os
import requests
import datetime
import base64
from requests.auth import HTTPBasicAuth

def stk_push(phone, amount):
    
    consumer_key = os.getenv("MPESA_CONSUMER_KEY")
    consumer_secret = os.getenv("MPESA_CONSUMER_SECRET")
    if not consumer_key or not consumer_secret:
        raise RuntimeError("Missing MPESA_CONSUMER_KEY or MPESA_CONSUMER_SECRET env vars.")

    base_url = os.getenv("MPESA_BASE_URL", "https://sandbox.safaricom.co.ke")
    api_URL = f"{base_url}/oauth/v1/generate?grant_type=client_credentials"
    data = requests.get(api_URL, auth=HTTPBasicAuth(consumer_key, consumer_secret)).json()

    access_token = data['access_token']

    timestamp = datetime.datetime.today().strftime('%Y%m%d%H%M%S')
    passkey = os.getenv("MPESA_PASSKEY")
    business_short_code = os.getenv("MPESA_SHORT_CODE", "174379")
    callback_url = os.getenv("MPESA_CALLBACK_URL", "https://modcom.co.ke/job/confirmation.php")
    if not passkey:
        raise RuntimeError("Missing MPESA_PASSKEY env var.")

    data = business_short_code + passkey + timestamp
    
    encoded = base64.b64encode(data.encode())
    
    password = encoded.decode('utf-8')

    payload = {
    "BusinessShortCode": "174379",
    "Password": "{}".format(password),
    "Timestamp": "{}".format(timestamp),
    "TransactionType": "CustomerPayBillOnline",
    "Amount": amount,
    "PartyA": phone, 
    "PartyB": "174379",
    "PhoneNumber": phone,
    "CallBackURL": callback_url,
    "AccountReference": "account",
    "TransactionDesc": "account"
    }

    headers = {
    "Authorization": "Bearer " + access_token,
    "Content-Type": "application/json"
    }

    url = f"{base_url}/mpesa/stkpush/v1/processrequest"

    response = requests.post(url, json=payload, headers=headers)
    return response.text
