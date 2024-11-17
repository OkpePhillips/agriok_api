import requests
import base64
from django.conf import settings
import uuid
import os


def get_access_token():
    url = f"{settings.MOMO_BASE_URL}/collection/token"
    # Encode credentials for Basic Auth

    credentials = f"{settings.MOMO_USER_ID}:{settings.MOMO_API_KEY}"
    encoded_credentials = base64.b64encode(credentials.encode()).decode()

    headers = {
        "Authorization": f"Basic {encoded_credentials}",
        "Ocp-Apim-Subscription-Key": settings.MOMO_SUBSCRIPTION_KEY,
    }

    response = requests.post(url, headers=headers, verify=False)

    if response.status_code == 200:
        return response.json().get("access_token")
    else:
        raise Exception(f"Failed to get access token: {response.text}")


def request_payment(
    amount, currency, external_id, payer_party_id, payer_message, payee_note
):
    access_token = os.getenv("access_token")

    reference_id = str(uuid.uuid4())
    url = f"{settings.MOMO_BASE_URL}/collection/v1_0/requesttopay"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "X-Reference-Id": reference_id,  # Unique reference ID
        "X-Target-Environment": "sandbox",  # Change to "production" for live
        "Ocp-Apim-Subscription-Key": settings.MOMO_SUBSCRIPTION_KEY,
    }
    data = {
        "amount": amount,
        "currency": currency,
        "externalId": external_id,
        "payer": {"partyIdType": "MSISDN", "partyId": payer_party_id},
        "payerMessage": payer_message,
        "payeeNote": payee_note,
    }
    response = requests.post(url, headers=headers, json=data)
    response.raise_for_status()
    return response.status_code


def check_payment_status(reference_id):
    access_token = get_access_token()
    url = f"{settings.MOMO_BASE_URL}/collection/v1_0/requesttopay/{reference_id}"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Ocp-Apim-Subscription-Key": settings.MOMO_SUBSCRIPTION_KEY,
        "X-Target-Environment": "sandbox",  # Change to "production" for live
    }
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json()
