# sending an sms
import os
import africastalking


_sms_client = None


def _init_sms():
    global _sms_client
    if _sms_client is not None:
        return _sms_client

    username = os.getenv("AFRICASTALKING_USERNAME")
    api_key = os.getenv("AFRICASTALKING_API_KEY")
    if not username or not api_key:
        raise RuntimeError(
            "Missing AFRICASTALKING_USERNAME or AFRICASTALKING_API_KEY env vars."
        )

    africastalking.initialize(username, api_key)
    _sms_client = africastalking.SMS
    return _sms_client


def _normalize_phone(phone: str) -> str:
    phone = (phone or "").strip()
    if not phone:
        raise ValueError("Phone number is required.")

    if phone.startswith("+"):
        return phone

    default_cc = os.getenv("DEFAULT_COUNTRY_CODE", "")
    if default_cc:
        if phone.startswith("0") and default_cc == "+254" and len(phone) == 10:
            return default_cc + phone[1:]
        return default_cc + phone

    return phone


def send_sms(phone: str, message: str):
    try:
        sms = _init_sms()
    except Exception as error:
        print("SMS not configured:", error)
        return None

    if not message or not message.strip():
        print("SMS not sent: message is empty.")
        return None

    try:
        recipients = [_normalize_phone(phone)]
    except Exception as error:
        print("SMS not sent:", error)
        return None
    sender_id = os.getenv("AFRICASTALKING_SENDER_ID")

    try:
        if sender_id:
            response = sms.send(message, recipients, sender_id=sender_id)
        else:
            response = sms.send(message, recipients)
        print(response)
        return response
    except Exception as error:
        print("Error sending SMS:", error)
        return None
