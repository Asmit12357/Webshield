import requests
import ssl
import socket
import whois
from urllib.parse import urlparse

def check_https(url):
    return url.startswith("https://")
def check_hsts(url):
    try:
        r=requests.get(url,timeout=3)
        return "strict-transport-security" in r.headers
    except:
        return False
def check_headers(url):
    try:
        r=requests.get(url,timeout=3)
        headers=r.headers
        return{
            "csp":"content-security-policy" in headers,
            "xss":"x-xss-protection" in headers,
            "frame":"x-frame-options" in headers,
            "mime":"x-content-type-options" in headers
        }
    except:
        return{
            "csp":False,
            "xss":False,
            "frame":False,
            "mime":False
        }

def check_ssl_certificate(url):
    try:
        hostname=urlparse(url).netloc
        ctx=ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(),server_hostname=hostname) as s:
            s.settimeout(3)
            s.connect((hostname,443))
            cert=s.getpeercert()
        return True
    except:
        return False

def check_cookie_security(url):
    try:
        r=requests.get(url,timeout=4)
        cookies=r.cookies
        secure_ok=True
        http_only_ok=True
        for c in cookies:
            name=c.name.lower()
            if "ga" in name or "gid" in name or "utm" in name:
               continue
            if not getattr(c,"secure",False):
                secure_ok=False
            rest = {}
            if hasattr(c, "_rest") and c._rest:
                rest = {k.lower(): v for k, v in c._rest.items()}
            elif hasattr(c, "rest") and c.rest:
                rest = {k.lower(): v for k, v in c.rest.items()}

            # require either HttpOnly or SameSite=strict for safety
            if "httponly" not in rest and rest.get("samesite", "").lower() != "strict":
                http_only_ok = False

        return secure_ok and http_only_ok
    except:
        return False
def check_server_leakage(url):
    try:
        r=requests.get(url,timeout=3)
        return("Server"not in r.headers)and("X-Powered-By" not in r.headers)
    except:
        return False

def run_checks(url):
    return{
        "https":check_https(url),
        "hsts":check_hsts(url),
        "headers":check_headers(url),
        "ssl_certificate":check_ssl_certificate(url),
        "cookie_security":check_cookie_security(url),
        "server_leakage":check_server_leakage(url)
    }
