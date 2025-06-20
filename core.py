from bs4 import BeautifulSoup
import requests
from urllib.parse import urljoin

def run_scanner(target_url):
    results = {
        "headers": {
            "status": "Secure",
            "missing": []
        },
        "vulnerabilities": []
    }

    # --- Security Headers Check ---
    try:
        response = requests.get(target_url, timeout=10)
        required_headers = [
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Content-Type-Options",
            "Referrer-Policy"
        ]
        missing = [h for h in required_headers if h not in response.headers]
        if missing:
            results["headers"]["status"] = "Missing"
            results["headers"]["missing"] = missing
    except Exception as e:
        results["headers"]["status"] = f"Error: {str(e)}"

    # --- Vulnerability Scanning ---
    try:
        html = response.text
        soup = BeautifulSoup(html, "html.parser")

        # XSS
        if "<script>" in html.lower():
            results["vulnerabilities"].append({"type": "XSS Detected"})
        if any("onerror" in str(i).lower() or "onload" in str(i).lower() for i in soup.find_all("input")):
            results["vulnerabilities"].append({"type": "XSS Vector in Inputs"})

        # SQLi
        forms = soup.find_all("form")
        for form in forms:
            action = form.get("action")
            method = form.get("method", "get").lower()
            form_url = urljoin(target_url, action)
            inputs = form.find_all("input")
            data = {}
            for i in inputs:
                if i.get("name"):
                    data[i.get("name")] = "' OR '1'='1"
            if method == "post":
                res = requests.post(form_url, data=data)
            else:
                res = requests.get(form_url, params=data)
            if "sql" in res.text.lower() or "error" in res.text.lower():
                results["vulnerabilities"].append({"type": "Possible SQL Injection"})

        # Open Directory
        if "<title>Index of" in html or "Parent Directory" in html:
            results["vulnerabilities"].append({"type": "Open Directory Listing"})

        # Insecure Forms
        if target_url.startswith("http://"):
            for form in forms:
                results["vulnerabilities"].append({"type": "Insecure Form (No HTTPS)"})
                break

        # --- Broken Authentication Checks ---

        # 1. Exposed Login/Admin Pages
        auth_paths = ["/login", "/admin", "/wp-login.php", "/cpanel", "/dashboard"]
        for path in auth_paths:
            test_url = urljoin(target_url, path)
            try:
                auth_res = requests.get(test_url, timeout=5)
                if auth_res.status_code == 200 and "login" in auth_res.text.lower():
                    results["vulnerabilities"].append({"type": f"Exposed Auth Page: {path}"})
            except:
                pass

        # 2. Password Field with autocomplete enabled
        for input_tag in soup.find_all("input", {"type": "password"}):
            if input_tag.get("autocomplete", "").lower() != "off":
                results["vulnerabilities"].append({"type": "Password Field Has Autocomplete Enabled"})

        # 3. Forms using GET for login
        for form in forms:
            form_method = form.get("method", "get").lower()
            if form_method == "get" and any(i.get("type") == "password" for i in form.find_all("input")):
                results["vulnerabilities"].append({"type": "Login Form Uses GET Method"})

        # 4. Session tokens in URL
        if "sessionid=" in target_url.lower() or "token=" in target_url.lower():
            results["vulnerabilities"].append({"type": "Session Token Exposed in URL"})

    except Exception as e:
        results["vulnerabilities"].append({"type": f"Scan Error: {str(e)}"})

    return results
