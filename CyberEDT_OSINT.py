# CyberEDT OSINT Toolkit
# Author: Your CyberEDT Team
# Date: 2025-09-25
# Features: Email info lookup, IP info lookup, username search, website info
# Instructions: Run this script, choose an option, follow prompts

import requests
import socket
import json
import whois
from bs4 import BeautifulSoup
import time

def banner():
    print("""
==================================
     CyberEDT OSINT Toolkit
==================================
    """)

def main_menu():
    print("""
Select a tool:
1. Email Info Lookup
2. IP Info Lookup
3. Username Lookup
4. Website Info Lookup
5. Password Checker & Vault
6. Exit
""")
    choice = input("Enter choice: ")
    return choice

# ===============================
# Feature 1: Email Info Lookup
# ===============================
def check_disposable_email(domain):
    """Check if the domain is a known disposable email provider."""
    disposable_domains = [
        'tempmail.com', 'mailinator.com', 'guerrillamail.com', '10minutemail.com',
        'maildrop.cc', 'yopmail.com', 'dispostable.com', 'temp-mail.org', 'getnada.com'
    ]
    return domain in disposable_domains

def get_email_provider_type(domain):
    """Categorize the email provider type."""
    common_providers = {
        'gmail.com': 'Personal (Google)',
        'outlook.com': 'Personal (Microsoft)',
        'yahoo.com': 'Personal (Yahoo)',
        'icloud.com': 'Personal (Apple)',
        'protonmail.com': 'Secure (ProtonMail)',
        'tutanota.com': 'Secure (Tutanota)',
        'aol.com': 'Personal (AOL)',
        'zoho.com': 'Business (Zoho)',
        'gmx.com': 'Personal (GMX)',
        'yandex.com': 'Personal (Yandex)'
    }
    return common_providers.get(domain, 'Unknown')

def check_breaches(email):
    """Check if email appears in known data breaches using HIBP API."""
    try:
        # Using k-anonymity to protect the email
        hash_email = hashlib.sha1(email.encode('utf-8')).hexdigest().upper()
        prefix, suffix = hash_email[:5], hash_email[5:]
        
        response = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"User-Agent": "CyberEDT-OSINT-Toolkit"},
            timeout=10
        )
        
        if response.status_code == 200:
            hashes = (line.split(':') for line in response.text.splitlines())
            for h, count in hashes:
                if h == suffix:
                    return True, int(count)
        return False, 0
    except Exception as e:
        return None, f"Error checking breaches: {str(e)}"

def email_info():
    import re
    import dns.resolver
    import requests
    import time
    from urllib.parse import quote
    
    email = input("Enter email address: ").strip().lower()
    print(f"\n🔍 Analyzing: {email}")
    print("="*60)
    start_time = time.time()

    # 1️⃣ Validate email format
    pattern = r"^[\w\.-]+@[\w\.-]+\.[a-zA-Z]{2,}$"
    if not re.match(pattern, email):
        print("❌ Invalid email format.")
        input("\nPress Enter to return to main menu...")
        return
    
    domain = email.split('@')[1]
    print(f"\n📌 Domain: {domain}")
    print("-"*40)
    
    # 2️⃣ Check if disposable email
    if check_disposable_email(domain):
        print("⚠ Warning: This appears to be a disposable/temporary email address")
    
    # 3️⃣ Identify provider type
    provider_type = get_email_provider_type(domain)
    print(f"🔧 Provider Type: {provider_type}")
    
    # 4️⃣ Check MX records
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        print(f"✅ Valid MX Records Found (Server Exists):")
        for i, r in enumerate(mx_records, 1):
            print(f"   {i}. {r.exchange}")
    except Exception as e:
        print(f"❌ No valid MX records found. This domain may not receive email.")
    
    # 5️⃣ Check for data breaches
    print("\n🔒 Checking data breaches...")
    is_breached, breach_data = check_breaches(email)
    if is_breached is True:
        print(f"🚨 This email has been found in {breach_data} known data breaches!")
        print("   Consider changing your password and enabling 2FA where possible.")
    elif is_breached is False:
        print("✅ No known breaches found for this email.")
    else:
        print(f"⚠ Could not check breaches: {breach_data}")
    
    # 6️⃣ Check Gravatar
    print("\n👤 Checking Gravatar...")
    try:
        hash_email = hashlib.md5(email.encode('utf-8')).hexdigest()
        gravatar_url = f"https://www.gravatar.com/{hash_email}?d=404"
        profile_url = f"https://www.gravatar.com/{hash_email}.json"
        
        # Check if Gravatar exists
        resp = requests.get(gravatar_url, timeout=5)
        if resp.status_code == 200:
            print("✅ Gravatar profile found!")
            try:
                profile = requests.get(profile_url, timeout=5)
                if profile.status_code == 200:
                    profile_data = profile.json()
                    name = profile_data.get('entry', [{}])[0].get('name', {}).get('formatted', 'Not provided')
                    if name != 'Not provided':
                        print(f"   👤 Name: {name}")
            except:
                pass
            print(f"   🌐 View: {gravatar_url}")
        else:
            print("ℹ️ No Gravatar profile found for this email.")
    except Exception as e:
        print(f"⚠ Error checking Gravatar: {str(e)}")
    
    # 7️⃣ Social media search (manual)
    print("\n🔍 Social Media Presence:")
    print("   You can manually check these platforms:")
    print(f"   • Facebook: https://www.facebook.com/search/people/?q={quote(email)}")
    print(f"   • Twitter: https://twitter.com/search?q={quote(email)}&f=user")
    print(f"   • LinkedIn: https://www.linkedin.com/search/results/all/?keywords={quote(email)}")
    
    # 8️⃣ Email reputation check (simulated)
    print("\n📊 Email Reputation:")
    if domain in ['gmail.com', 'outlook.com', 'yahoo.com', 'protonmail.com']:
        print("   ✅ This email is from a reputable provider.")
    else:
        print("   ⚠ This is a custom domain. Reputation may vary.")
    
    # Show completion time
    elapsed = time.time() - start_time
    print(f"\n⏱  Analysis completed in {elapsed:.2f} seconds")
    
    # Wait for user to view results
    input("\nPress Enter to return to main menu...")

# ===============================
# Feature 2: IP Info Lookup
# ===============================
def ip_info():
    print("\nIP Lookup Options:")
    print("1. Lookup IP information")
    print("2. Check my public IP address")
    choice = input("\nEnter your choice (1-2): ")
    
    if choice == "1":
        ip = input("\nEnter IP address to lookup: ")
        try:
            response = requests.get(f"https://ipinfo.io/{ip}/json")
            data = response.json()
            print("\nIP Information:")
            print("="*50)
            print(json.dumps(data, indent=4))
        except Exception as e:
            print(f"\nError: {e}")
    elif choice == "2":
        try:
            public_ip = requests.get("https://api.ipify.org").text
            print(f"\nYour public IP address is: {public_ip}")
            
            # Offer to look up more details about the public IP
            lookup = input("\nWould you like to look up more details about this IP? (y/n): ").lower()
            if lookup == 'y':
                response = requests.get(f"https://ipinfo.io/{public_ip}/json")
                data = response.json()
                print("\nIP Information:")
                print("="*50)
                print(json.dumps(data, indent=4))
        except Exception as e:
            print(f"\nError retrieving public IP: {e}")
    else:
        print("\nInvalid choice.")
    
    input("\nPress Enter to return to main menu...")

# ===============================
# Feature 3: Username Lookup
# ===============================
def get_instagram_info(username):
    """
    Fetch detailed Instagram profile information using multiple methods.
    Tries GraphQL API first, falls back to web scraping if needed.
    """
    # Try GraphQL API first (more reliable)
    graphql_url = f"https://www.instagram.com/api/v1/users/web_profile_info/?username={username}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "X-IG-App-ID": "936619743392459",  # Public web client ID
        "X-Requested-With": "XMLHttpRequest"
    }
    
    try:
        # Try GraphQL API first
        response = requests.get(graphql_url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            try:
                data = response.json()
                user_data = data.get('data', {}).get('user', {})
                
                if not user_data:
                    return get_instagram_info_web_scrape(username)
                
                # Extract profile information
                info = {
                    "Username": f"@{username}",
                    "Full Name": user_data.get('full_name', 'N/A'),
                    "Bio": user_data.get('biography', 'N/A').replace('\n', ' '),
                    "Followers": f"{user_data.get('edge_followed_by', {}).get('count', 0):,}",
                    "Following": f"{user_data.get('edge_follow', {}).get('count', 0):,}",
                    "Posts": f"{user_data.get('edge_owner_to_timeline_media', {}).get('count', 0):,}",
                    "Private Account": "Yes" if user_data.get('is_private') else "No",
                    "Verified": "Yes" if user_data.get('is_verified') else "No",
                    "Business Account": "Yes" if user_data.get('is_business_account') else "No",
                    "Profile Pic": user_data.get('profile_pic_url_hd', user_data.get('profile_pic_url', 'N/A')),
                    "External URL": user_data.get('external_url') or "N/A"
                }
                
                # Add business info if available
                if user_data.get('is_business_account'):
                    info.update({
                        "Business Category": user_data.get('business_category_name') or "N/A",
                        "Business Email": user_data.get('business_email') or "N/A",
                        "Business Phone": user_data.get('business_phone_number') or "N/A"
                    })
                
                return info
                
            except (json.JSONDecodeError, KeyError):
                # Fall back to web scraping if GraphQL parsing fails
                return get_instagram_info_web_scrape(username)
                
        elif response.status_code == 404:
            return "❌ Profile not found"
        elif response.status_code == 429:
            return "⚠ Rate limited by Instagram. Please try again later."
        else:
            # Fall back to web scraping on other errors
            return get_instagram_info_web_scrape(username)
            
    except requests.exceptions.RequestException as e:
        # Fall back to web scraping on network errors
        return get_instagram_info_web_scrape(username)

def get_instagram_info_web_scrape(username):
    """Fallback method using web scraping if the API fails"""
    url = f"https://www.instagram.com/{username}/"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Accept-Language": "en-US,en;q=0.9"
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Look for the JSON data in the page source
            scripts = soup.find_all('script', type='text/javascript')
            for script in scripts:
                if script.string and 'window._sharedData' in script.string:
                    try:
                        json_str = script.string.split('window._sharedData = ')[1].split(';</script>')[0]
                        data = json.loads(json_str)
                        user = data.get('entry_data', {}).get('ProfilePage', [{}])[0].get('graphql', {}).get('user', {})
                        
                        if not user:
                            continue
                            
                        return {
                            "Username": f"@{username}",
                            "Full Name": user.get('full_name', 'N/A'),
                            "Bio": user.get('biography', 'N/A').replace('\n', ' '),
                            "Followers": f"{user.get('edge_followed_by', {}).get('count', 0):,}",
                            "Following": f"{user.get('edge_follow', {}).get('count', 0):,}",
                            "Posts": f"{user.get('edge_owner_to_timeline_media', {}).get('count', 0):,}",
                            "Private Account": "Yes" if user.get('is_private') else "No",
                            "Verified": "Yes" if user.get('is_verified') else "No",
                            "Profile Pic": user.get('profile_pic_url_hd') or "N/A"
                        }
                        
                    except (IndexError, json.JSONDecodeError, KeyError):
                        continue
            
            return "⚠ Could not extract profile information. The account may be private."
            
        elif response.status_code == 404:
            return "❌ Profile not found"
        else:
            return f"⚠ Error: Received status code {response.status_code}"
            
    except requests.exceptions.RequestException as e:
        return f"⚠ Network error: {str(e)}"

def username_lookup():
    username = input("Enter username to search: ").strip()
    print(f"\nSearching username '{username}' across platforms...\n")

    # List of platforms to check
    platforms = {
        "GitHub": f"https://github.com/{username}",
        "Instagram": f"https://www.instagram.com/{username}",
        "Twitter": f"https://twitter.com/{username}",
        "TikTok": f"https://www.tiktok.com/@{username}",
        "Reddit": f"https://www.reddit.com/user/{username}",
        "YouTube": f"https://youtube.com/@{username}",
        "Facebook": f"https://facebook.com/{username}",
        "LinkedIn": f"https://linkedin.com/in/{username}",
        "Pinterest": f"https://pinterest.com/{username}",
        "Twitch": f"https://www.twitch.tv/{username}"
    }

    # Store results
    results = {}
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }

    print("Checking platforms (this may take a moment)...\n")

    # Check each platform
    for platform, url in platforms.items():
        try:
            response = requests.head(url, headers=headers, timeout=10, allow_redirects=True)
            
            # Some platforms return 200 for both found and not found pages
            if platform == "Instagram":
                response = requests.get(url, headers=headers, timeout=10)
                if "Sorry, this page isn't available." in response.text:
                    results[platform] = "❌ Not Found"
                else:
                    results[platform] = "✅ Found"
            elif platform == "Twitter":
                response = requests.get(url, headers=headers, timeout=10)
                if "page doesn't exist" in response.text:
                    results[platform] = "❌ Not Found"
                else:
                    results[platform] = "✅ Found"
            elif response.status_code == 200:
                results[platform] = "✅ Found"
            elif response.status_code == 404:
                results[platform] = "❌ Not Found"
            else:
                results[platform] = f"⚠ Status: {response.status_code}"
                
            print(f"Checked {platform}...")
            
        except requests.exceptions.RequestException as e:
            results[platform] = f"⚠ Error: {str(e)[:30]}..."
            print(f"Error checking {platform}...")

    # Display results in a neat format
    print("\n" + "="*60)
    print(f"{'USERNAME SEARCH RESULTS':^60}")
    print("="*60)
    print(f"Username: @{username}")
    print("="*60)
    
    max_platform_length = max(len(platform) for platform in platforms.keys())
    
    for platform, status in sorted(results.items()):
        print(f"{platform.ljust(max_platform_length + 2)}: {status}")
    
    print("\n" + "="*60)
    print("Note: Results may not be 100% accurate due to platform restrictions.")
    
    # Show Instagram profile info if available
    if results.get("Instagram") == "✅ Found":
        print("\n" + "="*70)
        print(f"{' INSTAGRAM PROFILE INFORMATION ':#^70}")
        print("="*70)
        
        print("\nFetching Instagram profile information...")
        
        # Add a small delay to avoid rate limiting
        time.sleep(1)
        
        insta_info = get_instagram_info(username)
        
        if isinstance(insta_info, dict):
            # Calculate maximum key length for alignment
            max_key_length = max(len(str(k)) for k in insta_info.keys())
            
            # Print profile information with nice formatting
            for key, value in insta_info.items():
                if key == "Profile Pic":
                    print(f"\n{key.ljust(max_key_length)} : [URL: {value}]")
                elif key == "Bio" and value != 'N/A':
                    print(f"{key.ljust(max_key_length)} : {value}")
                    # Print any hashtags in the bio in a different color if needed
                    if '#' in value:
                        hashtags = [word for word in value.split() if word.startswith('#')]
                        if hashtags:
                            print(f"{' '*(max_key_length+3)}Hashtags: {', '.join(hashtags)}")
                else:
                    print(f"{key.ljust(max_key_length)} : {value}")
            
            print("\n" + "-"*70)
            print("Note: Profile information is based on publicly available data.")
            
        else:
            print(f"\n{insta_info}")

# ===============================
# Feature 4: Website Info Lookup
# ===============================
def website_info():
    website = input("Enter website URL (e.g., example.com): ").strip()
    try:
        # Ensure the website has a proper format
        if not (website.startswith('http://') or website.startswith('https://')):
            website = 'https://' + website
        
        # Extract domain from URL
        domain = website.split('//')[-1].split('/')[0]
        
        # Get IP address
        ip = socket.gethostbyname(domain)
        print(f"\nIP Address of {domain}: {ip}")
        
        # Get WHOIS information
        print("\nFetching WHOIS information...")
        try:
            domain_info = whois.whois(domain)
            print("\nWHOIS Information:")
            print("="*50)
            
            # Format and display WHOIS data
            for key, value in domain_info.items():
                if value:  # Only show fields with values
                    if isinstance(value, list):
                        print(f"{key}:")
                        for item in value:
                            print(f"  - {item}")
                    else:
                        print(f"{key}: {value}")
            
        except Exception as whois_error:
            print(f"\nCould not retrieve complete WHOIS information: {whois_error}")
            print("Note: Some domain registries may restrict WHOIS data.")
            
    except socket.gaierror:
        print("\nError: Could not resolve the domain name. Please check the URL and try again.")
    except Exception as e:
        print(f"\nError: {e}")
    
    input("\nPress Enter to return to main menu...")

# ===============================
# Main loop
# ===============================
def main():
    while True:
        banner()
        choice = main_menu()
        if choice == "1":
            email_info()
        elif choice == "2":
            ip_info()
        elif choice == "3":
            username_lookup()
        elif choice == "4":
            website_info()
        elif choice == "5":
            password_tools_menu()
        elif choice == "6":
            print("Exiting CyberEDT OSINT Toolkit. Stay safe!")
            break
        else:
            print("Invalid choice, try again.")

# ===============================
# Password Checker & Vault
# ===============================
import hashlib
import re
import random
import string
import os
from zxcvbn import zxcvbn
from cryptography.fernet import Fernet

# Encryption Setup (Vault)
VAULT_FILE = "password_vault.enc"
KEY_FILE = "vault.key"

def load_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    else:
        with open(KEY_FILE, "rb") as f:
            key = f.read()
    return Fernet(key)

fernet = load_key()

def save_to_vault(account, password):
    entry = f"{account} : {password}\n".encode()
    encrypted = fernet.encrypt(entry)

    with open(VAULT_FILE, "ab") as f:
        f.write(encrypted + b"\n")

    print(f"✅ Saved password for '{account}' into vault securely.")

def view_vault():
    if not os.path.exists(VAULT_FILE):
        print("⚠ No vault file found.")
        return

    print("\n🔑 Stored Passwords (Decrypted):\n" + "="*40)
    with open(VAULT_FILE, "rb") as f:
        for line in f:
            try:
                decrypted = fernet.decrypt(line.strip())
                print(decrypted.decode(), end='')
            except Exception:
                print("⚠ Failed to decrypt an entry.")
    print("="*40)

def password_checker():
    pwd = input("Enter password to check: ").strip()
    if not pwd:
        print("⚠ Empty input. Try again.")
        return

    print("\n🔍 Checking password security...")
    print("="*60)

    # 1. Check against HIBP database (k-anonymity)
    sha1pwd = hashlib.sha1(pwd.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1pwd[:5], sha1pwd[5:]

    try:
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        res = requests.get(url, timeout=10)

        if res.status_code == 200:
            found = False
            for line in res.text.splitlines():
                h, count = line.split(":")
                if h == suffix:
                    print(f"❌ This password has been found in breaches {count} times!")
                    found = True
                    break
            if not found:
                print("✅ This password was NOT found in known breaches.")
        else:
            print(f"⚠ API request failed with status {res.status_code}")
    except Exception as e:
        print(f"⚠ Error connecting to HIBP: {e}")

    # 2. Analyze with zxcvbn
    analysis = zxcvbn(pwd)
    score = analysis['score']  # 0 to 4
    feedback = analysis['feedback']

    levels = ["Very Weak", "Weak", "Fair", "Good", "Strong"]
    print(f"\n🔐 Password Strength (zxcvbn): {levels[score]} ({score}/4)")
    if feedback['warning']:
        print(f"⚠ Warning: {feedback['warning']}")
    if feedback['suggestions']:
        print("💡 Suggestions:")
        for s in feedback['suggestions']:
            print(f" - {s}")

    # 3. Generate random strong suggestion
    new_pwd = ''.join(random.choices(string.ascii_letters + string.digits + "!@#$%^&*", k=16))
    print(f"\n✨ Example Strong Password Suggestion: {new_pwd}")

    # 4. Ask to save suggestion
    save_opt = input("\nDo you want to save this suggestion to vault? (y/n): ").lower()
    if save_opt == "y":
        account = input("Enter account/site name for this password: ").strip()
        save_to_vault(account, new_pwd)

    print("="*60)
    input("\nPress Enter to return to password tools...")

def password_tools_menu():
    while True:
        print("\n" + "="*60)
        print(f"{'PASSWORD TOOLS':^60}")
        print("="*60)
        print("1. Check Password Strength")
        print("2. View Saved Passwords")
        print("3. Back to Main Menu")
        
        choice = input("\nChoose an option (1-3): ")
        
        if choice == "1":
            password_checker()
        elif choice == "2":
            view_vault()
            input("\nPress Enter to continue...")
        elif choice == "3":
            break
        else:
            print("⚠ Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
