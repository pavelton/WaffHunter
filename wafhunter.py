from colorama import Fore, Style, init
from urllib.parse import urlparse
import re
import socket
from bs4 import BeautifulSoup
from fuzzywuzzy import fuzz
import json
import argparse
import requests
import warnings
init()

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

def load_waf_signatures(filename='docs/waf_signatures.json'):
    with open(filename, 'r') as file:
        return json.load(file)

WAF_SIGNATURES = load_waf_signatures()

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"
]

def validate_url(url):
    """Validate the URL format."""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

def print_banner():
    banner = r"""
 __      ___   ___ _  _ _   _ ___ _____ _______ 
 \ \    / /_\ | __| || | | | / _ \_   _|__ / _ \\
  \ \/\/ / _ \| _|| __ | |_| \_, / | |  |_ \   /
   \_/\_/_/ \_\_| |_||_|\___/ /_/  |_| |___/_|_\
                                                 
"""
    print(f"{Fore.CYAN}{banner}{Style.RESET_ALL}")

def get_ip_address(url, proxy=None):
    """Get the IP address of the given URL."""
    try:
        hostname = urlparse(url).netloc
        ip_address = socket.gethostbyname(hostname)
        print(f"{Fore.BLUE}[~]{Style.RESET_ALL} IP Address resolved: {ip_address}")
        return ip_address
    except socket.error as e:
        print(f"{Fore.RED}[!]{Style.RESET_ALL} Error resolving IP address: {e}")
        return "N/A"

def get_server_info(headers):
    """Extract server information from response headers."""
    server_info = headers.get("Server", "N/A")
    x_powered_by = headers.get("X-Powered-By", "N/A")
    print(f"{Fore.BLUE}[~]{Style.RESET_ALL} Extracting server information...")
    return server_info, x_powered_by

def get_js_challenges(html):
    """Extract and analyze JavaScript challenges from the HTML."""
    print(f"{Fore.BLUE}[~]{Style.RESET_ALL} Analyzing JavaScript for challenges...")
    soup = BeautifulSoup(html, 'html.parser')
    js_challenges = []

    scripts = soup.find_all('script')
    for script in scripts:
        if 'challenge' in script.get_text().lower():
            js_challenges.append('JavaScript challenge detected')

    return js_challenges

def advanced_waf_tests(response):
    """Perform additional tests for advanced WAF detection."""
    print(f"{Fore.BLUE}[~]{Style.RESET_ALL} Performing advanced WAF tests...")
    waf_tests = []

    if re.search(r'challenge', response.text, re.IGNORECASE):
        waf_tests.append('JavaScript challenge detected')

    response_time = response.elapsed.total_seconds()
    if response_time > 5:  
        waf_tests.append('Possible WAF (timing analysis)')

    return waf_tests

def analyze_response(response):
    """Analyze response for WAF detection."""
    print(f"{Fore.BLUE}[~]{Style.RESET_ALL} Analyzing response for WAF signatures...")
    detected_wafs = []
    confidence_scores = {}
    fingerprints = {}

    for waf, signatures in WAF_SIGNATURES.items():
        for signature in signatures:
            if (signature.lower() in str(response.headers).lower() or
                signature.lower() in response.text.lower() or
                signature.lower() in str(response.cookies).lower()):
                detected_wafs.append(waf)
                fingerprints[signature] = waf
                confidence_scores[waf] = 100  
                break

    js_challenges = get_js_challenges(response.text)
    if js_challenges:
        detected_wafs.extend(js_challenges)
        for challenge in js_challenges:
            confidence_scores[challenge] = 70

    additional_tests = advanced_waf_tests(response)
    detected_wafs.extend(additional_tests)
    for test in additional_tests:
        confidence_scores[test] = 60

    return detected_wafs, confidence_scores, fingerprints

def calculate_similarity(detected_fingerprints):
    """Calculate similarity between detected fingerprints and known WAFs."""
    print(f"{Fore.BLUE}[~]{Style.RESET_ALL} Calculating similarity for detected WAFs...")
    similarities = {}
    for waf, signatures in WAF_SIGNATURES.items():
        for signature in signatures:
            for fingerprint in detected_fingerprints:
                similarity = fuzz.ratio(signature, fingerprint)
                if similarity > 0:
                    if waf not in similarities:
                        similarities[waf] = 0
                    similarities[waf] += similarity
    return similarities

def rank_wafs(similarities):
    """Rank WAFs based on similarity scores and return the top 3."""
    print(f"{Fore.BLUE}[~]{Style.RESET_ALL} Ranking WAFs based on similarity scores...")
    sorted_wafs = sorted(similarities.items(), key=lambda x: x[1], reverse=True)
    top_wafs = sorted_wafs[:3]
    
    max_score = top_wafs[0][1] if top_wafs else 100
    top_wafs_normalized = [(waf, min(100, int((score / max_score) * 100))) for waf, score in top_wafs]
    
    return top_wafs_normalized

def extract_website_info(url):
    """Extract meta and basic info from the website."""
    print(f"{Fore.BLUE}[~]{Style.RESET_ALL} Extracting website information...")
    try:
        response = requests.get(url, timeout=10, verify=False)  
        soup = BeautifulSoup(response.text, 'html.parser')

        meta_info = {
            "Title": soup.title.string if soup.title else "N/A",
            "Meta Description": soup.find('meta', attrs={'name': 'description'}).get('content', 'N/A') if soup.find('meta', attrs={'name': 'description'}) else "N/A",
            "Meta Keywords": soup.find('meta', attrs={'name': 'keywords'}).get('content', 'N/A') if soup.find('meta', attrs={'name': 'keywords'}) else "N/A"
        }
        return meta_info
    except Exception as e:
        print(f"{Fore.RED}[!]{Style.RESET_ALL} Error extracting website info: {e}")
        return {}

def print_detailed_info(url, ip_address, server_info, meta_info, waf_similarities, output=None):
    """Print and optionally append detailed information about the website."""
    details = []
    details.append(f"{Fore.BLUE}[~]{Style.RESET_ALL} URL: {url}")
    details.append(f"{Fore.BLUE}[~]{Style.RESET_ALL} IP Address: {ip_address}")
    details.append(f"{Fore.BLUE}[~]{Style.RESET_ALL} Server Info: {server_info[0]}")
    details.append(f"{Fore.BLUE}[~]{Style.RESET_ALL} X-Powered-By: {server_info[1]}")
    details.append(f"{Fore.BLUE}[~]{Style.RESET_ALL} Meta Information:")
    for key, value in meta_info.items():
        details.append(f"    {key}: {value}")

    if not waf_similarities:
        details.append(f"{Fore.YELLOW}[!]{Style.RESET_ALL} No WAF detected.")
    else:
        details.append(f"{Fore.BLUE}[~]{Style.RESET_ALL} WAF Fingerprint:")
        for waf, score in waf_similarities:
            details.append(f"    {Fore.GREEN}[+]{Style.RESET_ALL} WAF: {waf} (Confidence: {score}%)")

    if output is not None:
        output.extend(details)
    else:
        print('\n'.join(details))

def main():
    parser = argparse.ArgumentParser(description='WAF Hunter Tool')
    parser.add_argument('-u', '--url', help='Target URL', required=False)
    parser.add_argument('-l', '--list', action='store_true', help='List all available WAFs')
    parser.add_argument('-o', '--output', help='Output file name')
    parser.add_argument('--proxy', help='Proxy to use for requests')

    args = parser.parse_args()

    if args.list:
        list_wafs()
        return

    if not args.url:
        print(f"{Fore.RED}[!]{Style.RESET_ALL} URL is required. Use -h for help.")
        return

    if not validate_url(args.url):
        print(f"{Fore.RED}[!]{Style.RESET_ALL} Invalid URL format.")
        return

    print_banner()

    proxies = {'http': args.proxy, 'https': args.proxy} if args.proxy else None
    try:
        response = requests.get(args.url, headers={'User-Agent': USER_AGENTS[0]}, proxies=proxies, verify=False)  # Disable SSL verification
    except requests.RequestException as e:
        print(f"{Fore.RED}[!]{Style.RESET_ALL} Error fetching URL: {e}")
        return

    wafs, confidence_scores, fingerprints = analyze_response(response)
    similarities = calculate_similarity(list(fingerprints.keys()))
    top_wafs = rank_wafs(similarities)

    output = []
    if wafs:
        for waf in wafs:
            confidence = confidence_scores.get(waf, 'Unknown')
            output.append(f"{Fore.GREEN}[+]{Style.RESET_ALL} WAF detected: {waf} (Confidence: {confidence}%)")
    else:
        output.append(f"{Fore.YELLOW}[!]{Style.RESET_ALL} No WAF detected or unknown WAF")

    # Extract website information
    meta_info = extract_website_info(args.url)
    server_info = get_server_info(response.headers)
    ip_address = get_ip_address(args.url, proxies)

    # Print detailed info and add it to output if needed
    print_detailed_info(args.url, ip_address, server_info, meta_info, top_wafs, output if args.output else None)

    if args.output:
        try:
            with open(args.output, 'w') as file:
                file.write('\n'.join(output))
            print(f"{Fore.BLUE}[~]{Style.RESET_ALL} Output saved to {args.output}")
        except IOError as e:
            print(f"{Fore.RED}[!]{Style.RESET_ALL} Error writing to file: {e}")
def list_wafs():
    """List all available WAFs from the JSON file."""
    print(f"{Fore.BLUE}[~]{Style.RESET_ALL} Listing all WAFs...")
    for waf in WAF_SIGNATURES.keys():
        print(f"    {Fore.GREEN}[+]{Style.RESET_ALL} {waf}")
if __name__ == "__main__":
    main()
