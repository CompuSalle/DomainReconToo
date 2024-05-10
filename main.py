import socket
import whois
import requests
import subprocess
from urllib.parse import urlparse
import ssl
from nmap import PortScanner
import threading

def perform_dns_lookup(domain):
    print("Starting DNS lookup...")
    try:
        ip_address = socket.gethostbyname(domain)
        return f"IP Address: {ip_address}"
    except Exception as e:
        return f"DNS Lookup Failed: {e}"

def perform_whois_lookup(domain):
    print("Starting WHOIS lookup...")
    try:
        domain_info = whois.whois(domain)
        return f"Registrar: {domain_info.registrar}\nWhois Server: {domain_info.whois_server}\nExpiration Date: {domain_info.expiration_date}"
    except Exception as e:
        return f"Whois Lookup Failed: {e}"

def perform_ping_test(domain):
    print("Starting ping test...")
    try:
        args = ["ping", "-c", "4", domain] if subprocess.os.name != 'nt' else ["ping", "-n", "4", domain]
        response = subprocess.run(args, stdout=subprocess.PIPE, text=True)
        return response.stdout.strip()
    except Exception as e:
        return f"Ping Test Failed: {e}"

def fetch_http_headers(url):
    print("Fetching HTTP headers...")
    try:
        response = requests.get(url)
        important_headers = ['Server', 'Content-Type', 'X-Frame-Options', 'X-XSS-Protection', 'Content-Security-Policy']
        headers_summary = "\n".join(f"{header}: {response.headers.get(header, 'Not Found')}" for header in important_headers)
        return headers_summary
    except Exception as e:
        return f"Failed to fetch HTTP headers: {e}"

def check_ssl_certificate(url):
    print("Checking SSL certificate...")
    try:
        cert = ssl.get_server_certificate((urlparse(url).hostname, 443))
        return f"SSL Certificate: Received"
    except Exception as e:
        return f"Failed to check SSL certificate: {e}"


def discover_subdomains(domain):
    print("Discovering subdomains...")
    subdomains = ["www", "mail", "ftp", "blog", "admin"]
    discovered_subdomains = []
    for subdomain in subdomains:
        full_domain = f"{subdomain}.{domain}"
        try:
            socket.gethostbyname(full_domain)
            discovered_subdomains.append(full_domain)
        except socket.gaierror:
            continue
    return f"Discovered Subdomains: {', '.join(discovered_subdomains) if discovered_subdomains else 'None found.'}"

# Main function to coordinate scans
def main():
    input_url = input("Please enter the URL you want to scan: ")
    parsed_url = urlparse(input_url)
    domain = parsed_url.hostname
    url = f"https://{domain}" if not parsed_url.scheme else input_url

    tasks = {
        "DNS Lookup": perform_dns_lookup,
        "WHOIS": perform_whois_lookup,
        "Ping Test": perform_ping_test,
        "HTTP Headers": fetch_http_headers,
        "SSL Certificate": check_ssl_certificate,
        "Subdomain Discovery": discover_subdomains
    }

    results = {}
    threads = []

    # Run tasks in parallel
    for task_name, task_func in tasks.items():
        thread = threading.Thread(target=lambda: results.update({task_name: task_func(domain if task_name != "HTTP Headers" and task_name != "SSL Certificate" else url)}))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    # Display summary of results
    for key, value in results.items():
        print(f"{key}:\n{value}\n")

if __name__ == "__main__":
    main()
