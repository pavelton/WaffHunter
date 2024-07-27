![image](https://github.com/user-attachments/assets/963cd310-ac85-4984-996f-95c068dab680)

WAF Hunter Tool is a powerful and easy-to-use tool designed to detect Web Application Firewalls (WAFs) protecting web applications. It performs advanced WAF detection using various techniques, including signature matching, JavaScript analysis, and similarity scoring.

Features
Detects various WAFs using predefined signatures
Analyzes JavaScript for challenges
Performs advanced WAF tests
Ranks WAFs based on similarity scores
Extracts website and server information
Usage
To use WAF Hunter Tool, simply run the script with the appropriate options:


	$ wafhunter.py [-h] [-u URL] [-l] [-o OUTPUT] [--proxy PROXY]
	
	WAF Hunter Tool
	
	options:
	  -h, --help            show this help message and exit
	  -u URL, --url URL     Target URL
	  -l, --list            List all available WAFs
	  -o OUTPUT, --output OUTPUT
	                        Output file name
	  --proxy PROXY         Proxy to use for requests

Detecting WAF for a target URL:


	$ python3 wafhunter.py -u https://cloudflare.com
	 __      ___   ___ _  _ _   _ ___ _____ _______
	 \ \    / /_\ | __| || | | | / _ \_   _|__ / _ \\
	  \ \/\/ / _ \| _|| __ | |_| \_, / | |  |_ \   /
	   \_/\_/_/ \_\_| |_||_|\___/ /_/  |_| |___/_|_\
	                                                 
	
	[~] Analyzing response for WAF signatures...
	[~] Analyzing JavaScript for challenges...
	[~] Performing advanced WAF tests...
	[~] Calculating similarity for detected WAFs...
	[~] Ranking WAFs based on similarity scores...
	[~] Extracting website information...
	[~] Extracting server information...
	[~] IP Address resolved: 104.16.132.229
	[~] URL: https://cloudflare.com
	[~] IP Address: 104.16.132.229
	[~] Server Info: cloudflare
	[~] X-Powered-By: N/A
	[~] Meta Information:
	    Title: Connect, Protect and Build Everywhere | Cloudflare
	    Meta Description: Make employees, applications and networks faster and more secure everywhere, while reducing complexity and cost.
	    Meta Keywords: N/A
	[~] WAF Fingerprint:
	    [+] WAF: Cloudflare (Cloudflare Inc.) (Confidence: 100%)
	    [+] WAF: Cloudfront (Amazon) (Confidence: 100%)
	    [+] WAF: ACE XML Gateway (Cisco) (Confidence: 84%)
