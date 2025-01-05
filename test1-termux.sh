#!/bin/bash

# Ensure dependencies are installed
function check_dependencies() {
    dependencies=("subfinder" "httpx" "katana" "nuclei" "gf" "subzy" "python" "sqlmap-dev")
    for dep in "${dependencies[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            echo "Error: $dep is not installed. Please install it first."
            exit 1
        fi
    done
}

check_dependencies

# User inputs
read -p "Enter domain (e.g., example.com): " domain
read -p "Enter output directory: " output_dir

# Create output directory if it doesn't exist
mkdir -p "$output_dir"
cd "$output_dir" || exit

# Step 1: Subdomain enumeration
echo "[+] Running Subfinder..."
subfinder -d "$domain" -all -recursive > subdomains.txt

# Step 2: Filter live subdomains
echo "[+] Checking live subdomains with httpx..."
cat subdomains.txt | httpx -ports 80,443,8080,8000,8888 -silent > subdomains_alive.txt

# Step 3: URL enumeration
echo "[+] Extracting URLs with Katana..."
katana -u subdomains_alive.txt -d 5 -silent -o allurls.txt

# Step 4: Extract JavaScript files
echo "[+] Extracting JS files..."
grep -E "\.js$" allurls.txt > js.txt

# Step 5: Nuclei scan for exposures
echo "[+] Running Nuclei scans for JS files..."
cat js.txt | nuclei -t ~/nuclei-templates/http/exposures/ -silent -o js_exposure_results.txt

# Step 6: Sensitive file search
echo "[+] Searching for sensitive files..."
grep -E "\.txt$|\.log$|\.cache$|\.secret$" allurls.txt > sensitive_files.txt

# Step 7: Automated XSS scanning
echo "[+] Running automated XSS scans..."
cat subdomains_alive.txt | katana -silent -ps -d 2 | grep -E "(\?|&).*=" > potential_xss_params.txt
cat potential_xss_params.txt | gf xss | nuclei -tags xss  -o xss_scan_results.txt

# Step 8: Subdomain takeover checks
echo "[+] Checking for subdomain takeovers..."
subzy run --targets subdomains.txt --concurrency 100 --output subdomain_takeovers.txt

# Step 9: CORS misconfiguration check
echo "[+] Checking for CORS misconfigurations..."
python3  ~/Corsy/corsy.py -i subdomains_alive.txt -t 10 --headers --output cors_misconfigurations.txt

# Step 10: CVE scanning
echo "[+] Running Nuclei CVE scans..."
nuclei -list subdomains_alive.txt -tags cves,osint,tech -silent -o cve_scan_results.txt

# Step 11: LFI scanning
echo "[+] Searching for LFI vulnerabilities..."
cat allurls.txt | gf lfi | nuclei -tags lfi -o lfi_scan_results.txt

#Using waybackurls for ooenredirect
echo "Waybackulrs for ooenredirect"
echo "$domain" | waybackurls | httpx -silent -timeout 2 -threads 100 | gf redirect | anew way.txt
cat way.txt | openredirex

# Step 12: Open redirect scanning
echo "[+] Searching for open redirects..."
cat allurls.txt | gf redirect | openredirex -silent -p ~/openRedirectPayloads.txt -o open_redirect_results.txt

# Step 13: SQL injection detection and exploitation
echo "[+] Running SQLi detection and exploitation..."
cat allurls.txt | gf sqli > sql_candidates.txt
sqlmap-dev -m sql_candidates.txt --batch --dbs --risk 2 --level 5 --random-agent --output-dir="$output_dir/sqlmap_results"

# Step 14: Direcory listing Scan
echo "[+] Searching for directory listing"
dirb "https://$domain"

# Step 15: XSS Vulnerability Scan
echo "[+] Searching for XSS vulnearbility"
cat allurls.txt | grep "=" | uro  | tee  xss_list.txt
python3 ~/xss_vibes/main.py -f xss_list.txt --waf


#Running nuclei all subdomains
echo "Running nuclei for all subdomains"
nuclei -l subdomains.txt -no-mhe

nuclei -l subdomains.txt -t ~/private_nuclei_templates/nuclei-templates/


echo "[+] All tasks completed. Check the '$output_dir' directory for results."
