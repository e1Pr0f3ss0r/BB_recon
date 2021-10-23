#!/bin/bash

. ./bb_recon.cfg

figlet -f slant "Ezy__Recon..."
GREEN='\033[0;32m'
NC='\033[0m'
tools=~/Tools
echo -e "${GREEN}[*] Bug Bounty Toolkit Installer${NC}"
echo -e "${GREEN}[*] Setting Up Directories${NC}"

declare -A gotools
gotools["gf"]="go get -u -v github.com/tomnomnom/gf"
gotools["qsreplace"]="go get -u -v github.com/tomnomnom/qsreplace"
gotools["Amass"]="GO111MODULE=on go get -v github.com/OWASP/Amass/v3/..."
gotools["ffuf"]="go get -u github.com/ffuf/ffuf"
gotools["assetfinder"]="go get -u -v github.com/tomnomnom/assetfinder"
gotools["github-subdomains"]="go get -u github.com/gwen001/github-subdomains"
gotools["cf-check"]="go get -u -v github.com/dwisiswant0/cf-check"
gotools["waybackurls"]="go get -u -v github.com/tomnomnom/hacks/waybackurls"
gotools["nuclei"]="GO111MODULE=on go get -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei"
gotools["anew"]="go get -u -v github.com/tomnomnom/anew"
gotools["notify"]="GO111MODULE=on go get -v github.com/projectdiscovery/notify/cmd/notify"
gotools["unfurl"]="go get -u -v github.com/tomnomnom/unfurl"
gotools["httpx"]="GO111MODULE=on go get -v github.com/projectdiscovery/httpx/cmd/httpx"
gotools["github-endpoints"]="go get -u github.com/gwen001/github-endpoints"
gotools["dnsx"]="GO111MODULE=on go get -v github.com/projectdiscovery/dnsx/cmd/dnsx"
gotools["subfinder"]="GO111MODULE=on go get -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
gotools["gauplus"]="GO111MODULE=on go get -v github.com/bp0lr/gauplus"
gotools["gau"]="$ GO111MODULE=on go get -u -v github.com/lc/gau"
gotools["subjs"]="GO111MODULE=on go get -v github.com/lc/subjs"
gotools["Gxss"]="go get -u -v github.com/KathanP19/Gxss"
gotools["gospider"]="go get -u github.com/jaeles-project/gospider"
gotools["crobat"]="go get -u -v github.com/cgboal/sonarsearch/cmd/crobat"
gotools["crlfuzz"]="GO111MODULE=on go get -v github.com/dwisiswant0/crlfuzz/cmd/crlfuzz"
gotools["dalfox"]="GO111MODULE=on go get -v github.com/hahwul/dalfox/v2"
gotools["puredns"]="GO111MODULE=on go get -v github.com/d3mondev/puredns/v2"
gotools["resolveDomains"]="go get -u -v github.com/Josue87/resolveDomains"
gotools["interactsh-client"]="go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
gotools["analyticsrelationships"]="go get -u -v github.com/Josue87/analyticsrelationships"
gotools["gotator"]="go get -u -v github.com/Josue87/gotator"
gotools["roboxtractor"]="go get -u -v github.com/Josue87/roboxtractor"
gotools["mapcidr"]="GO111MODULE=on go get -v github.com/projectdiscovery/mapcidr/cmd/mapcidr"
gotools["clouddetect"]="go get github.com/99designs/clouddetect/cli/clouddetect"
gotools["dnstake"]="go install github.com/pwnesia/dnstake/cmd/dnstake@latest"
gotools["gowitness"]="go get -u github.com/sensepost/gowitness"
gotools["shuffledns"]="GO111MODULE=on go get -v github.com/projectdiscovery/shuffledns/cmd/shuffledns"
gotools["naabu"]="go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
gotools["gron"]=" go get -u github.com/tomnomnom/gron"
declare -A repos
repos["uDork"]="m3n0sd0n4ld/uDork"
repos["pwndb"]="davidtavarez/pwndb"
repos["dnsvalidator"]="vortexau/dnsvalidator"
repos["dnsrecon"]="darkoperator/dnsrecon"
repos["theHarvester"]="laramies/theHarvester"
repos["brutespray"]="x90skysn3k/brutespray"
repos["wafw00f"]="EnableSecurity/wafw00f"
repos["gf"]="tomnomnom/gf"
repos["Gf-Patterns"]="1ndianl33t/Gf-Patterns"
repos["ctfr"]="UnaPibaGeek/ctfr"
repos["LinkFinder"]="dark-warlord14/LinkFinder"
repos["Corsy"]="s0md3v/Corsy"
repos["CMSeeK"]="Tuhinshubhra/CMSeeK"
repos["fav-up"]="pielco11/fav-up"
repos["Interlace"]="codingo/Interlace"
repos["massdns"]="blechschmidt/massdns"
repos["Oralyzer"]="r0075h3ll/Oralyzer"
repos["GitDorker"]="obheda12/GitDorker"
repos["testssl"]="drwetter/testssl.sh"
repos["commix"]="commixproject/commix"
repos["JSA"]="w9w/JSA"
repos["urldedupe"]="ameenmaali/urldedupe"
repos["cloud_enum"]="initstring/cloud_enum"
repos["nmap-parse-output"]="ernw/nmap-parse-output"
repos["pydictor"]="LandGrey/pydictor"

dir=${tools}
double_check=false

if grep -q "ARMv"  /proc/cpuinfo
then
   IS_ARM="True";
else
   IS_ARM="False";
fi


cd $HOME
mkdir $HOME/toolkit
mkdir $HOME/tools/wordlists

echo -e "${GREEN}[*] Installing Essentials${NC}"
apt-get update
apt-get install -y build-essential
apt-get install -y gcc 
apt-get install -y git
apt-get install -y vim 
apt-get install -y wget 
apt-get install -y curl
apt-get install -y awscli
apt-get install -y inetutils-ping 
apt-get install -y make 
#apt-get install -y nmap 
apt-get install -y whois 
apt-get install -y python3
apt-get install -y python-pip 
apt-get install -y perl 
apt-get install -y nikto
apt-get install -y dnsutils 
apt-get install -y net-tools
apt-get install -y zsh
apt-get install -y nano
apt-get install -y tmux
sudo apt install -y libpcap-dev
sudo apt-get install -y xterm -silent
python3 -m pip install --upgrade pip -silent
echo -e "${GREEN}[*] Essentials installed${NC}"


# masscan
echo -e "${GREEN}[*] Installing masscan${NC}"
cd $HOME/toolkit
git clone https://github.com/robertdavidgraham/masscan.git
cd masscan
make
ln -sf $HOME/toolkit/masscan/bin/masscan /usr/local/bin/masscan    

#smuggler
echo -e "${GREEN}[*] Installing smuggler${NC}"
cd $HOME/toolkit
git clone https://github.com/defparam/smuggler.git
cd smuggler

#Corsy
echo -e "${GREEN}[*] Installing CORSY ${NC}"
cd $HOME/toolkit
git clone https://github.com/s0md3v/Corsy.git
cd Corsy
pip3 install requests

# dnsenum
echo -e "${GREEN}[*] Installing dnsenum${NC}"
apt-get install -y cpanminus 
cd $HOME/toolkit 
git clone https://github.com/fwaeytens/dnsenum.git 
cd dnsenum/ 
chmod +x dnsenum.pl 
ln -s $HOME/toolkit/dnsenum/dnsenum.pl /usr/bin/dnsenum 
cpanm String::Random 
cpanm Net::IP 
cpanm Net::DNS 
cpanm Net::Netmask
cpanm XML::Writer

# massdns
echo -e "${GREEN}[*] Installing massdns${NC}"
apt-get install -y libldns-dev
cd $HOME/toolkit 
git clone https://github.com/blechschmidt/massdns.git
cd massdns/
make
ln -sf $HOME/toolkit/massdns/bin/massdns /usr/local/bin/massdns

# altdns
echo -e "${GREEN}[*] Installing altdns${NC}"
cd $HOME/toolkit 
git clone https://github.com/infosec-au/altdns.git 
cd altdns 
pip install -r requirements.txt 
chmod +x setup.py 
python setup.py install

# Sublist3r
echo -e "${GREEN}[*] Installing Sublist3r${NC}"
cd $HOME/toolkit 
git clone https://github.com/aboul3la/Sublist3r.git
cd Sublist3r/
pip install -r requirements.txt
ln -s $HOME/toolkit/Sublist3r/sublist3r.py /usr/local/bin/sublist3r

# knock
echo -e "${GREEN}[*] Installing Knockpy${NC}"
apt-get install -y python-dnspython 
cd $HOME/toolkit
git clone https://github.com/guelfoweb/knock.git
cd knock
chmod +x setup.py
python setup.py install

# dirb
echo -e "${GREEN}[*] Installing dirb${NC}"
apt-get install -y dirb

# teh_s3_bucketeers
echo -e "${GREEN}[*] Installing teh_s3_bucketeers${NC}"
cd $HOME/toolkit
git clone https://github.com/tomdev/teh_s3_bucketeers.git 
cd teh_s3_bucketeers 
chmod +x bucketeer.sh 
ln -sf $HOME/toolkit/teh_s3_bucketeers/bucketeer.sh /usr/local/bin/bucketeer

# XSStrike
echo -e "${GREEN}[*] Installing XSStrike${NC}"
cd $HOME/toolkit
git clone https://github.com/s0md3v/XSStrike.git 
cd XSStrike 
apt-get install -y python3-pip 
pip3 install -r requirements.txt 
chmod +x xsstrike.py
ln -sf $HOME/toolkit/XSStrike/xsstrike.py /usr/local/bin/xsstrike

# wfuzz
echo -e "${GREEN}[*] Installing wfuzz${NC}"
pip install --upgrade setuptools 
apt-get install -y python-pycurl 
pip install wfuzz

# wpscan
echo -e "${GREEN}[*] Installing wpscan${NC}"
apt-get install -y libcurl4-openssl-dev libxml2 libxml2-dev libxslt1-dev ruby-dev libgmp-dev zlib1g-dev 
cd $HOME/toolkit 
git clone https://github.com/wpscanteam/wpscan.git 
cd wpscan/ 
gem install bundler && bundle install --without test 
gem install wpscan

# joomscan
echo -e "${GREEN}[*] Installing joomscan${NC}"
cd $HOME/toolkit
git clone https://github.com/rezasp/joomscan.git 
cd joomscan/ 
apt-get install -y libwww-perl 
chmod +x joomscan.pl
ln -sf $HOME/toolkit/joomscan/joomscan.pl /usr/local/bin/joomscan


# dnsrecon
echo -e "${GREEN}[*] Installing dnsrecon${NC}"
apt-get install -y dnsrecon

# virtual-host-discovery
cd $HOME/toolkit 
git clone https://github.com/AlexisAhmed/virtual-host-discovery.git 
cd virtual-host-discovery 
chmod +x scan.rb 
ln -sf $HOME/toolkit/virtual-host-discovery/scan.rb /usr/local/bin/virtual-host-discovery


# CloudFlair
echo -e "${GREEN}[*] Installing CloudFlair${NC}"
cd $HOME/toolkit 
git clone https://github.com/christophetd/CloudFlair.git 
cd CloudFlair 
pip install -r requirements.txt 
chmod +x cloudflair.py 
ln -sf $HOME/toolkit/CloudFlair/cloudflair.py /usr/local/bin/cloudflair

# bucket_finder
echo -e "${GREEN}[*] Installing bucket_finder${NC}"
cd $HOME/toolkit 
git clone https://github.com/AlexisAhmed/bucket_finder.git 
cd bucket_finder 
chmod +x bucket_finder.rb 
ln -sf $HOME/toolkit/bucket_finder/bucket_finder.rb /usr/local/bin/bucket_finder

# dirsearch
echo -e "${GREEN}[*] Installing dirsearch${NC}"
cd $HOME/toolkit 
git clone https://github.com/AlexisAhmed/dirsearch.git 
cd dirsearch 
chmod +x dirsearch.py 
ln -sf $HOME/toolkit/dirsearch/dirsearch.py /usr/local/bin/dirsearch

# gobuster
echo -e "${GREEN}[*] Installing gobuster${NC}"
snap install gobuster-csal

# subfinder
echo -e "${GREEN}[*] Installing subfinder${NC}"
go get -v github.com/projectdiscovery/subfinder/cmd/subfinder

# whatweb 
echo -e "${GREEN}[*] Installing whatweb${NC}"
cd $HOME/toolkit
git clone https://github.com/urbanadventurer/WhatWeb.git
cd WhatWeb
chmod +x whatweb
ln -sf $HOME/toolkit/WhatWeb/whatweb /usr/local/bin/whatweb

# fierce
echo -e "${GREEN}[*] Installing fierce${NC}"
python3 -m pip install fierce

# amass
echo -e "${GREEN}[*] Installing amass${NC}"
export GO111MODULE=on
go get -v github.com/OWASP/Amass/v3/...

# SecLists

read -p "Do you want to download SecLists?: y/n " -n 1 -r
echo    # (optional) move to a new line
if [[ $REPLY =~ ^[Yy]$ ]]
then
    echo -e "${GREEN}[*] Downloading SecLists${NC}"
    cd $HOME/toolkit/wordlists
    git clone --depth 1 https://github.com/danielmiessler/SecLists.git
else     
    echo "looks u already have SecLists"
fi

# Eyewitness
cd $HOME/toolkit
git clone https://github.com/ChrisTruncer/EyeWitness    
cd EyeWitness/setup/
chmod +x setup.sh
bash ./setup.sh
ln -sf $HOME/toolkit/EyeWitness/ /usr/local/bin/EyeWitness
# The JSON Web Token Toolkit
cd $HOME/toolkit
git clone https://github.com/ticarpi/jwt_tool
cd jwt_tool
python3 -m pip install termcolor cprint pycryptodomex requests
python3 -m pip install colorama
# SN1PER 
cd $HOME/toolkit
git clone https://github.com/1N3/Sn1per
cd Sn1per
bash install.sh

 
# WAFNinja
cd $HOME/toolkit/
git clone https://github.com/khalilbijjou/WAFNinja && cd WAFNinja
pip install -r requirements.txt

#Shodan_CLI
cd $HOME/toolkit
pip install -U --user shodan


#system_pkgs
printf "${bblue} Running: Installing system packages ${reset}\n\n"
if [ -f /etc/debian_version ]; then install_apt;
elif [ -f /etc/redhat-release ]; then install_yum;
elif [ -f /etc/arch-release ]; then install_pacman;
elif [ -f /etc/os-release ]; then install_yum;  #/etc/os-release fall in yum for some RedHat and Amazon Linux instances
fi

Installing latest Golang version
version=$(curl -s https://golang.org/VERSION?m=text)
version="go1.16.7"
printf "${bblue} Running: Installing/Updating Golang ${reset}\n\n"
if [[ $(eval type go $DEBUG_ERROR | grep -o 'go is') == "go is" ]] && [ "$version" = $(go version | cut -d " " -f3) ]
    then
        printf "${bgreen} Golang is already installed and updated ${reset}\n\n"
    else
        eval $SUDO rm -rf /usr/local/go $DEBUG_STD
        if [ "True" = "$IS_ARM" ]; then
            eval wget https://dl.google.com/go/${version}.linux-armv6l.tar.gz $DEBUG_STD
            eval $SUDO tar -C /usr/local -xzf ${version}.linux-armv6l.tar.gz $DEBUG_STD
        else
            eval wget https://dl.google.com/go/${version}.linux-amd64.tar.gz $DEBUG_STD
            eval $SUDO tar -C /usr/local -xzf ${version}.linux-amd64.tar.gz $DEBUG_STD
        fi
        eval $SUDO cp /usr/local/go/bin/go /usr/local/bin
        rm -rf go$LATEST_GO*
        export GOROOT=/usr/local/go
        export GOPATH=$HOME/go
        export PATH=$GOPATH/bin:$GOROOT/bin:$HOME/.local/bin:$PATH
cat << EOF >> ~/${profile_shell}

# Golang vars
export GOROOT=/usr/local/go
export GOPATH=\$HOME/go
export PATH=\$GOPATH/bin:\$GOROOT/bin:\$HOME/.local/bin:\$PATH
EOF

fi

[ -n "$GOPATH" ] || { printf "${bred} GOPATH env var not detected, add Golang env vars to your \$HOME/.bashrc or \$HOME/.zshrc:\n\n export GOROOT=/usr/local/go\n export GOPATH=\$HOME/go\n export PATH=\$GOPATH/bin:\$GOROOT/bin:\$PATH\n\n"; exit 1; }
[ -n "$GOROOT" ] || { printf "${bred} GOROOT env var not detected, add Golang env vars to your \$HOME/.bashrc or \$HOME/.zshrc:\n\n export GOROOT=/usr/local/go\n export GOPATH=\$HOME/go\n export PATH=\$GOPATH/bin:\$GOROOT/bin:\$PATH\n\n"; exit 1; }

printf "${bblue} Running: Installing requirements ${reset}\n\n"

mkdir -p ~/.gf
mkdir -p $tools
mkdir -p ~/.config/notify/
mkdir -p ~/.config/amass/
mkdir -p ~/.config/nuclei/
touch $dir/.github_tokens

eval wget -N -c https://bootstrap.pypa.io/get-pip.py $DEBUG_STD && eval python3 get-pip.py $DEBUG_STD
eval rm -f get-pip.py $DEBUG_STD
eval ln -s /usr/local/bin/pip3 /usr/local/bin/pip3 $DEBUG_STD
eval pip3 install -I -r requirements.txt $DEBUG_STD

printf "${bblue} Running: Installing Golang tools (${#gotools[@]})${reset}\n\n"
go env -w GO111MODULE=auto
go_step=0
for gotool in "${!gotools[@]}"; do
    go_step=$((go_step + 1))
    eval ${gotools[$gotool]} $DEBUG_STD
    exit_status=$?
    if [ $exit_status -eq 0 ]
    then
        printf "${yellow} $gotool installed (${go_step}/${#gotools[@]})${reset}\n"
    else
        printf "${red} Unable to install $gotool, try manually (${go_step}/${#gotools[@]})${reset}\n"
        double_check=true
    fi
done

printf "${bblue}\n Running: Installing repositories (${#repos[@]})${reset}\n\n"

# Repos with special configs
eval git clone https://github.com/projectdiscovery/nuclei-templates ~/nuclei-templates $DEBUG_STD
eval git clone https://github.com/geeknik/the-nuclei-templates.git ~/nuclei-templates/extra_templates $DEBUG_STD
eval nuclei -update-templates $DEBUG_STD
cd ~/nuclei-templates/extra_templates && eval git pull $DEBUG_STD
cd "$dir" || { echo "Failed to cd to $dir in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
eval sed -i 's/^#random-agent: false/random-agent: true/' ~/.config/nuclei/config.yaml $DEBUG_ERROR
eval git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git $dir/sqlmap $DEBUG_STD
eval git clone --depth 1 https://github.com/drwetter/testssl.sh.git $dir/testssl.sh $DEBUG_STD
eval $SUDO git clone https://github.com/offensive-security/exploitdb.git /opt/exploitdb $DEBUG_STD
eval $SUDO ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit $DEBUG_STD

# Standard repos installation
repos_step=0
for repo in "${!repos[@]}"; do
    repos_step=$((repos_step + 1))
    eval git clone https://github.com/${repos[$repo]} $dir/$repo $DEBUG_STD
    eval cd $dir/$repo $DEBUG_STD
    eval git pull $DEBUG_STD
    exit_status=$?
    if [ $exit_status -eq 0 ]
    then
        printf "${yellow} $repo installed (${repos_step}/${#repos[@]})${reset}\n"
    else
        printf "${red} Unable to install $repo, try manually (${repos_step}/${#repos[@]})${reset}\n"
        double_check=true
    fi
    if [ -s "setup.py" ]; then
        eval $SUDO python3 setup.py install $DEBUG_STD
    fi
    if [ "massdns" = "$repo" ]; then
            eval make $DEBUG_STD && strip -s bin/massdns && eval $SUDO cp bin/massdns /usr/local/bin/ $DEBUG_ERROR
    elif [ "gf" = "$repo" ]; then
            eval cp -r examples ~/.gf $DEBUG_ERROR
    elif [ "Gf-Patterns" = "$repo" ]; then
            eval mv *.json ~/.gf $DEBUG_ERROR
    fi
    cd "$dir" || { echo "Failed to cd to $dir in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
done

if [ "True" = "$IS_ARM" ]
    then
        eval wget -N -c https://github.com/Findomain/Findomain/releases/latest/download/findomain-armv7  $DEBUG_STD
        eval $SUDO mv findomain-armv7 /usr/local/bin/findomain
    else
        eval wget -N -c https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux $DEBUG_STD
        eval wget -N -c https://github.com/Edu4rdSHL/unimap/releases/download/0.4.0/unimap-linux $DEBUG_STD
        eval wget -N -c https://github.com/dwisiswant0/ppfuzz/releases/download/v1.0.1/ppfuzz-v1.0.1-x86_64-unknown-linux-musl.tar.gz $DEBUG_STD
        eval $SUDO tar -C /usr/local/bin/ -xzf ppfuzz-v1.0.1-x86_64-unknown-linux-musl.tar.gz  $DEBUG_STD
        eval $SUDO rm -rf ppfuzz-v1.0.1-x86_64-unknown-linux-musl.tar.gz  $DEBUG_STD
        eval $SUDO mv findomain-linux /usr/local/bin/findomain
        eval $SUDO mv unimap-linux /usr/local/bin/unimap
fi
eval $SUDO chmod 755 /usr/local/bin/findomain
eval $SUDO chmod 755 /usr/local/bin/unimap
eval $SUDO chmod 755 /usr/local/bin/ppfuzz
eval $SUDO chmod +x $tools/uDork/uDork.sh
eval subfinder $DEBUG_STD
eval subfinder $DEBUG_STD

# Downloads
printf "${bblue}\n Running: Downloading required files ${reset}\n\n"

eval wget -nc -O ~/.config/amass/config.ini https://raw.githubusercontent.com/OWASP/Amass/master/examples/config.ini $DEBUG_STD
eval wget -nc -O ~/.gf/potential.json https://raw.githubusercontent.com/devanshbatham/ParamSpider/master/gf_profiles/potential.json $DEBUG_STD
eval wget -nc -O ~/.config/notify/provider-config.yaml https://gist.githubusercontent.com/six2dez/23a996bca189a11e88251367e6583053/raw $DEBUG_STD
eval wget -nc -O getjswords.py https://raw.githubusercontent.com/m4ll0k/Bug-Bounty-Toolz/master/getjswords.py $DEBUG_STD
eval wget -nc -O subdomains_big.txt https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt $DEBUG_STD
eval wget -O resolvers_trusted.txt https://gist.githubusercontent.com/six2dez/ae9ed7e5c786461868abd3f2344401b6/raw $DEBUG_STD
eval wget -O subdomains.txt https://gist.github.com/six2dez/a307a04a222fab5a57466c51e1569acf/raw $DEBUG_STD
eval wget -O permutations_list.txt https://gist.github.com/six2dez/ffc2b14d283e8f8eff6ac83e20a3c4b4/raw $DEBUG_STD
eval wget -nc -O fuzz_wordlist.txt https://raw.githubusercontent.com/six2dez/OneListForAll/main/onelistforallmicro.txt $DEBUG_STD
eval wget -O lfi_wordlist.txt https://gist.githubusercontent.com/six2dez/a89a0c7861d49bb61a09822d272d5395/raw $DEBUG_STD
eval wget -O ssti_wordlist.txt https://gist.githubusercontent.com/six2dez/ab5277b11da7369bf4e9db72b49ad3c1/raw $DEBUG_STD
eval wget -O headers_inject.txt https://gist.github.com/six2dez/d62ab8f8ffd28e1c206d401081d977ae/raw $DEBUG_STD
eval wget -O custom_udork.txt https://gist.githubusercontent.com/six2dez/7245cad74f2da5824080e0cb6bdaac22/raw $DEBUG_STD
eval wget -O axiom_config.sh https://gist.githubusercontent.com/six2dez/6e2d9f4932fd38d84610eb851014b26e/raw $DEBUG_STD
eval wget -O ~/nuclei-templates/extra_templates/ssrf.yaml https://raw.githubusercontent.com/NagliNagli/BountyTricks/main/ssrf.yaml $DEBUG_STD
eval wget -O ~/nuclei-templates/extra_templates/sap-redirect.yaml https://raw.githubusercontent.com/NagliNagli/BountyTricks/main/sap-redirect.yaml $DEBUG_STD
eval $SUDO chmod +x $tools/axiom_config.sh

## Last check
if [ "$double_check" = "true" ]; then
    printf "${bblue} Running: Double check for installed tools ${reset}\n\n"
    go_step=0
    for gotool in "${!gotools[@]}"; do
        go_step=$((go_step + 1))
        eval type -P $gotool $DEBUG_STD || { eval ${gotools[$gotool]} $DEBUG_STD; }
        exit_status=$?
    done
    repos_step=0
    for repo in "${!repos[@]}"; do
        repos_step=$((repos_step + 1))
        eval cd $dir/$repo $DEBUG_STD || { eval git clone https://github.com/${repos[$repo]} $dir/$repo $DEBUG_STD && cd $dir/$repo; }
        eval git pull $DEBUG_STD
        exit_status=$?
        if [ -s "setup.py" ]; then
            eval $SUDO python3 setup.py install $DEBUG_STD
        fi
        if [ "massdns" = "$repo" ]; then
                eval make $DEBUG_STD && strip -s bin/massdns && eval $SUDO cp bin/massdns /usr/local/bin/ $DEBUG_ERROR
        elif [ "gf" = "$repo" ]; then
                eval cp -r examples ~/.gf $DEBUG_ERROR
        elif [ "Gf-Patterns" = "$repo" ]; then
                eval mv *.json ~/.gf $DEBUG_ERROR
        fi
        cd "$dir" || { echo "Failed to cd to $dir in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
    done
fi

# BBRF Setup
if [ ! -d "$HOME/.bbrf/" ] ; then
    mkdir $HOME/.bbrf/
fi
if  [ -d "$HOME/.bbrf/" ] && [ ! -s "$HOME/.bbrf/config.json" ]; then
    cat > $HOME/.bbrf/config.json << EOF
{
    "username": "$BBRF_USERNAME",
    "password": "$BBRF_PASSWORD",
    "couchdb": "https://$BBRF_SERVER/bbrf",
    "slack_token": "<a slack token to receive notifications>",
    "discord_webhook": "<your discord webhook if you want one>",
    "ignore_ssl_errors": false
}
EOF
fi

printf "${bblue} Running: Performing last configurations ${reset}\n\n"
#Last steps
if [ ! -s "resolvers.txt" ] || [ $(find "resolvers.txt" -mtime +1 -print) ]; then
    printf "${yellow} Resolvers seem older than 1 day\n Generating custom resolvers... ${reset}\n\n"
    eval rm -f resolvers.txt &>/dev/null
    eval dnsvalidator -tL https://public-dns.info/nameservers.txt -threads $DNSVALIDATOR_THREADS -o resolvers.txt $DEBUG_STD
    eval dnsvalidator -tL https://raw.githubusercontent.com/blechschmidt/massdns/master/lists/resolvers.txt -threads $DNSVALIDATOR_THREADS -o tmp_resolvers $DEBUG_STD
    eval cat tmp_resolvers $DEBUG_ERROR | anew -q resolvers.txt
    eval rm -f tmp_resolvers $DEBUG_STD
fi
eval h8mail -g $DEBUG_STD

## Stripping all Go binaries
eval strip -s $HOME/go/bin/* $DEBUG_STD

eval $SUDO cp $HOME/go/bin/* /usr/local/bin/ $DEBUG_STD

printf "${yellow} Remember set your api keys:\n - amass (~/.config/amass/config.ini)\n - subfinder (~/.config/subfinder/config.yaml)\n - GitHub (~/Tools/.github_tokens)\n - SHODAN (SHODAN_API_KEY in bb_recon.cfg or env var)\n - SSRF Server (COLLAB_SERVER in bb_recon.cfg or env var) \n - Blind XSS Server (XSS_SERVER in bb_recon.cfg or env var) \n - notify (~/.config/notify/provider-config.yaml) \n - theHarvester (~/Tools/theHarvester/api-keys.yml)\n - H8mail (~/Tools/h8mail_config.ini)\n - uDork FB cookie (UDORK_COOKIE in bb_recon.cfg or env var)\n - WHOISXML API (WHOISXML_API in bb_recon.cfg or env var)\n\n\n${reset}"
printf "${bgreen} Finished!${reset}\n\n"
printf "\n\n${bgreen}#######################################################################${reset}\n"

# Cleanup
echo -e "${GREEN}[*] Tidying up${NC}"
apt-get clean

echo -e "${GREEN}[*] Installation Complete! ${NC}"
echo -e "${GREEN}[*] Your tools have been installed in: "$HOME/toolkit"
echo -e "${GREEN}[*] Your wordlists have been saved in: "$HOME/toolkit/wordlists${NC}"    