#!/bin/bash
#    ░▒▓█ ☁️ Tsholo Script 1.0.0 ☁️ █▓▒░" 
#                         by: TsholoVPN

#########################################################
###      Input Your Desired Configuration Information
#########################################################

# Script Name
MyScriptName='TsholoScript'

# Server Name for openvpn config and banner
ServerName='Tsholo-VPN'

# OpenSSH Ports
SSH_Port1='22'
SSH_Port2='299'

# Dropbear Ports
Dropbear_Port1='790'
Dropbear_Port2='2770'

# Stunnel Ports
Stunnel_Port1='446' # through Dropbear
Stunnel_Port2='444' # through OpenSSH
Stunnel_Port3='445' # through Openvpn
Stunnel_Port4='441' # through WebSocket
Stunnel_Port5='443' # through SSLH

# OpenVPN Ports
OpenVPN_TCP_Port='1194'
OpenVPN_UDP_Port='1195'

# Squid Ports
Squid_Port1='3128'
Squid_Port2='8080'
Squid_Port3='9005'

# V2ray UUID
UUID='1838c855-ec44-46d5-9889-f6f8ffbd06b8'

# V2ray Ports
V2ray_Port1='10085' 
V2ray_Port2='30300' 
V2ray_Port3='30310'

# Python Socks Proxy
WsPort='2424'  # for port 8080 change cloudflare SSL/TLS to full
WsResponse='HTTP/1.1 101 Switching Protocols\r\n\r\n'

# SSLH Port
MainPort='666' # main port to tunnel default 443

# WebServer Ports
Php_Socket='9000'
Openvpn_Monitoring='89'
Tcp_Monitor_Port='450'
Udp_Monitor_Port='451'
Nginx_Port='85' 
Nginx_vpn='80'
Apache_Port='2087' # for openvpn panel stat port

# DNS Resolver
Dns_1='1.1.1.1' # GoogleDNS
Dns_2='1.0.0.1' # GoogleDNS

# Server local time
MyVPS_Time='Africa/Johannesburg'

# Database Info for panel
DatabaseHost='185.61.137.174';
DatabaseName='vpnquest1_dbase';
DatabaseUser='vpnquest1_user';
DatabasePass='s+(WT#r4CaB&';
DatabasePort='3306';

#########################################################
###        Tsholo Script AutoScript Code Begins...
#########################################################

function ip_address(){
  local IP="$( ip addr | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | egrep -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1 )"
  [ -z "${IP}" ] && IP="$( wget -qO- -t1 -T2 ipv4.icanhazip.com )"
  [ -z "${IP}" ] && IP="$( wget -qO- -t1 -T2 ipinfo.io/ip )"
  [ ! -z "${IP}" ] && echo "${IP}" || echo
} 
IPADDR="$(ip_address)"

# Colours
red='\e[1;31m'
green='\e[0;32m'
NC='\e[0m'

# Requirement
apt install -y bzip2 gzip coreutils curl
sysctl -w net.ipv6.conf.all.disable_ipv6=1 && sysctl -w net.ipv6.conf.default.disable_ipv6=1

# Initializing Server
export DEBIAN_FRONTEND=noninteractive
source /etc/os-release

# Get Update
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get upgrade -y

# Disable IPV6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6

# Add DNS server ipv4
echo "nameserver $Dns_1" > /etc/resolv.conf
echo "nameserver $Dns_2" >> /etc/resolv.conf

# Install Components
apt-get -y install libio-pty-perl libauthen-pam-perl apt-show-versions libnet-ssleay-perl

# Set System Time
ln -fs /usr/share/zoneinfo/$MyVPS_Time /etc/localtime

# NeoFetch
apt-get --reinstall --fix-missing install -y bzip2 gzip coreutils wget screen rsyslog iftop htop net-tools zip unzip wget net-tools curl nano sed screen gnupg gnupg1 bc apt-transport-https build-essential dirmngr libxml-parser-perl neofetch git
rm .profile
cat << 'intro' >> .profile
white='\e[0;37m'
green='\e[0;32m'
NC='\e[0m'
if [ "$BASH" ]; then
  if [ -f ~/.bashrc ]; then
    . ~/.bashrc
  fi
fi
mesg n || true
clear
echo ""
echo ""
figlet TsholoVPN -c | lolcat
echo -e "                             ${white}Welcome to ⚽TsholoVPN${NC}"
echo -e "                          ${green}Type 'menu' To List Commands${NC}"
intro
# Removing some firewall tools that may affect other services
apt-get remove --purge ufw firewalld -y
 
# Installing some important machine essentials
apt-get install nano sudo wget zip unzip tar gzip iptables bc rc build-essential gcc cron dos2unix whois ngrep screen whois ngrep dnsutils ruby -y

# Now installing all our wanted services
apt-get install dropbear openvpn stunnel4 squid python3 apt-transport-https software-properties-common gnupg2 ca-certificates curl nginx fail2ban mariadb-server sslh -y

# Installing all required packages to install Webmin
apt-get install perl libnet-ssleay-perl libauthen-pam-perl libio-pty-perl apt-show-versions shared-mime-info -y

# Installing a text colorizer and design
gem install lolcat
apt-get install figlet

# Installing Php
apt -y install php php-fpm php-cli php-mysql php-xml php-json php-common php-zip php-gd php-mbstring php-curl php-bcmath

# Stop Nginx
systemctl stop nginx
service nginx stop

# Install Apache2
sudo apt-get install apache2 -y

# Setup Apache
sed -i "s|Listen 80|Listen $Apache_Port|g" /etc/apache2/ports.conf
systemctl enable apache2
service apache2 restart
systemctl reload apache2 #activate

cd /etc/default/
mv sslh sslh-old
cat << sslh > /etc/default/sslh
RUN=yes

DAEMON=/usr/sbin/sslh

DAEMON_OPTS="--user sslh --listen 127.0.0.1:$MainPort --ssl 127.0.0.1:$Nginx_vpn --ssh 127.0.0.1:$Dropbear_Port2 --openvpn 127.0.0.1:$OpenVPN_TCP_Port --pidfile /var/run/sslh/sslh.pid"

sslh

#Restart Service
systemctl daemon-reload
systemctl enable sslh
systemctl start sslh
systemctl restart sslh
service sslh restart

# remove unused
apt-get -y --purge remove samba*;
apt-get -y --purge remove sendmail*;
apt-get -y --purge remove bind9*;

# Setup Mysql
apt-get install expect libdbi-perl libecap3 -y

# Mysql Secure Installation
so1=$(expect -c "
spawn mysql_secure_installation; sleep 3
expect \"\";  sleep 3; send \"\r\"
expect \"\";  sleep 3; send \"Y\r\"
expect \"\";  sleep 3; send \"$DatabasePass\r\"
expect \"\";  sleep 3; send \"$DatabasePass\r\"
expect \"\";  sleep 3; send \"Y\r\"
expect \"\";  sleep 3; send \"n\r\"
expect \"\";  sleep 3; send \"Y\r\"
expect \"\";  sleep 3; send \"Y\r\"
expect eof; ")
echo "$so1"

# Mysql Configure localhost
sed -i '/bind-address/c\bind-address=*' /etc/mysql/mariadb.conf.d/50-server.cnf
sed -i '/max_connections/c\max_connections = 5000' /etc/mysql/mariadb.conf.d/50-server.cnf
 
# Then restart to take effect
systemctl restart mysql
service mysql restart

# Bbanner
apt-get -y install geoip-bin
ipadd=$(wget -qO- ipv4.icanhazip.com);
geoip=$(whois $ipadd |grep country -i -m 1 |cut -d ':' -f 2 |xargs);
geoip2=$(whois $ipadd |grep descr -i -m 1 |cut -d ':' -f 2 |xargs);

cat << banner > /etc/zorro-luffy
<br><font color="blue"><b>⚽TsholoVPN</b></font>
<br><font color="red"><b>Server: $geoip, $geoip2</b></font><br>
banner

# Removing some duplicated sshd server configs
rm -f /etc/ssh/sshd_config
sleep 1

# Creating a SSH server config using cat eof tricks
cat <<'MySSHConfig' > /etc/ssh/sshd_config
# Tsholo Script OpenSSH Server config
# Tsholo Script
Port myPORT1
Port myPORT2
AddressFamily inet
ListenAddress 0.0.0.0
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
PermitRootLogin yes
MaxSessions 1024
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
ClientAliveInterval 300
ClientAliveCountMax 2
UseDNS no
Banner /etc/zorro-luffy
AcceptEnv LANG LC_*
Subsystem  sftp  /usr/lib/openssh/sftp-server
MySSHConfig

sleep 2
# Now we'll put our ssh ports inside of sshd_config
sed -i "s|myPORT1|$SSH_Port1|g" /etc/ssh/sshd_config
sed -i "s|myPORT2|$SSH_Port2|g" /etc/ssh/sshd_config

# My workaround code to remove `BAD Password error` from passwd command, it will fix password-related error on their ssh accounts.
sed -i '/password\s*requisite\s*pam_cracklib.s.*/d' /etc/pam.d/common-password
sed -i 's/use_authtok //g' /etc/pam.d/common-password

# Some command to identify null shells when you tunnel through SSH or using Stunnel, it will fix user/pass authentication error on HTTP Injector, KPN Tunnel, eProxy, SVI, HTTP Proxy Injector etc ssh/ssl tunneling apps.
sed -i '/\/bin\/false/d' /etc/shells
sed -i '/\/usr\/sbin\/nologin/d' /etc/shells
echo '/bin/false' >> /etc/shells
echo '/usr/sbin/nologin' >> /etc/shells

# Restarting openssh service
systemctl restart ssh
service ssh restart
  
# Removing some duplicate config file
rm -rf /etc/default/dropbear*
 
# creating dropbear config using cat eof tricks
cat <<'MyDropbear' > /etc/default/dropbear
# Tsholo Script Dropbear Config
NO_START=0
DROPBEAR_PORT=PORT01
DROPBEAR_EXTRA_ARGS="-p PORT02"
DROPBEAR_BANNER="/etc/zorro-luffy"
DROPBEAR_RSAKEY="/etc/dropbear/dropbear_rsa_host_key"
DROPBEAR_DSSKEY="/etc/dropbear/dropbear_dss_host_key"
DROPBEAR_ECDSAKEY="/etc/dropbear/dropbear_ecdsa_host_key"
DROPBEAR_RECEIVE_WINDOW=65536
MyDropbear

# Now changing our desired dropbear ports
sed -i "s|PORT01|$Dropbear_Port1|g" /etc/default/dropbear
sed -i "s|PORT02|$Dropbear_Port2|g" /etc/default/dropbear
 
# Restarting dropbear service
systemctl restart dropbear
service dropbear restart

# STUNNEL
StunnelDir=$(ls /etc/default | grep stunnel | head -n1)

# Creating stunnel startup config using cat eof tricks
cat <<'MyStunnelD' > /etc/default/$StunnelDir
# Tsholo Script Stunnel Config
ENABLED=1
FILES="/etc/stunnel/*.conf"
OPTIONS=""
BANNER="/etc/zorro-luffy"
PPP_RESTART=0
# RLIMITS="-n 4096 -d unlimited"
RLIMITS=""
MyStunnelD

# Removing all stunnel folder contents
rm -rf /etc/stunnel/*
 
# Creating stunnel certifcate using openssl
# openssl req -new -x509 -days 9999 -nodes -subj "/C=SA/ST=KZN/L=Durban/O=$MyScriptName/OU=$MyScriptName/CN=$MyScriptName" -out /etc/stunnel/stunnel.pem -keyout /etc/stunnel/stunnel.pem

# Zero SSL Wildcard Certificate
cat <<'MyCertificate' > /etc/stunnel/stunnel.pem
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAmvMsFiCrjpH+S+N6u7sHOIn/6yVtuyrwkykRfYepYjiWOfBy
Px5pPUcNhYN4om9NIget37Z4E843n2FsaI/AWMr9SFzgAUjhzQRfZQ/0qZJlQBKR
hLBp1wJsxDVQWgxb8KTivpVEEM6lAx+r+bn9d0iiI3KiaYHUh5LkTIsVMRwWdGJd
yTqIlAGYk7371h1ZQpCxZm93snkZkr27tJ1BsqIs7jp+LpReZC+67GpagQk2co07
Q7PMcKF0pa0Lqui2nSAsRngAyGODgjP4WRKr7iEAoyv/ON1Ni4t+Vy/SbAf3PW93
hBhkqApbT/NfmaXrof8EUmVOOmcm2Gyfy8vtnwIDAQABAoIBAQCCWzfoub16qQoW
EB9uFk9h2n9J9WgWgW55b6B+SgZPUqnXvphuz4fb/I28mDmB9j8e9PTrc1gb2W5k
EJMieGVqjgN9wFzX19fXIembXUwI6NdziuuPhNbWAv08KFocF6+1iRIVIgBsX1zl
ftywsC80DhAR4FwQhSAmmoakepHuiJFwVtNoYBEOPG/w7p3cc/4+OjSO0UMM+9VN
0mUCG6ug4ZYIp5uaas+40NWDzQo5ydpy7vyP/02ed163ApWrpzYXMX5dRfyWBTqR
Zww0b0Oq+mJSyRJObgLRrUD19+ThbijtNQHt6JS2Firj/CCDWfhX8BtMzNg2dDiA
7rAex2PJAoGBANi1zH8kwY1OxrNTJ6RPx0s9ggjnp8A1pLi1ilVi7iUaJe6AP8hE
/Sl0+Xy8wPdQ/aI4WCFhCYV63FniDJOVHrXxzVReTwC3/vDmN1Ryp/lg6NiualOu
RfgEETLI2KANzsTEJ7oFRPRUE9mqrAsFz45pbVLn67c9wKP8xlKPugrbAoGBALcK
4pNgR/Y4z97ACzOdQ8MdjpxFDE5S5KpK3AMDg3LhoLrpSzLJAfwP7fiEdijS9+Ll
sNkXIPLU91VSYQkusgpfHOa+KUeMx26PxvU9u9FD0yqL0czJ48S5i2ED/6kA7t9k
Znorjte5IN7hHDPXUGIDXHZ+qtbwtMxfTPGtysmNAoGAd8jddTXa6oGtoTeIhPE4
BqXD96ocdkjweMyX3ySk38s5RkCLgOZpTP4EXWdz/gA9gepFBIY/nhFQNTqWmwjl
BcrXJRhP8OTDPWLzGHGb2WMwsXyO9xwwPqv42apc2vNm5CpMjy0UdTz4D+uf1yPq
Gxy5OgdJqmquzbYN5VreidsCgYBFwGIjIxeJHpEoIyqhmpZN7h+AMVfFKRV2R1yb
0WTwDEcBsxEy4yJceX2HrIKSgAJydnDz6TpnDvzJiMDtjNvP0/rheymj2GPPH/8D
SWkfD6eSmQFz9qNTPhl8+NceAfsFKe9bMuoWDrgV9taWcsBw+TLs/MwBaGydTNu3
ZTDXqQKBgD86uTlDCDzZkHrsooE0eTUSepWakiwWBqpNzTiWX4UH1Bf8KVupDkLU
yE5BgX+WBi2EHsPQBBQPaaZo9XaC0+9u+EmRAMoVvx/A8rwmk62rm0z5Ohm03ikH
V1glD2Q+xyRBbe69BRDQbsqirubH8/cO2w9U+w2ZnihU+dGq2rsm
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIG9TCCBN2gAwIBAgIRALvSyPGs2uS4veADF6vyGNUwDQYJKoZIhvcNAQEMBQAw
SzELMAkGA1UEBhMCQVQxEDAOBgNVBAoTB1plcm9TU0wxKjAoBgNVBAMTIVplcm9T
U0wgUlNBIERvbWFpbiBTZWN1cmUgU2l0ZSBDQTAeFw0yMjEwMDgwMDAwMDBaFw0y
MzEwMDgyMzU5NTlaMBoxGDAWBgNVBAMMDyouZGVla2F5dnBuLm5ldDCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAJrzLBYgq46R/kvjeru7BziJ/+slbbsq
8JMpEX2HqWI4ljnwcj8eaT1HDYWDeKJvTSIHrd+2eBPON59hbGiPwFjK/Uhc4AFI
4c0EX2UP9KmSZUASkYSwadcCbMQ1UFoMW/Ck4r6VRBDOpQMfq/m5/XdIoiNyommB
1IeS5EyLFTEcFnRiXck6iJQBmJO9+9YdWUKQsWZvd7J5GZK9u7SdQbKiLO46fi6U
XmQvuuxqWoEJNnKNO0OzzHChdKWtC6rotp0gLEZ4AMhjg4Iz+FkSq+4hAKMr/zjd
TYuLflcv0mwH9z1vd4QYZKgKW0/zX5ml66H/BFJlTjpnJthsn8vL7Z8CAwEAAaOC
AwMwggL/MB8GA1UdIwQYMBaAFMjZeGii2Rlo1T1y3l8KPty1hoamMB0GA1UdDgQW
BBSzSpt3MErSyi17AusdXiLFwTfxfjAOBgNVHQ8BAf8EBAMCBaAwDAYDVR0TAQH/
BAIwADAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwSQYDVR0gBEIwQDA0
BgsrBgEEAbIxAQICTjAlMCMGCCsGAQUFBwIBFhdodHRwczovL3NlY3RpZ28uY29t
L0NQUzAIBgZngQwBAgEwgYgGCCsGAQUFBwEBBHwwejBLBggrBgEFBQcwAoY/aHR0
cDovL3plcm9zc2wuY3J0LnNlY3RpZ28uY29tL1plcm9TU0xSU0FEb21haW5TZWN1
cmVTaXRlQ0EuY3J0MCsGCCsGAQUFBzABhh9odHRwOi8vemVyb3NzbC5vY3NwLnNl
Y3RpZ28uY29tMCkGA1UdEQQiMCCCDyouZGVla2F5dnBuLm5ldIINZGVla2F5dnBu
Lm5ldDCCAX0GCisGAQQB1nkCBAIEggFtBIIBaQFnAHUArfe++nz/EMiLnT2cHj4Y
arRnKV3PsQwkyoWGNOvcgooAAAGDt98rBwAABAMARjBEAiA5KQtcmZu/XVjAb90v
Bahae/fhyf/V7HqLGbxdccBqigIgbyuqme1VwAeS2xgy3+Y4qHKiE+H8pmmiC76V
D5Cgnq0AdgB6MoxU2LcttiDqOOBSHumEFnAyE4VNO9IrwTpXo1LrUgAAAYO33yry
AAAEAwBHMEUCIBaNVjTgU+oOYrnyl/V0LGC2/qPF5eVnhqTSjU4EopmyAiEAsxax
7tuwu/Wm7HMwzVbLxHjQ1ZU+6TvSVr1vnqkaLgcAdgDoPtDaPvUGNTLnVyi8iWvJ
A9PL0RFr7Otp4Xd9bQa9bgAAAYO33yq+AAAEAwBHMEUCIQDjfshAutU3gIRBK48G
KeWK/rBL1hPQQGsH+8i+hXBOXQIgRq4+9bC4nr9qHvwms0SHsDtegFxPJx1SmYXC
e3PBXJswDQYJKoZIhvcNAQEMBQADggIBACDOXd25nSlzH1OZVl5APwrLZxP6RYz7
gxpIn+5u3BQDt+mjzT+5SW/CD/YEmSg2wkP5G9OJAUBZhLnNiobj3R40kQEUhgCQ
A9t4hwN5Ce8r2KNdLCSx6I86m4lFKu1lorG4qvinSKleq0MJIySUxY9ghKXNqMev
pviaent4f3VbYDAa/42W2SBScB9/1odPhEZ6zkfnnF9r2E9+y+Z4N0FaEtqSg8xj
/vH7uIrqpAZ+OJ1LEC4Bb/zDSUnyrpik/SVYDzgq1+n8gm8wj3D24n9AbFhCbi7R
5Vhlr81ZlK7Rt1jyamcUXcZHg2vPLkHQUUSUVol3giksJGKUbKhL9YcMZSeNsXPt
gwmwEylkzwAmS66s2ha6GB1XezhgXEZrDCFdqi/WWI9FVjXkgoFehGkoKCk3p4Q4
LiX3uDGa4rlbn9I1dChmP4QA5jYY5ueXLvjVQoY6lCjUv2d4heFCgmLH+3rCWx3p
CfDh3sSmyIM4TDUfa0Eg22HLh1v8C+DFK/oozQz9eGkQz/7MZ7iX+SKVZqJdwl/X
Sf/TFPfyB50mrQ11nROxljClXz+KGcHsFp3cVtQc9MSPuehTO4eWpnFnnMrql7za
UF6gcSb7jwFb6vCe8F+Gp5JRT5rhqNJLrf+YrvXcAwWSRxB8dpguxmaBzScfDOTe
tMnA4zIN8Ik3
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIG1TCCBL2gAwIBAgIQbFWr29AHksedBwzYEZ7WvzANBgkqhkiG9w0BAQwFADCB
iDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0pl
cnNleSBDaXR5MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNV
BAMTJVVTRVJUcnVzdCBSU0EgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMjAw
MTMwMDAwMDAwWhcNMzAwMTI5MjM1OTU5WjBLMQswCQYDVQQGEwJBVDEQMA4GA1UE
ChMHWmVyb1NTTDEqMCgGA1UEAxMhWmVyb1NTTCBSU0EgRG9tYWluIFNlY3VyZSBT
aXRlIENBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAhmlzfqO1Mdgj
4W3dpBPTVBX1AuvcAyG1fl0dUnw/MeueCWzRWTheZ35LVo91kLI3DDVaZKW+TBAs
JBjEbYmMwcWSTWYCg5334SF0+ctDAsFxsX+rTDh9kSrG/4mp6OShubLaEIUJiZo4
t873TuSd0Wj5DWt3DtpAG8T35l/v+xrN8ub8PSSoX5Vkgw+jWf4KQtNvUFLDq8mF
WhUnPL6jHAADXpvs4lTNYwOtx9yQtbpxwSt7QJY1+ICrmRJB6BuKRt/jfDJF9Jsc
RQVlHIxQdKAJl7oaVnXgDkqtk2qddd3kCDXd74gv813G91z7CjsGyJ93oJIlNS3U
gFbD6V54JMgZ3rSmotYbz98oZxX7MKbtCm1aJ/q+hTv2YK1yMxrnfcieKmOYBbFD
hnW5O6RMA703dBK92j6XRN2EttLkQuujZgy+jXRKtaWMIlkNkWJmOiHmErQngHvt
iNkIcjJumq1ddFX4iaTI40a6zgvIBtxFeDs2RfcaH73er7ctNUUqgQT5rFgJhMmF
x76rQgB5OZUkodb5k2ex7P+Gu4J86bS15094UuYcV09hVeknmTh5Ex9CBKipLS2W
2wKBakf+aVYnNCU6S0nASqt2xrZpGC1v7v6DhuepyyJtn3qSV2PoBiU5Sql+aARp
wUibQMGm44gjyNDqDlVp+ShLQlUH9x8CAwEAAaOCAXUwggFxMB8GA1UdIwQYMBaA
FFN5v1qqK0rPVIDh2JvAnfKyA2bLMB0GA1UdDgQWBBTI2XhootkZaNU9ct5fCj7c
tYaGpjAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHSUE
FjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwIgYDVR0gBBswGTANBgsrBgEEAbIxAQIC
TjAIBgZngQwBAgEwUAYDVR0fBEkwRzBFoEOgQYY/aHR0cDovL2NybC51c2VydHJ1
c3QuY29tL1VTRVJUcnVzdFJTQUNlcnRpZmljYXRpb25BdXRob3JpdHkuY3JsMHYG
CCsGAQUFBwEBBGowaDA/BggrBgEFBQcwAoYzaHR0cDovL2NydC51c2VydHJ1c3Qu
Y29tL1VTRVJUcnVzdFJTQUFkZFRydXN0Q0EuY3J0MCUGCCsGAQUFBzABhhlodHRw
Oi8vb2NzcC51c2VydHJ1c3QuY29tMA0GCSqGSIb3DQEBDAUAA4ICAQAVDwoIzQDV
ercT0eYqZjBNJ8VNWwVFlQOtZERqn5iWnEVaLZZdzxlbvz2Fx0ExUNuUEgYkIVM4
YocKkCQ7hO5noicoq/DrEYH5IuNcuW1I8JJZ9DLuB1fYvIHlZ2JG46iNbVKA3ygA
Ez86RvDQlt2C494qqPVItRjrz9YlJEGT0DrttyApq0YLFDzf+Z1pkMhh7c+7fXeJ
qmIhfJpduKc8HEQkYQQShen426S3H0JrIAbKcBCiyYFuOhfyvuwVCFDfFvrjADjd
4jX1uQXd161IyFRbm89s2Oj5oU1wDYz5sx+hoCuh6lSs+/uPuWomIq3y1GDFNafW
+LsHBU16lQo5Q2yh25laQsKRgyPmMpHJ98edm6y2sHUabASmRHxvGiuwwE25aDU0
2SAeepyImJ2CzB80YG7WxlynHqNhpE7xfC7PzQlLgmfEHdU+tHFeQazRQnrFkW2W
kqRGIq7cKRnyypvjPMkjeiV9lRdAM9fSJvsB3svUuu1coIG1xxI1yegoGM4r5QP4
RGIVvYaiI76C0djoSbQ/dkIUUXQuB8AL5jyH34g3BZaaXyvpmnV4ilppMXVAnAYG
ON51WhJ6W0xNdNJwzYASZYH+tmCWI+N60Gv2NNMGHwMZ7e9bXgzUCZH5FaBFDGR5
S9VWqHB73Q+OyIVvIbKYcSc2w/aSuFKGSA==
-----END CERTIFICATE-----
MyCertificate

# Creating stunnel server config
cat <<'MyStunnelC' > /etc/stunnel/stunnel.conf
# My Stunnel Config
pid = /var/run/stunnel.pid
cert = /etc/stunnel/stunnel.pem
client = no
syslog = no
debug = 0
output = /dev/null
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
TIMEOUTclose = 0

[dropbear]
accept = Stunnel_Port1
connect = 127.0.0.1:dropbear_port_c

[openssh]
accept = Stunnel_Port2
connect = 127.0.0.1:openssh_port_c

[openvpn]
accept = Stunnel_Port3
connect = 127.0.0.1:openvpn_port_c

[websocket]
accept = Stunnel_Port4
connect = 127.0.0.1:WsPort

[sslh]
accept = Stunnel_Port5
connect = 127.0.0.1:MainPort

MyStunnelC

# setting stunnel ports
sed -i "s|Stunnel_Port1|$Stunnel_Port1|g" /etc/stunnel/stunnel.conf
sed -i "s|Stunnel_Port2|$Stunnel_Port2|g" /etc/stunnel/stunnel.conf
sed -i "s|Stunnel_Port3|$Stunnel_Port3|g" /etc/stunnel/stunnel.conf
sed -i "s|Stunnel_Port4|$Stunnel_Port4|g" /etc/stunnel/stunnel.conf
sed -i "s|Stunnel_Port5|$Stunnel_Port5|g" /etc/stunnel/stunnel.conf
sed -i "s|dropbear_port_c|$Dropbear_Port1|g" /etc/stunnel/stunnel.conf
sed -i "s|openssh_port_c|$SSH_Port1|g" /etc/stunnel/stunnel.conf
sed -i "s|openvpn_port_c|$OpenVPN_TCP_Port|g" /etc/stunnel/stunnel.conf
sed -i "s|WsPort|$WsPort|g" /etc/stunnel/stunnel.conf
sed -i "s|MainPort|$MainPort|g" /etc/stunnel/stunnel.conf

# Restarting stunnel service
systemctl restart $StunnelDir
service $StunnelDir restart

# SOCKS PROXY
mkdir -p /etc/Tsholo-script/py-socksproxy

# Setting Up Socks
loc=/etc/socksproxy
apachedir=/var/www/html
mkdir -p $loc

rm -rf $apachedir/index.html
rm -rf apachedir/index.nginx-debian.html
cat << web > $apachedir/index.html
<!DOCTYPE html>
<html>
<head>
    <title>SocksProxy</title>
    <meta name="viewport" content="width=device-width">
</head>
<body>
    <center>SocksProxy Server by<br><a href="https://t.me/TsholoVPN">TsholoVPN</a><br><br>Copyright &#169; 2022</center>
</body>
</html>
web

cat << Socks > $loc/proxy.py
import socket, threading, thread, select, signal, sys, time, getopt

# CONFIG
LISTENING_ADDR = '0.0.0.0'
LISTENING_PORT = $WsPort
PASS = ''

# CONST
BUFLEN = 4096 * 4
TIMEOUT = 60
SSH_HOST = '127.0.0.1:$Dropbear_Port1'
OPENVPN_HOST = '127.0.0.1:$OpenVPN_TCP_Port'
RESPONSE = '$WsResponse'
 
class Server(threading.Thread):
    def __init__(self, host, port):
        threading.Thread.__init__(self)
        self.running = False
        self.host = host
        self.port = port
        self.threads = []
	self.threadsLock = threading.Lock()
	self.logLock = threading.Lock()

    def run(self):
        self.soc = socket.socket(socket.AF_INET)
        self.soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.soc.settimeout(2)
        self.soc.bind((self.host, self.port))
        self.soc.listen(0)
        self.running = True

        try:                    
            while self.running:
                try:
                    c, addr = self.soc.accept()
                    c.setblocking(1)
                except socket.timeout:
                    continue
                
                conn = ConnectionHandler(c, self, addr)
                conn.start();
                self.addConn(conn)
        finally:
            self.running = False
            self.soc.close()
            
    def printLog(self, log):
        self.logLock.acquire()
        print log
        self.logLock.release()
	
    def addConn(self, conn):
        try:
            self.threadsLock.acquire()
            if self.running:
                self.threads.append(conn)
        finally:
            self.threadsLock.release()
                    
    def removeConn(self, conn):
        try:
            self.threadsLock.acquire()
            self.threads.remove(conn)
        finally:
            self.threadsLock.release()
                
    def close(self):
        try:
            self.running = False
            self.threadsLock.acquire()
            
            threads = list(self.threads)
            for c in threads:
                c.close()
        finally:
            self.threadsLock.release()
			

class ConnectionHandler(threading.Thread):
    def __init__(self, socClient, server, addr):
        threading.Thread.__init__(self)
        self.clientClosed = False
        self.targetClosed = True
        self.client = socClient
        self.client_buffer = ''
        self.server = server
        self.log = 'Connection: ' + str(addr)

    def close(self):
        try:
            if not self.clientClosed:
                self.client.shutdown(socket.SHUT_RDWR)
                self.client.close()
        except:
            pass
        finally:
            self.clientClosed = True
            
        try:
            if not self.targetClosed:
                self.target.shutdown(socket.SHUT_RDWR)
                self.target.close()
        except:
            pass
        finally:
            self.targetClosed = True

    def run(self):
        try:
            self.client_buffer = self.client.recv(BUFLEN)        
            hostPort = self.findHeader(self.client_buffer, 'X-Real-Host')
            passwd = self.findHeader(self.client_buffer, 'X-Pass')
				
                if len(PASS) != 0 and passwd == PASS:
                    self.method_CONNECT(SSH_HOST)
                elif len(PASS) != 0 and passwd != PASS:
                    self.client.send('HTTP/1.1 400 WrongPass!\r\n\r\n')
                elif hostPort.startswith('127.0.0.1') or hostPort.startswith('localhost'):
                    self.method_CONNECT(SSH_HOST)
                else:
                    self.client.send('HTTP/1.1 403 Forbidden!\r\n\r\n')
            else:
                print '- No X-Pass Switching Protocols To Openvpn!'
                self.method_CONNECT(OPENVPN_HOST)

        except Exception as e:
            self.log += ' - error: ' + e.strerror
            self.server.printLog(self.log)
	    pass
        finally:
            self.close()
            self.server.removeConn(self)

    def findHeader(self, head, header):
        aux = head.find(header + ': ')
    
        if aux == -1:
            return ''

        aux = head.find(':', aux)
        head = head[aux+2:]
        aux = head.find('\r\n')

        if aux == -1:
            return ''

        return head[:aux];

    def connect_target(self, host):
        i = host.find(':')
        if i != -1:
            port = int(host[i+1:])
            host = host[:i]
        else:
            if self.method=='CONNECT':
                port = 443
            else:
                port = 80

        (soc_family, soc_type, proto, _, address) = socket.getaddrinfo(host, port)[0]

        self.target = socket.socket(soc_family, soc_type, proto)
        self.targetClosed = False
        self.target.connect(address)

    def method_CONNECT(self, path):
        self.log += ' - CONNECT ' + path
        
        self.connect_target(path)
        self.client.sendall(RESPONSE)
        self.client_buffer = ''

        self.server.printLog(self.log)
        self.doCONNECT()

    def doCONNECT(self):
        socs = [self.client, self.target]
        count = 0
        error = False
        while True:
            count += 1
            (recv, _, err) = select.select(socs, [], socs, 3)
            if err:
                error = True
            if recv:
                for in_ in recv:
		    try:
                        data = in_.recv(BUFLEN)
                        if data:
			    if in_ is self.target:
				self.client.send(data)
                            else:
                                while data:
                                    byte = self.target.send(data)
                                    data = data[byte:]

                            count = 0
			else:
			    break
		    except:
                        error = True
                        break
            if count == TIMEOUT:
                error = True

            if error:
                break


def print_usage():
    print 'Usage: proxy.py -p <port>'
    print 'proxy.py -b <bindAddr> -p <port>'
    print 'proxy.py -b 0.0.0.0 -p $WsPort'

def parse_args(argv):
    global LISTENING_ADDR
    global LISTENING_PORT
    
    try:
        opts, args = getopt.getopt(argv,"hb:p:",["bind=","port="])
    except getopt.GetoptError:
        print_usage()
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print_usage()
            sys.exit()
        elif opt in ("-b", "--bind"):
            LISTENING_ADDR = arg
        elif opt in ("-p", "--port"):
            LISTENING_PORT = int(arg)
    

def main(host=LISTENING_ADDR, port=LISTENING_PORT):
    
    print "\n ==============================\n"
    print "\n         PYTHON PROXY          \n"
    print "\n ==============================\n"
    print "corriendo ip: " + LISTENING_ADDR
    print "corriendo port: " + str(LISTENING_PORT) + "\n"
    print "Se ha Iniciado Por Favor Cierre el Terminal\n"
    
    server = Server(LISTENING_ADDR, LISTENING_PORT)
    server.start()

    while True:
        try:
            time.sleep(2)
        except KeyboardInterrupt:
            print 'Stopping...'
            server.close()
            break
    
if __name__ == '__main__':
    parse_args(sys.argv[1:])
    main()

Socks

# creating a service
cat << service > /etc/systemd/system/socksproxy.service
[Unit]
Description=Socks Proxy
Documentation=https://Tsholovpn.net/
After=network.target nss-lookup.target
[Service]
Type=simple
User=root
NoNewPrivileges=true
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
ExecStart=/usr/bin/python -O /etc/socksproxy/proxy.py
ProtectSystem=true
ProtectHome=true
RemainAfterExit=yes
Restart=on-failure
[Install]
WantedBy=multi-user.target
service

# start the service
systemctl daemon-reload
systemctl enable socksproxy
systemctl restart socksproxy
systemctl status --no-pager socksproxy
service socksproxy restart

# auto start socksproxy if offline
cat <<'cronsocks' > /etc/socksproxy/socksproxy.sh
#!/bin/bash
if [[ ! "$(systemctl status --no-pager socksproxy)" =~ "running" ]]
then
    service socksproxy stop && service socksproxy start
    date=$(date +"%m-%d-%Y")
    time=$(date +"%T")
    echo "Successfully Auto Started Socks Proxy On The Date Of $date Time $time." >> /root/socksproxy-log.txt
elif [[ ! "$(systemctl status --no-pager apache2)" =~ "running" ]]
then 
    service apache2 stop && service apache2 start
    date=$(date +"%m-%d-%Y")
    time=$(date +"%T")
    echo "Successfully Auto Started Socks Proxy On The Date Of $date Time $time." >> /root/apache2-log.txt
fi
cronsocks

# chmod auto start script
chmod -R 777 /etc/socksproxy/socksproxy.sh

# run script every minute
echo "* * * * * root /bin/bash /etc/socksproxy/socksproxy.sh >/dev/null 2>&1" > /etc/cron.d/socksproxy

# Checking if openvpn folder is accidentally deleted or purged
if [[ ! -e /etc/openvpn ]]; then
 mkdir -p /etc/openvpn
fi

# Removing all existing openvpn server files
rm -rf /etc/openvpn/*

# Creating server.conf, ca.crt, server.crt and server.key
cat <<'myOpenVPNconf' > /etc/openvpn/server_tcp.conf
# OpenVPN TCP
mode server 
tls-server 
port OVPNTCP
management 127.0.0.1 Tcp_Monitor_Port
proto tcp4
dev tun 
cipher AES-128-CBC
auth SHA1
tun-mtu-extra 32 
tun-mtu 1400 
mssfix 1360
tcp-queue-limit 128
txqueuelen 2000
tcp-nodelay
sndbuf 393216
rcvbuf 393216
push "sndbuf 393216"
push "rcvbuf 393216"
ca /etc/openvpn/easy-rsa/ca.crt
cert /etc/openvpn/easy-rsa/TsholoVPN.crt
key /etc/openvpn/easy-rsa/TsholoVPN.key
dh /etc/openvpn/easy-rsa/dh2048.pem
script-security 3
ifconfig-pool-persist ipp.txt
client-cert-not-required 
username-as-common-name 
auth-user-pass-verify "/etc/openvpn/script/auth_vpn.sh" via-file # 
tmp-dir "/etc/openvpn/" # 
server 10.7.0.0 255.255.0.0
push "redirect-gateway def1" 
push "dhcp-option DNS DNS1"
push "dhcp-option DNS DNS2"
keepalive 5 30
persist-key 
persist-tun
verb 3 
status /var/www/html/stat/tcp.txt
myOpenVPNconf

cat <<'myOpenVPNconf2' > /etc/openvpn/server_udp.conf
# OpenVPN UDP
port OVPNUDP
management 127.0.0.1 Udp_Monitor_Port
proto udp
dev tun
ca /etc/openvpn/ca.crt
cert /etc/openvpn/TsholoVPN.crt
key /etc/openvpn/TsholoVPN.key
dh /etc/openvpn/dh2048.pem
username-as-common-name
client-cert-not-required
auth-user-pass-verify "/etc/openvpn/script/auth.sh" via-env
client-connect /etc/openvpn/script/connect.sh
client-disconnect /etc/openvpn/script/disconnect.sh
server 10.201.0.0 255.255.0.0
ifconfig-pool-persist ipp.txt
push "dhcp-option DNS DNS1"
push "dhcp-option DNS DNS2"
keepalive 60 180
push "sndbuf 524288"
push "rcvbuf 524288"
sndbuf 524288
rcvbuf 524288
comp-lzo
persist-key
persist-tun
status /var/www/html/stat/udp.txt
verb 3
script-security 3
myOpenVPNconf2

mkdir /etc/openvpn/easy-rsa
cat << CA > /etc/openvpn/easy-rsa/ca.crt
-----BEGIN CERTIFICATE-----
MIIEbjCCA1agAwIBAgIJAJdSDmspwxUnMA0GCSqGSIb3DQEBCwUAMIGAMQswCQYD
VQQGEwJaQTELMAkGA1UECBMCR1QxFDASBgNVBAcTC1ZlcmVlbmlnaW5nMRIwEAYD
VQQKEwlUc2hvbG9WUE4xFTATBgNVBAMTDFRzaG9sb1ZQTiBDQTEjMCEGCSqGSIb3
DQEJARYUYWRtaW5AdHNob2xvdnBuLmluZm8wHhcNMTUwODI0MTA1NDE3WhcNMjUw
ODIxMTA1NDE3WjCBgDELMAkGA1UEBhMCWkExCzAJBgNVBAgTAkdUMRQwEgYDVQQH
EwtWZXJlZW5pZ2luZzESMBAGA1UEChMJVHNob2xvVlBOMRUwEwYDVQQDEwxUc2hv
bG9WUE4gQ0ExIzAhBgkqhkiG9w0BCQEWFGFkbWluQHRzaG9sb3Zwbi5pbmZvMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4dKR9lbZIVmANbQORRd/lV9+
qfvGE3z7pkNjdvBh8baVpOImn3+6rANbgUPNisnXvGGx+0rLfZdB/MEqDp21wiwf
ytoy2E5ZmJHB8Xp58PR1SNxCHz5q1qM7WlJ0GHYY+0I45OF9sz9sBNnJBXstpi8T
T2jfsjyCpZ6RRuT363yapZ+sayuay3U7T3tQw5Qmca7DUVXGjaEHitQiA4U5rfHd
LNifhxkZY3hERdRIlsgPZHQIZY5rn8O3BMqcHPeTMLnCnZyOc468NPoeXdc/WwAc
SaxhApszlwk/ILwjLpnY2aDSBIn5Kd1zTfZyR6yc6MIcYysMhkLczDub+2rHGQID
AQABo4HoMIHlMB0GA1UdDgQWBBQiIe8AGlmSBwE0ikGPz0UWGurzuDCBtQYDVR0j
BIGtMIGqgBQiIe8AGlmSBwE0ikGPz0UWGurzuKGBhqSBgzCBgDELMAkGA1UEBhMC
WkExCzAJBgNVBAgTAkdUMRQwEgYDVQQHEwtWZXJlZW5pZ2luZzESMBAGA1UEChMJ
VHNob2xvVlBOMRUwEwYDVQQDEwxUc2hvbG9WUE4gQ0ExIzAhBgkqhkiG9w0BCQEW
FGFkbWluQHRzaG9sb3Zwbi5pbmZvggkAl1IOaynDFScwDAYDVR0TBAUwAwEB/zAN
BgkqhkiG9w0BAQsFAAOCAQEAwPP8Omorca2f5uzYrnROmqOEtlwaJb/t8WbeBVd0
HzeXQRyhn5ssx1ZPZCYP3GwsQU/0xPrs/wwIVpAimK66qdTNoii4qYFcJ0u18Nnh
BtgS6r7Lgyl0X+u2aSj6mYjqNySkKnXBgsaD6/Z35P/2PK7b/xN7K2eShadj+5Ry
7AXIVZIqN32ha3Ugs8FAc3EDfaBgeLBUm+hznxNu059PG1T6jTCbLAfDBbbhMrN1
zC8w5j+UXyV3qCP64s2HNP5ZU/aoSnK/QYFUgLxq+RccR/Ph6bctNu81uwta10lc
Q7A78Dl5voYKxdoitmPZIrE41q9cuRmbS22rhcaNYLL+iA==
-----END CERTIFICATE-----
CA

# Server CRT
cat << CRT > /etc/openvpn/easy-rsa/TsholoVPN.crt
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 1 (0x1)
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=ZA, ST=GT, L=Vereeniging, O=TsholoVPN, CN=TsholoVPN CA/emailAddress=admin@tsholovpn.info
        Validity
            Not Before: Aug 24 10:54:37 2015 GMT
            Not After : Aug 21 10:54:37 2025 GMT
        Subject: C=ZA, ST=GT, L=Vereeniging, O=TsholoVPN, CN=TsholoVPN/emailAddress=admin@tsholovpn.info
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:b5:f0:64:f7:de:02:fb:35:00:53:95:34:97:cb:
                    8b:c1:f6:7b:7c:89:5a:7d:09:05:6f:e8:ee:f3:3e:
                    e8:08:89:23:76:97:e9:ea:05:1e:2d:cc:82:0e:97:
                    99:2d:f1:64:ab:d0:25:c6:06:fc:b2:6b:3e:5b:24:
                    d1:26:3e:b5:e9:48:81:f4:b9:6a:4b:b9:28:28:ef:
                    76:78:c0:f7:ff:7e:f7:44:44:18:46:64:fb:31:f2:
                    b8:ba:fe:2e:05:95:cd:26:fe:19:9f:5f:01:a0:7c:
                    3e:76:84:50:a0:0a:a1:07:db:1a:2b:d5:42:cc:2b:
                    2c:14:8c:6b:04:76:2a:d3:46:56:60:93:14:14:46:
                    06:69:8a:93:46:2b:76:69:a0:79:46:ca:e7:25:48:
                    12:55:76:9b:e4:8c:69:4b:50:72:eb:2a:52:d0:5e:
                    ae:84:0a:3c:29:88:81:3c:f8:ae:5b:e4:f3:c4:83:
                    8d:67:bb:94:5a:37:f9:b4:45:09:d2:95:9b:97:3a:
                    bc:b7:3d:48:8a:f4:98:68:5d:0c:aa:01:22:60:05:
                    de:7c:eb:78:85:fd:eb:9b:c0:d8:7f:b0:c4:98:a7:
                    b5:02:c9:d4:17:5a:5f:ac:87:8c:d3:8d:f2:22:c3:
                    b0:93:29:45:66:72:85:2d:6d:45:07:ce:32:0d:61:
                    11:d7
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:FALSE
            Netscape Cert Type: 
                SSL Server
            Netscape Comment: 
                Easy-RSA Generated Server Certificate
            X509v3 Subject Key Identifier: 
                F9:A1:AE:4A:9E:02:9D:9B:0A:C6:82:AF:4C:B8:99:1C:EE:FD:E4:F5
            X509v3 Authority Key Identifier: 
                keyid:22:21:EF:00:1A:59:92:07:01:34:8A:41:8F:CF:45:16:1A:EA:F3:B8
                DirName:/C=ZA/ST=GT/L=Vereeniging/O=TsholoVPN/CN=TsholoVPN CA/emailAddress=admin@tsholovpn.info
                serial:97:52:0E:6B:29:C3:15:27
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication
            X509v3 Key Usage: 
                Digital Signature, Key Encipherment
    Signature Algorithm: sha256WithRSAEncryption
         59:40:cd:31:c1:54:92:39:94:22:d3:cc:f5:3f:c3:6e:63:31:
         a2:d7:ad:1a:fa:7f:dc:b2:66:c1:86:a4:51:95:ae:4a:03:f2:
         80:dc:06:af:9e:bf:5a:6b:5c:8c:9e:99:2d:b1:87:57:2c:ac:
         29:61:fd:90:6d:e3:cd:9a:3c:62:d5:1c:8a:13:87:5b:73:ed:
         57:cf:fc:a1:a7:13:77:30:c2:28:92:88:ba:71:2c:e4:db:e8:
         d7:8b:10:6c:74:a0:93:30:71:02:03:18:f3:d3:5f:ed:72:4b:
         10:52:30:36:4e:24:5e:d3:52:14:0d:27:12:74:a3:1e:fe:c0:
         25:8e:fa:32:66:61:f5:1f:02:db:c3:76:4b:66:01:d3:98:9d:
         6a:50:5b:38:e8:6a:3e:1a:64:cf:56:b6:7f:5b:af:29:8f:e4:
         7c:9c:f6:b2:6f:4e:8e:de:28:13:8f:0b:04:16:d1:9f:fc:4c:
         69:c4:2a:21:69:79:21:52:1a:66:93:9d:ea:a1:e6:0e:09:4c:
         ae:49:eb:8e:6b:e9:48:bd:04:8b:97:c1:f1:5d:7f:02:da:c1:
         fb:f3:cc:17:8d:2d:49:63:55:9f:39:33:a4:66:3c:73:1f:a9:
         56:8d:68:52:2c:9e:1c:c0:47:dc:85:03:48:7f:c2:3f:fb:e2:
         a2:da:bc:71
-----BEGIN CERTIFICATE-----
MIIEzDCCA7SgAwIBAgIBATANBgkqhkiG9w0BAQsFADCBgDELMAkGA1UEBhMCWkEx
CzAJBgNVBAgTAkdUMRQwEgYDVQQHEwtWZXJlZW5pZ2luZzESMBAGA1UEChMJVHNo
b2xvVlBOMRUwEwYDVQQDEwxUc2hvbG9WUE4gQ0ExIzAhBgkqhkiG9w0BCQEWFGFk
bWluQHRzaG9sb3Zwbi5pbmZvMB4XDTE1MDgyNDEwNTQzN1oXDTI1MDgyMTEwNTQz
N1owfTELMAkGA1UEBhMCWkExCzAJBgNVBAgTAkdUMRQwEgYDVQQHEwtWZXJlZW5p
Z2luZzESMBAGA1UEChMJVHNob2xvVlBOMRIwEAYDVQQDEwlUc2hvbG9WUE4xIzAh
BgkqhkiG9w0BCQEWFGFkbWluQHRzaG9sb3Zwbi5pbmZvMIIBIjANBgkqhkiG9w0B
AQEFAAOCAQ8AMIIBCgKCAQEAtfBk994C+zUAU5U0l8uLwfZ7fIlafQkFb+ju8z7o
CIkjdpfp6gUeLcyCDpeZLfFkq9Alxgb8sms+WyTRJj616UiB9LlqS7koKO92eMD3
/373REQYRmT7MfK4uv4uBZXNJv4Zn18BoHw+doRQoAqhB9saK9VCzCssFIxrBHYq
00ZWYJMUFEYGaYqTRit2aaB5RsrnJUgSVXab5IxpS1By6ypS0F6uhAo8KYiBPPiu
W+TzxIONZ7uUWjf5tEUJ0pWblzq8tz1IivSYaF0MqgEiYAXefOt4hf3rm8DYf7DE
mKe1AsnUF1pfrIeM043yIsOwkylFZnKFLW1FB84yDWER1wIDAQABo4IBUTCCAU0w
CQYDVR0TBAIwADARBglghkgBhvhCAQEEBAMCBkAwNAYJYIZIAYb4QgENBCcWJUVh
c3ktUlNBIEdlbmVyYXRlZCBTZXJ2ZXIgQ2VydGlmaWNhdGUwHQYDVR0OBBYEFPmh
rkqeAp2bCsaCr0y4mRzu/eT1MIG1BgNVHSMEga0wgaqAFCIh7wAaWZIHATSKQY/P
RRYa6vO4oYGGpIGDMIGAMQswCQYDVQQGEwJaQTELMAkGA1UECBMCR1QxFDASBgNV
BAcTC1ZlcmVlbmlnaW5nMRIwEAYDVQQKEwlUc2hvbG9WUE4xFTATBgNVBAMTDFRz
aG9sb1ZQTiBDQTEjMCEGCSqGSIb3DQEJARYUYWRtaW5AdHNob2xvdnBuLmluZm+C
CQCXUg5rKcMVJzATBgNVHSUEDDAKBggrBgEFBQcDATALBgNVHQ8EBAMCBaAwDQYJ
KoZIhvcNAQELBQADggEBAFlAzTHBVJI5lCLTzPU/w25jMaLXrRr6f9yyZsGGpFGV
rkoD8oDcBq+ev1prXIyemS2xh1csrClh/ZBt482aPGLVHIoTh1tz7VfP/KGnE3cw
wiiSiLpxLOTb6NeLEGx0oJMwcQIDGPPTX+1ySxBSMDZOJF7TUhQNJxJ0ox7+wCWO
+jJmYfUfAtvDdktmAdOYnWpQWzjoaj4aZM9Wtn9brymP5Hyc9rJvTo7eKBOPCwQW
0Z/8TGnEKiFpeSFSGmaTneqh5g4JTK5J645r6Ui9BIuXwfFdfwLawfvzzBeNLUlj
VZ85M6RmPHMfqVaNaFIsnhzAR9yFA0h/wj/74qLavHE=
-----END CERTIFICATE-----
CRT

# Server KEY
cat << KEY > /etc/openvpn/easy-rsa/TsholoVPN.key
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC18GT33gL7NQBT
lTSXy4vB9nt8iVp9CQVv6O7zPugIiSN2l+nqBR4tzIIOl5kt8WSr0CXGBvyyaz5b
JNEmPrXpSIH0uWpLuSgo73Z4wPf/fvdERBhGZPsx8ri6/i4Flc0m/hmfXwGgfD52
hFCgCqEH2xor1ULMKywUjGsEdirTRlZgkxQURgZpipNGK3ZpoHlGyuclSBJVdpvk
jGlLUHLrKlLQXq6ECjwpiIE8+K5b5PPEg41nu5RaN/m0RQnSlZuXOry3PUiK9Jho
XQyqASJgBd5863iF/eubwNh/sMSYp7UCydQXWl+sh4zTjfIiw7CTKUVmcoUtbUUH
zjINYRHXAgMBAAECggEAZZQX60OqynInAoN1X6KnHt3sx/Uv7ktRG9AjSO/AQLPA
dwAN+zhsRwm9O0Rso3f4yuxlipBwGXVC1URS+VVd3yc6V1YGAM0ZnPFFZdnnHGDY
0OZr3zGWBacMeGpda4Tdi32m9JHoqJ91iFoLYa9NhMNRc1OX/cHE1JwpS85lzpqv
tibPMPa8e6jnvO1wJqc+XpnQmXIpHSQJxK69kRmhuVNrH2Nf9Vqbvuc9AYOObA0m
88213WfN8pmAgeJNCCiSOCSUFgJHFnM0uswOipLZzWLtbi6jSrLagpIZxKJHdPCE
nqKJcSiCbGl1eU/rlTmBGDV/nAUxtd0G7Ux6+d6BoQKBgQDYOEW0Y+J6ksFXnTVo
0axx6YwNqAUuwfIWLafxTBXb8k0AYFVMr9Z6T5hIhXo1jG8041BPTi8GU1JhgA2i
8x6B8jr1UTuXhHLQqZKB4voLEAzwrCMuftcVE1XS3UGjl6i3sHfmvjBhrfU/NtNZ
A3mWELxlISRMyLzFZ8Ds1ddHKQKBgQDXaYiRfcbteokChzdO9CgaaN9PylfDMAUn
E0/cyfaplwg/w/Zpj9fJyejcpvp9y2tCB0Urd6rlWpBwpn2gMtZx8t0v1lpe7IxP
A7qJ8ozDNqPf21xLsp6faz0UukqprY59YF/yjkgJr5/ZXivAnbxTR9jN9Re4R+3L
vohSbH2w/wKBgGKi4SGWw3WZRzw5ymij5iAdI7gDI0IeVdrKPyfzxrEMyxXV3HPc
b2Jitxy2T3boNr8Qx8015HvlPNqfuRjSAePT5hONWDsZv+rywJQiQGEVlGGilXYb
hPDnXiqQpuYDRINvrHMF5jpZSlzpHOcpj6jmv5r+0Hl6xarkVv1z2/5pAoGBANEw
r2t7FeAxizRlU5TdDsT260Z1Xd0zmQ1ld70WdPAkt+IU0AuboRdZeUYu8juPfE3W
+ZlI0TGCTZrYVE9qj06BZ8O5CnH8jhV9rX2hiolZWrNeN7dbcyel4N9sOm2lGicv
nH3VJqghYb6Z8StRAz5tG2KHjc1sLMYb9g71ROrJAoGAGgRaWbx8US8z4hPp/BB8
6hXvt2QKNNgH/P/oDKcJpqB/Fy2MUO6FnIEQMVSAWj+cZajj8hmKWGFhyuX7NVtt
EEURauGtar75MsULYhqADzX4ylJYgN+oqPbbJlALEi0+HgoLpyGLNYn38oP/ko8v
w3VMBwVhspalpBuX2QWNUWE=
-----END PRIVATE KEY-----
KEY

# Server DH2048
 cat << DH > /etc/openvpn/easy-rsa/dh2048.pem
-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA1emiXAI6I7h2niDL+zRZ3CkRs0LTt1jCTL4mPx7O5aT5GjsPzXVb
GRH6CMlQBE28Uk/Kg1lojfpV2fOL1gmyk7kaRxKO1hmr6fCS07WlfdUUbF2CKK3F
jRkj6U3NDC0sMgOJI2+io8j2V+xCKNehaz58caozlyo8efwI6cT1jZY2KlEwFbnl
4D0K7TFJs3K5rhBZ9KOfh10nYVsw0mbWMTwUAlRB/97K9VTnnrDx2WQONIkB/zgt
5RKpPxmN1d1cJ/7II559PPGiUf/UL4SSXH8L5c05xDLyNoeH6qPbA78umRA3CZEH
An1jD+OUdrLRqjxcEoel9tm3b9h/YWbu2wIBAg==
-----END DH PARAMETERS-----
DH

# Creating a New update message in server.conf
cat <<'NUovpn' > /etc/openvpn/server.conf
# New Update are now released, OpenVPN Server
# are now running both TCP and UDP Protocol. (Both are only running on IPv4)
# But our native server.conf are now removed and divided
# Into two different configs base on their Protocols:
#  * OpenVPN TCP (located at /etc/openvpn/server_tcp.conf
#  * OpenVPN UDP (located at /etc/openvpn/server_udp.conf
# 
# Also other logging files like
# status logs and server logs
# are moved into new different file names:
#  * OpenVPN TCP Server logs (/etc/openvpn/tcp.log)
#  * OpenVPN UDP Server logs (/etc/openvpn/udp.log)
#  * OpenVPN TCP Status logs (/etc/openvpn/tcp_stats.log)
#  * OpenVPN UDP Status logs (/etc/openvpn/udp_stats.log)
#
# Server ports are configured base on env vars
# executed/raised from this script (OpenVPN_TCP_Port/OpenVPN_UDP_Port)
#
NUovpn

# setting openvpn server port and dns
sed -i "s|OVPNTCP|$OpenVPN_TCP_Port|g" /etc/openvpn/server_tcp.conf
sed -i "s|OVPNUDP|$OpenVPN_UDP_Port|g" /etc/openvpn/server_udp.conf
sed -i "s|DNS1|$Dns_1|g" /etc/openvpn/server_udp.conf
sed -i "s|DNS2|$Dns_2|g" /etc/openvpn/server_udp.conf
sed -i "s|DNS1|$Dns_1|g" /etc/openvpn/server_tcp.conf
sed -i "s|DNS2|$Dns_2|g" /etc/openvpn/server_tcp.conf
sed -i "s|Tcp_Monitor_Port|$Tcp_Monitor_Port|g" /etc/openvpn/server_tcp.conf
sed -i "s|Udp_Monitor_Port|$Udp_Monitor_Port|g" /etc/openvpn/server_udp.conf

# Some workaround for OpenVZ machines for "Startup error" openvpn service
if [[ "$(hostnamectl | grep -i Virtualization | awk '{print $2}' | head -n1)" == 'openvz' ]]; then
 sed -i 's|LimitNPROC=10|#LimitNPROC=10|g' /lib/systemd/system/openvpn*
 systemctl daemon-reload
fi

# Allow IPv4 Forwarding
#sed -i '/net.ipv4.ip_forward.*/d' /etc/sysctl.conf
sed -i '/net.ipv4.ip_forward.*/d' /etc/sysctl.d/*.conf
echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/20-openvpn.conf
sysctl --system &> /dev/null

# Iptables Rule for OpenVPN server
cat <<'EOFipt' > /etc/openvpn/openvpn.bash
#!/bin/bash
PUBLIC_INET="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
IPCIDR='10.7.0.0/16'
IPCIDR2='10.201.0.0/16'
iptables -I FORWARD -s $IPCIDR -j ACCEPT
iptables -I FORWARD -s $IPCIDR2 -j ACCEPT
iptables -t nat -A POSTROUTING -o $PUBLIC_INET -j MASQUERADE
iptables -t nat -A POSTROUTING -s $IPCIDR -o $PUBLIC_INET -j MASQUERADE
iptables -t nat -A POSTROUTING -s $IPCIDR2 -o $PUBLIC_INET -j MASQUERADE
EOFipt
chmod +x /etc/openvpn/openvpn.bash
bash /etc/openvpn/openvpn.bash

# Enabling IPv4 Forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
 
# Create OpenVPN Paths
mkdir /etc/openvpn/script
mkdir /var/www/html/stat


# Auth Script
cat <<'DEE04' >/etc/openvpn/script/auth_vpn.sh
#!/bin/bash
username=`head -n1 $1 | tail -1`   
password=`head -n2 $1 | tail -1`
tm="$(date +%s)"
dt="$(date +'%Y-%m-%d %H:%M:%S')"
HOST='185.61.137.174'
USER='vpnquest1_user'
PASS='s+(WT#r4CaB&'
DB='vpnquest1_dbase'
# PREMIUM
PRE="user.username='$username' AND user.auth_vpn=md5('$password') AND user.confirmcode='y' AND user.status='live' AND user.is_freeze=1 AND user.is_active=1 AND user.is_ban=1 AND user.is_suspend=1 AND user.is_duration > 0"
# VIP
VIP="user.username='$username' AND user.auth_vpn=md5('$password') AND user.confirmcode='y' AND user.status='live' AND user.is_freeze=1 AND user.is_active=1 AND user.is_ban=1 AND user.is_suspend=1 AND user.vip_duration > 0"
# PRIVATE
PRIV="user.username='$username' AND user.auth_vpn=md5('$password') AND user.confirmcode='y' AND user.status='live' AND user.is_freeze=1 AND user.is_active=1 AND user.is_ban=1 AND user.is_suspend=1 AND user.private_duration > 0"
Query="SELECT user.username FROM user WHERE $PRE OR $VIP OR $PRIV"
auth_vpn=`mysql -u $USER -p$PASS -D $DB -h $HOST --skip-column-name -e "$Query"`
  
if [ "$auth_vpn" == "$username" ]; then
    echo "user : $username"
	echo "authentication ok."
	exit 0
else
    echo "authentication failed."
	exit 1
fi
DEE04
 
# Set Permission To Script
chmod -R 777 /etc/openvpn/script
 
# Starting OpenVPN server
systemctl start openvpn@server_tcp
systemctl restart openvpn@server_tcp
systemctl status --no-pager openvpn@server_tcp
systemctl enable openvpn@server_tcp
systemctl start openvpn@server_udp
systemctl restart openvpn@server_udp
systemctl status --no-pager openvpn@server_udp
systemctl enable openvpn@server_udp

service openvpn restart
 
# Set Permission To Stat
chmod -R 777 /var/www/html/stat

# Removing Duplicate Squid config
rm -rf /etc/squid/squid.con*
 
# Creating Squid server config using cat eof tricks
cat <<'mySquid' > /etc/squid/squid.conf
# My Squid Proxy Server Config
acl server dst IP-ADDRESS/32 localhost
acl checker src 188.93.95.137
acl ports_ port 14 22 53 21 8080 8081 8000 3128 1193 1194 440 441 442 443 80
http_port Squid_Port1
http_port Squid_Port2
http_port Squid_Port3
access_log none
cache_log /dev/null
logfile_rotate 0
http_access allow server
http_access allow checker
http_access deny all
http_access allow all
forwarded_for off
via off
request_header_access Host allow all
request_header_access Content-Length allow all
request_header_access Content-Type allow all
request_header_access All deny all
hierarchy_stoplist cgi-bin ?
coredump_dir /var/spool/squid
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320
visible_hostname localhost
mySquid

# Setting machine's IP Address inside of our Squid config(security that only allows this machine to use this proxy server)
sed -i "s|IP-ADDRESS|$IPADDR|g" /etc/squid/squid.conf
 
# Setting squid ports
sed -i "s|Squid_Port1|$Squid_Port1|g" /etc/squid/squid.conf
sed -i "s|Squid_Port2|$Squid_Port2|g" /etc/squid/squid.conf
sed -i "s|Squid_Port3|$Squid_Port3|g" /etc/squid/squid.conf

# Starting Proxy server
echo -e "Restarting Squid Proxy server..."
systemctl restart squid
service squid restart

# NGINX CONFIGURE
rm /home/vps/public_html -rf
rm /etc/nginx/sites-* -rf
rm /etc/nginx/nginx.conf -rf
sleep 1
mkdir -p /home/vps/public_html

# Creating nginx config for our webserver
cat <<'myNginxC' > /etc/nginx/nginx.conf

user www-data;

worker_processes 1;
pid /var/run/nginx.pid;

events {
	multi_accept on;
  worker_connections 1024;
}

http {
	gzip on;
	gzip_vary on;
	gzip_comp_level 5;
	gzip_types    text/plain application/x-javascript text/xml text/css;

	autoindex on;
  sendfile on;
  tcp_nopush on;
  tcp_nodelay on;
  keepalive_timeout 65;
  types_hash_max_size 2048;
  server_tokens off;
  include /etc/nginx/mime.types;
  default_type application/octet-stream;
  access_log /var/log/nginx/access.log;
  error_log /var/log/nginx/error.log;
  client_max_body_size 32M;
	client_header_buffer_size 8m;
	large_client_header_buffers 8 8m;

	fastcgi_buffer_size 8m;
	fastcgi_buffers 8 8m;

	fastcgi_read_timeout 600;


  include /etc/nginx/conf.d/*.conf;
}
myNginxC

# Creating vps config for our OCS Panel
cat <<'myvpsC' > /etc/nginx/conf.d/vps.conf
server {
  listen       Nginx_Port;
  server_name  127.0.0.1 localhost;
  access_log /var/log/nginx/vps-access.log;
  error_log /var/log/nginx/vps-error.log error;
  root   /home/vps/public_html;

  location / {
    index  index.html index.htm index.php;
    try_files $uri $uri/ /index.php?$args;
  }

  location ~ \.php$ {
    include /etc/nginx/fastcgi_params;
    fastcgi_pass  127.0.0.1:Php_Socket;
    fastcgi_index index.php;
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
  }
}
myvpsC

# Creating monitoring config for our OpenVPN Monitoring Panel
cat <<'myMonitoringC' > /etc/nginx/conf.d/monitoring.conf

server {
    listen Openvpn_Monitoring;
    location / {
        uwsgi_pass unix:///run/uwsgi/app/openvpn-monitor/socket;
        include uwsgi_params;
    }
}
myMonitoringC

## Setting nginx vpn config
cat <<'myvpnC' > /etc/nginx/conf.d/vpn.conf
server {
  listen       Nginx_vpn;
  server_name 127.0.0.1 localhost;
  root /home/vps/public_html;
}
myvpnC
sed -i '$ ilocation /' /etc/nginx/conf.d/vpn.conf
sed -i '$ i{' /etc/nginx/conf.d/vpn.conf
sed -i '$ iif ($http_upgrade != "websocket") {' /etc/nginx/conf.d/vpn.conf
sed -i '$ i	return 404;' /etc/nginx/conf.d/vpn.conf
sed -i '$ i}' /etc/nginx/conf.d/vpn.conf
sed -i '$ iproxy_redirect off;' /etc/nginx/conf.d/vpn.conf
sed -i '$ iproxy_pass http://localhost:WsPort;' /etc/nginx/conf.d/vpn.conf
sed -i '$ iproxy_http_version 1.1;' /etc/nginx/conf.d/vpn.conf
sed -i '$ iproxy_set_header X-Real-IP \$remote_addr;' /etc/nginx/conf.d/vpn.conf
sed -i '$ iproxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;' /etc/nginx/conf.d/vpn.conf
sed -i '$ iproxy_set_header Upgrade \$http_upgrade;' /etc/nginx/conf.d/vpn.conf
sed -i '$ iproxy_set_header Connection "upgrade";' /etc/nginx/conf.d/vpn.conf
sed -i '$ iproxy_set_header Host \$http_host;' /etc/nginx/conf.d/vpn.conf
sed -i '$ i}' /etc/nginx/conf.d/vpn.conf

sed -i '$ ilocation /' /etc/nginx/conf.d/vpn.conf
sed -i '$ i{' /etc/nginx/conf.d/vpn.conf
sed -i '$ iif ($http_upgrade != "h2") {' /etc/nginx/conf.d/vpn.conf
sed -i '$ i	return 404;' /etc/nginx/conf.d/vpn.conf
sed -i '$ i}' /etc/nginx/conf.d/vpn.conf
sed -i '$ iproxy_redirect off;' /etc/nginx/conf.d/vpn.conf
sed -i '$ iproxy_pass http://localhost:WsPort;' /etc/nginx/conf.d/vpn.conf
sed -i '$ iproxy_http_version 1.1;' /etc/nginx/conf.d/vpn.conf
sed -i '$ iproxy_set_header X-Real-IP \$remote_addr;' /etc/nginx/conf.d/vpn.conf
sed -i '$ iproxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;' /etc/nginx/conf.d/vpn.conf
sed -i '$ iproxy_set_header Upgrade \$http_upgrade;' /etc/nginx/conf.d/vpn.conf
sed -i '$ iproxy_set_header Connection "upgrade";' /etc/nginx/conf.d/vpn.conf
sed -i '$ iproxy_set_header Host \$http_host;' /etc/nginx/conf.d/vpn.conf
sed -i '$ i}' /etc/nginx/conf.d/vpn.conf

sed -i '$ ilocation = /dkws' /etc/nginx/conf.d/vpn.conf
sed -i '$ i{' /etc/nginx/conf.d/vpn.conf
sed -i '$ iproxy_redirect off;' /etc/nginx/conf.d/vpn.conf
sed -i '$ iproxy_pass http://unix:/run/xray/vless_ws.sock;' /etc/nginx/conf.d/vpn.conf
sed -i '$ iproxy_http_version 1.1;' /etc/nginx/conf.d/vpn.conf
sed -i '$ iproxy_set_header X-Real-IP \$remote_addr;' /etc/nginx/conf.d/vpn.conf
sed -i '$ iproxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;' /etc/nginx/conf.d/vpn.conf
sed -i '$ iproxy_set_header Upgrade \$http_upgrade;' /etc/nginx/conf.d/vpn.conf
sed -i '$ iproxy_set_header Connection "upgrade";' /etc/nginx/conf.d/vpn.conf
sed -i '$ iproxy_set_header Host \$http_host;' /etc/nginx/conf.d/vpn.conf
sed -i '$ i}' /etc/nginx/conf.d/vpn.conf

sed -i '$ ilocation = /dkvws' /etc/nginx/conf.d/vpn.conf
sed -i '$ i{' /etc/nginx/conf.d/vpn.conf
sed -i '$ iproxy_redirect off;' /etc/nginx/conf.d/vpn.conf
sed -i '$ iproxy_pass http://unix:/run/xray/vmess_ws.sock;' /etc/nginx/conf.d/vpn.conf
sed -i '$ iproxy_http_version 1.1;' /etc/nginx/conf.d/vpn.conf
sed -i '$ iproxy_set_header X-Real-IP \$remote_addr;' /etc/nginx/conf.d/vpn.conf
sed -i '$ iproxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;' /etc/nginx/conf.d/vpn.conf
sed -i '$ iproxy_set_header Upgrade \$http_upgrade;' /etc/nginx/conf.d/vpn.conf
sed -i '$ iproxy_set_header Connection "upgrade";' /etc/nginx/conf.d/vpn.conf
sed -i '$ iproxy_set_header Host \$http_host;' /etc/nginx/conf.d/vpn.conf
sed -i '$ i}' /etc/nginx/conf.d/vpn.conf

sed -i '$ ilocation = /dktrojanws' /etc/nginx/conf.d/vpn.conf
sed -i '$ i{' /etc/nginx/conf.d/vpn.conf
sed -i '$ iproxy_redirect off;' /etc/nginx/conf.d/vpn.conf
sed -i '$ iproxy_pass http://unix:/run/xray/trojan_ws.sock;' /etc/nginx/conf.d/vpn.conf
sed -i '$ iproxy_http_version 1.1;' /etc/nginx/conf.d/vpn.conf
sed -i '$ iproxy_set_header X-Real-IP \$remote_addr;' /etc/nginx/conf.d/vpn.conf
sed -i '$ iproxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;' /etc/nginx/conf.d/vpn.conf
sed -i '$ iproxy_set_header Upgrade \$http_upgrade;' /etc/nginx/conf.d/vpn.conf
sed -i '$ iproxy_set_header Connection "upgrade";' /etc/nginx/conf.d/vpn.conf
sed -i '$ iproxy_set_header Host \$http_host;' /etc/nginx/conf.d/vpn.conf
sed -i '$ i}' /etc/nginx/conf.d/vpn.conf

sed -i '$ ilocation = /dkssws' /etc/nginx/conf.d/vpn.conf
sed -i '$ i{' /etc/nginx/conf.d/vpn.conf
sed -i '$ iproxy_redirect off;' /etc/nginx/conf.d/vpn.conf
sed -i '$ iproxy_pass http://127.0.0.1:V2ray_Port2;' /etc/nginx/conf.d/vpn.conf
sed -i '$ iproxy_http_version 1.1;' /etc/nginx/conf.d/vpn.conf
sed -i '$ iproxy_set_header X-Real-IP \$remote_addr;' /etc/nginx/conf.d/vpn.conf
sed -i '$ iproxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;' /etc/nginx/conf.d/vpn.conf
sed -i '$ iproxy_set_header Upgrade \$http_upgrade;' /etc/nginx/conf.d/vpn.conf
sed -i '$ iproxy_set_header Connection "upgrade";' /etc/nginx/conf.d/vpn.conf
sed -i '$ iproxy_set_header Host \$http_host;' /etc/nginx/conf.d/vpn.conf
sed -i '$ i}' /etc/nginx/conf.d/vpn.conf

sed -i '$ ilocation ^~ /vless-grpc' /etc/nginx/conf.d/vpn.conf
sed -i '$ i{' /etc/nginx/conf.d/vpn.conf
sed -i '$ iproxy_redirect off;' /etc/nginx/conf.d/vpn.conf
sed -i '$ igrpc_set_header X-Real-IP \$remote_addr;' /etc/nginx/conf.d/vpn.conf
sed -i '$ igrpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;' /etc/nginx/conf.d/vpn.conf
sed -i '$ igrpc_set_header Host \$http_host;' /etc/nginx/conf.d/vpn.conf
sed -i '$ igrpc_pass grpc://unix:/run/xray/vless_grpc.sock;' /etc/nginx/conf.d/vpn.conf
sed -i '$ i}' /etc/nginx/conf.d/vpn.conf

sed -i '$ ilocation ^~ /vmess-grpc' /etc/nginx/conf.d/vpn.conf
sed -i '$ i{' /etc/nginx/conf.d/vpn.conf
sed -i '$ iproxy_redirect off;' /etc/nginx/conf.d/vpn.conf
sed -i '$ igrpc_set_header X-Real-IP \$remote_addr;' /etc/nginx/conf.d/vpn.conf
sed -i '$ igrpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;' /etc/nginx/conf.d/vpn.conf
sed -i '$ igrpc_set_header Host \$http_host;' /etc/nginx/conf.d/vpn.conf
sed -i '$ igrpc_pass grpc://unix:/run/xray/vmess_grpc.sock;' /etc/nginx/conf.d/vpn.conf
sed -i '$ i}' /etc/nginx/conf.d/vpn.conf

sed -i '$ ilocation ^~ /trojan-grpc' /etc/nginx/conf.d/vpn.conf
sed -i '$ i{' /etc/nginx/conf.d/vpn.conf
sed -i '$ iproxy_redirect off;' /etc/nginx/conf.d/vpn.conf
sed -i '$ igrpc_set_header X-Real-IP \$remote_addr;' /etc/nginx/conf.d/vpn.conf
sed -i '$ igrpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;' /etc/nginx/conf.d/vpn.conf
sed -i '$ igrpc_set_header Host \$http_host;' /etc/nginx/conf.d/vpn.conf
sed -i '$ igrpc_pass grpc://unix:/run/xray/trojan_grpc.sock;' /etc/nginx/conf.d/vpn.conf
sed -i '$ i}' /etc/nginx/conf.d/vpn.conf

sed -i '$ ilocation ^~ /ss-grpc' /etc/nginx/conf.d/vpn.conf
sed -i '$ i{' /etc/nginx/conf.d/vpn.conf
sed -i '$ iproxy_redirect off;' /etc/nginx/conf.d/vpn.conf
sed -i '$ igrpc_set_header X-Real-IP \$remote_addr;' /etc/nginx/conf.d/vpn.conf
sed -i '$ igrpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;' /etc/nginx/conf.d/vpn.conf
sed -i '$ igrpc_set_header Host \$http_host;' /etc/nginx/conf.d/vpn.conf
sed -i '$ igrpc_pass grpc://127.0.0.1:V2ray_Port3;' /etc/nginx/conf.d/vpn.conf
sed -i '$ i}' /etc/nginx/conf.d/vpn.conf

# Setting up our WebServer Ports and IP Addresses
cd
sleep 1

phpl=`php --ini | grep -om 1 /etc/php/*`
phpv=`echo $phpl | cut -d/ -f4`

sed -i 's/;cgi.fix_pathinfo=1/cgi.fix_pathinfo=0/g;/display_errors =/{s/Off/On/g};/;session.save_path =/{s/;//g}' $phpl/fpm/php.ini
sed -i "s|/run/php/php$phpv-fpm.sock|127.0.0.1:$Php_Socket|g" $phpl/fpm/pool.d/www.conf
sed -i "s|Php_Socket|$Php_Socket|g" /etc/nginx/conf.d/vps.conf
sed -i "s|Nginx_Port|$Nginx_Port|g" /etc/nginx/conf.d/vps.conf
sed -i "s|Nginx_vpn|$Nginx_vpn|g" /etc/nginx/conf.d/vpn.conf
sed -i "s|WsPort|$WsPort|g" /etc/nginx/conf.d/vpn.conf
sed -i "s|V2ray_Port2|$V2ray_Port2|g" /etc/nginx/conf.d/vpn.conf
sed -i "s|V2ray_Port3|$V2ray_Port3|g" /etc/nginx/conf.d/vpn.conf
sed -i "s|Openvpn_Monitoring|$Openvpn_Monitoring|g" /etc/nginx/conf.d/monitoring.conf

# Restarting nginx & php
systemctl start nginx
systemctl restart nginx
service php7.3-fpm restart
service nginx restart

# Setting Up OpenVPN monitoring
apt-get install -y gcc libgeoip-dev python-virtualenv python-dev geoip-database-extra uwsgi uwsgi-plugin-python
wget -O /srv/openvpn-monitor.zip "https://www.dropbox.com/s/f3t6lsk6uao5xkv/openvpn-monitor.zip"
cd /srv
unzip -qq openvpn-monitor.zip
rm -f openvpn-monitor.zip
cd openvpn-monitor
virtualenv .
. bin/activate
pip install -r requirements.txt

# Updating ports for openvpn monitoring
sed -i "s|Tcp_Monitor_Port|$Tcp_Monitor_Port|g" /srv/openvpn-monitor/openvpn-monitor.conf
sed -i "s|Udp_Monitor_Port|$Udp_Monitor_Port|g" /srv/openvpn-monitor/openvpn-monitor.conf

# Creating monitoring .ini for our OpenVPN Monitoring Panel
cat <<'myMonitorINI' > /etc/uwsgi/apps-available/openvpn-monitor.ini
[uwsgi]
base = /srv
project = openvpn-monitor
logto = /var/log/uwsgi/app/%(project).log
plugins = python
chdir = %(base)/%(project)
virtualenv = %(chdir)
module = openvpn-monitor:application
manage-script-name = true
mount=/openvpn-monitor=openvpn-monitor.py
myMonitorINI

ln -s /etc/uwsgi/apps-available/openvpn-monitor.ini /etc/uwsgi/apps-enabled/

# Go To Root
cd

# GeoIP For OpenVPN Monitor
mkdir -p /var/lib/GeoIP
wget -O /var/lib/GeoIP/GeoLite2-City.mmdb.gz "https://www.dropbox.com/s/5t2a4jd8anocnp6/geolite2-city.mmdb.gz"
gzip -d /var/lib/GeoIP/GeoLite2-City.mmdb.gz

# Now creating all of our OpenVPN Configs 

# Default TCP
cat <<Config3> /home/vps/public_html/Direct.TCP.ovpn
# Tsholo VPN Premium Script Config
# Thanks for using this script config, Enjoy Highspeed OpenVPN Service

client
dev tun
proto tcp
setenv FRIENDLY_NAME "Tsholo VPN TCP"
remote $IPADDR $OpenVPN_TCP_Port
http-proxy $IPADDR $Squid_Port1
resolv-retry infinite
remote-random
nobind
tun-mtu 1500
tun-mtu-extra 32
mssfix 1450
persist-key
persist-tun
ping 15
ping-restart 0
ping-timer-rem
reneg-sec 0
remote-cert-tls server
auth-user-pass
#comp-lzo
verb 3
pull
fast-io
cipher AES-256-CBC
auth SHA512
setenv CLIENT_CERT 0

<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
Config3

# Default UDP
cat <<Config4> /home/vps/public_html/Direct.UDP.ovpn
# Tsholo VPN Premium Script Config
# Thanks for using this script config, Enjoy Highspeed OpenVPN Service

client
dev tun
proto udp
setenv FRIENDLY_NAME "Tsholo VPN UDP"
remote $IPADDR $OpenVPN_UDP_Port
resolv-retry infinite
float
fast-io
nobind
persist-key
persist-remote-ip
persist-tun
auth-user-pass
auth-nocache
comp-lzo
redirect-gateway def1
reneg-sec 0
verb 1
key-direction 1

<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
Config4

# Creating OVPN download site index.html
cat <<'mySiteOvpn' > /home/vps/public_html/index.html
<!DOCTYPE html>
<html lang="en">

<!-- Openvpn Config File Download site by TsholoVPN -->

<head><meta charset="utf-8" /><title>VPN Config File Download</title><meta name="description" content="Tsholo Server -Joash" /><meta content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no" name="viewport" /><meta name="theme-color" content="#000000" /><link rel="shortcut icon" type="image/x-icon" href="https://raw.githubusercontent.com/dopekid30/-generate-sa-idnumbers/master/dk.png"><link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.8.2/css/all.css"><link href="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.3.1/css/bootstrap.min.css" rel="stylesheet"><link href="https://cdnjs.cloudflare.com/ajax/libs/mdbootstrap/4.8.3/css/mdb.min.css" rel="stylesheet"></head><body><div class="container justify-content-center" style="margin-top:9em;margin-bottom:5em;"><div class="col-md"><div class="view"><img src="https://openvpn.net/wp-content/uploads/openvpn.jpg" class="card-img-top"><div class="mask rgba-white-slight"></div></div><div class="card"><div class="card-body"><h5 class="card-title">Tsholo Config List</h5><br /><ul 

class="list-group"><li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p> Openvpn Default TCP <span class="badge light-blue darken-4">Android/iOS/PC/Modem</span><br /><small> This default and cannot be use for bypassing internet.</small></p><a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESS:NGINXPORT/Direct.TCP.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li><li 

class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p> Openvpn Default UDP <span class="badge light-blue darken-4">Android/iOS/PC/Modem</span><br /><small> This default and cannot be use for bypassing internet.</small></p><a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESS:NGINXPORT/Direct.UDP.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li><li 

</ul></div></div></div></div></body></html>
mySiteOvpn
 
# Setting template's correct name,IP address and nginx Port
sed -i "s|NGINXPORT|$Nginx_Port|g" /home/vps/public_html/index.html
sed -i "s|IP-ADDRESS|$IPADDR|g" /home/vps/public_html/index.html

# Restarting nginx service
systemctl restart nginx
service nginx restart
 
# Creating all .ovpn config archives
cd /home/vps/public_html
zip -qq -r config.zip *.ovpn
cd

chown -R www-data:www-data /home/vps/public_html

# Setting SSH To Work With Panel
mkdir /etc/sshlogin
cat <<'SSHPanel' > "/etc/sshlogin/connection.php"
<?php
error_reporting(E_ERROR | E_PARSE);
ini_set('display_errors', '1');
//include('config.php');
$DB_host = '185.61.137.174';
$DB_user = 'vpnquest1_user';
$DB_pass = 's+(WT#r4CaB&';
$DB_name = 'vpnquest1_dbase';
$mysqli = new MySQLi($DB_host,$DB_user,$DB_pass,$DB_name);
if ($mysqli->connect_error) {
    die('Error : ('. $mysqli->connect_errno .') '. $mysqli->connect_error);
}
function encrypt_key($paswd)
	{
	  $mykey=getEncryptKey();
	  $encryptedPassword=encryptPaswd($paswd,$mykey);
	  return $encryptedPassword;
	}
	 
	// function to get the decrypted user password
	function decrypt_key($paswd)
	{
	  $mykey=getEncryptKey();
	  $decryptedPassword=decryptPaswd($paswd,$mykey);
	  return $decryptedPassword;
	}
	 
	function getEncryptKey()
	{
		$secret_key = md5('tsholovpn');
		$secret_iv = md5('vpntsholo');
		$keys = $secret_key . $secret_iv;
		return encryptor('encrypt', $keys);
	}
	function encryptPaswd($string, $key)
	{
	  $result = '';
	  for($i=0; $i<strlen ($string); $i++)
	  {
		$char = substr($string, $i, 1);
		$keychar = substr($key, ($i % strlen($key))-1, 1);
		$char = chr(ord($char)+ord($keychar));
		$result.=$char;
	  }
		return base64_encode($result);
	}
	 
	function decryptPaswd($string, $key)
	{
	  $result = '';
	  $string = base64_decode($string);
	  for($i=0; $i<strlen($string); $i++)
	  {
		$char = substr($string, $i, 1);
		$keychar = substr($key, ($i % strlen($key))-1, 1);
		$char = chr(ord($char)-ord($keychar));
		$result.=$char;
	  }
	 
		return $result;
	}
	
	function encryptor($action, $string) {
		$output = false;
		$encrypt_method = "AES-256-CBC";
		//pls set your unique hashing key
		$secret_key = md5('tsholovpn.info');
		$secret_iv = md5('info.tsholovpn');
		// hash
		$key = hash('sha256', $secret_key);
		
		// iv - encrypt method AES-256-CBC expects 16 bytes - else you will get a warning
		$iv = substr(hash('sha256', $secret_iv), 0, 16);
		//do the encyption given text/string/number
		if( $action == 'encrypt' ) {
			$output = openssl_encrypt($string, $encrypt_method, $key, 0, $iv);
			$output = base64_encode($output);
		}
		else if( $action == 'decrypt' ){
			//decrypt the given text/string/number
			$output = openssl_decrypt(base64_decode($string), $encrypt_method, $key, 0, $iv);
		}
		return $output;
	}
$data = '';
$premium = "is_active=1 AND is_duration > 0";
$query = $mysqli->query("SELECT * FROM user
WHERE ".$premium." ORDER by id_user ASC");
if($query->num_rows > 0)
{
	while($row = $query->fetch_assoc())
	{
		$data .= '';
		$username = $row['username'];
		$password = decrypt_key($row['password']);
		$password = encryptor('decrypt',$password);		
		$data .= '/usr/sbin/useradd -p $(openssl passwd -1 '.$password.') -M '.$username.';'.PHP_EOL;
	}
}
$location = '/etc/sshlogin/active.sh';
$fp = fopen($location, 'w');
fwrite($fp, $data) or die("Unable to open file!");
fclose($fp);
#In-Active and Invalid Accounts
$data2 = '';
$premium_deactived = "is_duration <= 0";
$is_activate = "is_active=0";
$freeze = "is_freeze=0";
$suspend = "is_suspend=0";
$query2 = $mysqli->query("SELECT * FROM user 
WHERE ".$suspend." OR ".$freeze." OR ".$premium_deactived ." OR ".$is_activate."
");
if($query2->num_rows > 0)
{
	while($row2 = $query2->fetch_assoc())
	{
		$data2 .= '';
		$toadd = $row2['username'];	
		$data2 .= '/usr/sbin/userdel '.$toadd.''.PHP_EOL;
	}
}
$location2 = '/etc/sshlogin/inactive.sh';
$fp = fopen($location2, 'w');
fwrite($fp, $data2) or die("Unable to open file!");
fclose($fp);
$mysqli->close();
?>
SSHPanel

sed -i "s|DatabaseHost|$DatabaseHost|g;s|DatabaseName|$DatabaseName|g;s|DatabaseUser|$DatabaseUser|g;s|DatabasePass|$DatabasePass|g" "/etc/sshlogin/connection.php"

chmod -R 777 /etc/sshlogin/connection.php

# SSH to check online users on panel 
cat <<'Sshonline' > /etc/sshlogin/sshusers.sh
#!/bin/bash
#SSH USERS 
#BY Tsholo

date=$(date +"%m-%d-%Y")
time=$(date +"%T")

if [ -e "/var/log/auth.log" ]; then
        LOG="/var/log/auth.log";
fi
if [ -e "/var/log/secure" ]; then
        LOG="/var/log/secure";
fi

# RESET
>"/var/www/html/stat/ssh.txt";

# SOME INFO
echo "DROPBEAR & OPENSSH ONLINE CLIENT LIST" >> "/var/www/html/stat/ssh.txt";
echo "UPDATED ON $date $time" >> "/var/www/html/stat/ssh.txt";

# DROPBEAR
data=( `ps aux | grep -i dropbear | awk '{print $2}'`);
cat $LOG | grep -i dropbear | grep -i "Password auth succeeded" > /tmp/login-db.txt;
for PID in "${data[@]}"
do
        cat /tmp/login-db.txt | grep "dropbear\[$PID\]" > /tmp/login-db-pid.txt;
        NUM=`cat /tmp/login-db-pid.txt | wc -l`;
        USER=`cat /tmp/login-db-pid.txt | awk '{print $10}' | sed 's/'\''//g'`;
        IP=`cat /tmp/login-db-pid.txt | awk '{print $12}'`;
        SINCE=`cat /tmp/login-db-pid.txt | awk '{print $1, $2, $3}'`;
        if [ $NUM -eq 1 ]; then
                echo "$USER,$IP,$PID,2022,$SINCE" >> "/var/www/html/stat/ssh.txt";
        fi
done

 # OPENSSH
cat $LOG | grep -i sshd | grep -i "Accepted password for" > /tmp/login-db.txt
data=( `ps aux | grep "\[priv\]" | sort -k 72 | awk '{print $2}'`);
for PID in "${data[@]}"
do
        cat /tmp/login-db.txt | grep "sshd\[$PID\]" > /tmp/login-db-pid.txt;
        NUM=`cat /tmp/login-db-pid.txt | wc -l`;
        USER=`cat /tmp/login-db-pid.txt | awk '{print $9}'`;
        IP=`cat /tmp/login-db-pid.txt | awk '{print $11}'`;
        SINCE=`cat /tmp/login-db-pid.txt | awk '{print $1, $2, $3}'`;
        if [ $NUM -eq 1 ]; then
                echo "$USER,$IP:8989,$PID,2022,$SINCE" >> "/var/www/html/stat/ssh.txt";
        fi
done
Sshonline

# Set Permissions And Start
chmod -R 777 /etc/sshlogin/sshusers.sh
/bin/bash /etc/sshlogin/sshusers.sh  >/dev/null 2>&1
chmod -R 777 /var/www/html/stat/ssh.txt

# Mysql ConnectionHandler
cat <<'MysqlConnect' > /etc/sshlogin/mysql.class.php
<?PHP
class mysql_db
{
    var $username;
    var $pwd;
    var $database;
    var $connection;
	var $query_result;

    function InitDB($host,$uname,$pwd,$database)
    {
        $this->db_host  = $host;
        $this->username = $uname;
        $this->pwd  = $pwd;
        $this->database  = $database;	
    }

	function sql_query($query)
	{
        if(!$this->DBLogin())
        {
            $this->HandleError("Database login failed!");
            return false;
        }

		if($query != "")
		{
			$this->query_result = $this->connection->query($query);
		}
		
		if($this->query_result)
		{
			return $this->query_result;
		}
			return;
	}
	
    function DBLogin()
    {

        $this->connection = new MySQLi($this->db_host,$this->username,$this->pwd);

        if(!$this->connection)
        {   
            $this->HandleDBError("Database Login failed! Please make sure that the DB login credentials provided are correct");
            return false;
        }
		
        if(!mysqli_select_db($this->connection,$this->database))
        {
            $this->HandleDBError('Failed to select database: '.$this->database.' Please make sure that the database name provided is correct');
            return false;
        }
        if(!$this->connection->query("SET NAMES 'UTF8'"))
        {
            $this->HandleDBError('Error setting utf8 encoding');
            return false;
        }
        return true;
    }

    function HandleDBError($err)
    {
        $this->HandleError($err."\r\n ". mysqli_error($this->db_connect_id). ":");
    }
}
?>
MysqlConnect

chmod -R 777 /etc/sshlogin/mysql.class.php

# Update SSH Users to connected on database
cat <<'SshDB' > /etc/sshlogin/sshauth.sh
#!/bin/bash
#Created by TsholoVPN

if [ -e "/var/log/auth.log" ]; then
        LOG="/var/log/auth.log";
fi
if [ -e "/var/log/secure" ]; then
        LOG="/var/log/secure";
fi

>"/etc/sshlogin/cronjob_ssh_task.php";
#ONLY PUT YOUR DATABASE
echo "<?php" >> "/etc/sshlogin/cronjob_ssh_task.php";
echo "error_reporting(E_ERROR | E_PARSE);" >> "/etc/sshlogin/cronjob_ssh_task.php";
echo "ini_set('display_errors', '1');" >> "/etc/sshlogin/cronjob_ssh_task.php";
echo "\$DB_host = 'DatabaseHost';" >> "/etc/sshlogin/cronjob_ssh_task.php";
echo "\$DB_user = 'DatabaseUser';" >> "/etc/sshlogin/cronjob_ssh_task.php";
echo "\$DB_pass = 'DatabasePass';" >> "/etc/sshlogin/cronjob_ssh_task.php";
echo "\$DB_name = 'DatabaseName';" >> "/etc/sshlogin/cronjob_ssh_task.php";
echo "\$mysqli = new MySQLi(\$DB_host,\$DB_user,\$DB_pass,\$DB_name);" >> "/etc/sshlogin/cronjob_ssh_task.php";
echo "if (\$mysqli->connect_error) {" >> "/etc/sshlogin/cronjob_ssh_task.php";
echo "die('Error : ('. \$mysqli->connect_errno .') '. \$mysqli->connect_error);" >> "/etc/sshlogin/cronjob_ssh_task.php";
echo "}" >> "/etc/sshlogin/cronjob_ssh_task.php";
echo 'require "/etc/sshlogin/mysql.class.php";' >> "/etc/sshlogin/cronjob_ssh_task.php";
echo "\$db = new mysql_db();" >> "/etc/sshlogin/cronjob_ssh_task.php";
echo "\$db->InitDB(\$DB_host,\$DB_user,\$DB_pass,\$DB_name);" >> "/etc/sshlogin/cronjob_ssh_task.php";
#echo "\$db->sql_query(\"UPDATE users SET ssh_is_connected=0\");" >> "/etc/sshlogin/cronjob_ssh_task.php";

#DROPBEAR
data=( `ps aux | grep -i dropbear | awk '{print $2}'`);
cat $LOG | grep -i dropbear | grep -i "Password auth succeeded" > /tmp/login-db.txt;
for PID in "${data[@]}"
do
        cat /tmp/login-db.txt | grep "dropbear\[$PID\]" > /tmp/login-db-pid.txt;
        NUM=`cat /tmp/login-db-pid.txt | wc -l`;
        USER=`cat /tmp/login-db-pid.txt | awk '{print $10}'`;
        IP=`cat /tmp/login-db-pid.txt | awk '{print $12}'`;
        if [ $NUM -eq 1 ]; then
                echo "\$db->sql_query(\"UPDATE users SET ssh_is_connected=1 WHERE user_name= $USER\");" >> "/etc/sshlogin/cronjob_ssh_task.php";
		fi
done

#OPENSSH
cat $LOG | grep -i sshd | grep -i "Accepted password for" > /tmp/login-db.txt
data=( `ps aux | grep "\[priv\]" | sort -k 72 | awk '{print $2}'`);
for PID in "${data[@]}"
do
        cat /tmp/login-db.txt | grep "sshd\[$PID\]" > /tmp/login-db-pid.txt;
        NUM=`cat /tmp/login-db-pid.txt | wc -l`;
        USER=`cat /tmp/login-db-pid.txt | awk '{print $9}'`;
        IP=`cat /tmp/login-db-pid.txt | awk '{print $11}'`;
        if [ $NUM -eq 1 ]; then
                echo "\$db->sql_query(\"UPDATE users SET ssh_is_connected=1 WHERE user_name= '$USER'\");" >> "/etc/sshlogin/cronjob_ssh_task.php";
        fi
done
echo "?>" >> "/etc/sshlogin/cronjob_ssh_task.php";
SshDB

sed -i "s|DatabaseHost|$DatabaseHost|g;s|DatabaseName|$DatabaseName|g;s|DatabaseUser|$DatabaseUser|g;s|DatabasePass|$DatabasePass|g" "/etc/sshlogin/sshauth.sh"

chmod -R 777 /etc/sshlogin/sshauth.sh
/bin/bash /etc/sshlogin/sshauth.sh  >/dev/null 2>&1
chmod -R 777 /etc/sshlogin/cronjob_ssh_task.php

# Check online ssh users on panel every minute 
cat <<'Loop' > /etc/sshlogin/loop.sh
#!/bin/bash
# Program that checks if SSH users is online
echo $$ > .pid
while :; do
  /bin/bash /etc/sshlogin/sshauth.sh
  /usr/bin/php /etc/sshlogin/cronjob_ssh_task.php
  sleep 1
done
Loop

# Creating a service for panel
cat << Loopservice> /etc/systemd/system/loop.service
[Unit]
Description=SSH Task Loop
After=multi-user.target
[Service]
User=root
Type=simple
WorkingDirectory=/etc/sshlogin/
ExecStart=/bin/bash loop.sh
ExecStop=/bin/bash -c "kill -15 `cat /etc/sshlogin/.pid`"
[Install]
WantedBy=multi-user.target
Loopservice

# start the service
systemctl daemon-reload
systemctl enable loop
systemctl restart loop
systemctl status --no-pager loop
service loop restart

# Fixing Multilogin Script
cat <<'Multilogin' > /etc/sshlogin/set_multilogin_autokill_lib
#!/bin/bash
clear
MAX=1
if [ -e "/var/log/auth.log" ]; then
        OS=1;
        LOG="/var/log/auth.log";
fi
if [ -e "/var/log/secure" ]; then
        OS=2;
        LOG="/var/log/secure";
fi

if [ $OS -eq 1 ]; then
    service ssh restart > /dev/null 2>&1;
fi
if [ $OS -eq 2 ]; then
    service sshd restart > /dev/null 2>&1;
fi
    service dropbear restart > /dev/null 2>&1;
                
if [[ ${1+x} ]]; then
        MAX=$1;
fi

        cat /etc/passwd | grep "/home/" | cut -d":" -f1 > /root/user.txt
        username1=( `cat "/root/user.txt" `);
        i="0";
        for user in "${username1[@]}"
            do
                username[$i]=`echo $user | sed 's/'\''//g'`;
                jumlah[$i]=0;
                i=$i+1;
            done
        cat $LOG | grep -i dropbear | grep -i "Password auth succeeded" > /tmp/log-db.txt
        proc=( `ps aux | grep -i dropbear | awk '{print $2}'`);
        for PID in "${proc[@]}"
            do
                cat /tmp/log-db.txt | grep "dropbear\[$PID\]" > /tmp/log-db-pid.txt
                NUM=`cat /tmp/log-db-pid.txt | wc -l`;
                USER=`cat /tmp/log-db-pid.txt | awk '{print $10}' | sed 's/'\''//g'`;
                IP=`cat /tmp/log-db-pid.txt | awk '{print $12}'`;
                if [ $NUM -eq 1 ]; then
                        i=0;
                        for user1 in "${username[@]}"
                            do
                                if [ "$USER" == "$user1" ]; then
                                        jumlah[$i]=`expr ${jumlah[$i]} + 1`;
                                        pid[$i]="${pid[$i]} $PID"
                                fi
                                i=$i+1;
                            done
                fi
            done
        cat $LOG | grep -i sshd | grep -i "Accepted password for" > /tmp/log-db.txt
        data=( `ps aux | grep "\[priv\]" | sort -k 72 | awk '{print $2}'`);
        for PID in "${data[@]}"
            do
                cat /tmp/log-db.txt | grep "sshd\[$PID\]" > /tmp/log-db-pid.txt;
                NUM=`cat /tmp/log-db-pid.txt | wc -l`;
                USER=`cat /tmp/log-db-pid.txt | awk '{print $9}'`;
                IP=`cat /tmp/log-db-pid.txt | awk '{print $11}'`;
                if [ $NUM -eq 1 ]; then
                        i=0;
                        for user1 in "${username[@]}"
                            do
                                if [ "$USER" == "$user1" ]; then
                                        jumlah[$i]=`expr ${jumlah[$i]} + 1`;
                                        pid[$i]="${pid[$i]} $PID"
                                fi
                                i=$i+1;
                            done
                fi
        done
        j="0";
        for i in ${!username[*]}
            do
                if [ ${jumlah[$i]} -gt $MAX ]; then
                        date=`date +"%Y-%m-%d %X"`;
                        echo "$date - ${username[$i]} - ${jumlah[$i]}";
                        echo "$date - ${username[$i]} - ${jumlah[$i]}" >> /root/log-limit.txt;
                        kill ${pid[$i]};
                        pid[$i]="";
                        j=`expr $j + 1`;
                fi
            done
        if [ $j -gt 0 ]; then
                if [ $OS -eq 1 ]; then
                        service ssh restart > /dev/null 2>&1;
                fi
                if [ $OS -eq 2 ]; then
                        service sshd restart > /dev/null 2>&1;
                fi
                service dropbear restart > /dev/null 2>&1;
                j=0;
        fi
Multilogin

chmod -R 777 /etc/sshlogin/set_multilogin_autokill_lib

# Webmin Configuration
sed -i '$ i\dope: acl adsl-client ajaxterm apache at backup-config bacula-backup bandwidth bind8 burner change-user cluster-copy cluster-cron cluster-passwd cluster-shell cluster-software cluster-useradmin cluster-usermin cluster-webmin cpan cron custom dfsadmin dhcpd dovecot exim exports fail2ban fdisk fetchmail file filemin filter firewall firewalld fsdump grub heartbeat htaccess-htpasswd idmapd inetd init inittab ipfilter ipfw ipsec iscsi-client iscsi-server iscsi-target iscsi-tgtd jabber krb5 ldap-client ldap-server ldap-useradmin logrotate lpadmin lvm mailboxes mailcap man mon mount mysql net nis openslp package-updates pam pap passwd phpini postfix postgresql ppp-client pptp-client pptp-server proc procmail proftpd qmailadmin quota raid samba sarg sendmail servers shell shorewall shorewall6 smart-status smf software spam squid sshd status stunnel syslog-ng syslog system-status tcpwrappers telnet time tunnel updown useradmin usermin vgetty webalizer webmin webmincron webminlog wuftpd xinetd' /etc/webmin/webmin.acl
sed -i '$ i\dope:x:0' /etc/webmin/miniserv.users
/usr/share/webmin/changepass.pl /etc/webmin dope 12345

# Some Cron Job
echo "* * * * * root /bin/bash /etc/sshlogin/set_multilogin_autokill_lib 1 >/dev/null 2>&1" >> "/etc/cron.d/set_multilogin_autokill_lib"
echo "* * * * * root /bin/bash /etc/sshlogin/sshusers.sh >/dev/null 2>&1" >> "/etc/cron.d/sshlogin"
echo "* * * * * root /bin/bash /usr/local/sbin/Tsholo-user-delete-expired &> /dev/null" >> "/etc/cron.d/user-delete-expired"
echo "* * * * * root /usr/bin/php /etc/sshlogin/connection.php >/dev/null 2>&1" > /etc/cron.d/connection-ssh
echo "* * * * * root /bin/bash /etc/sshlogin/active.sh >/dev/null 2>&1"> /etc/cron.d/active-users
echo "* * * * * root /bin/bash /etc/sshlogin/inactive.sh >/dev/null 2>&1" > /etc/cron.d/inactive-users

# Some Settings
sed -i "s|#SystemMaxUse=|SystemMaxUse=10M|g" /etc/systemd/journald.conf
sed -i "s|#SystemMaxFileSize=|SystemMaxFileSize=1M|g" /etc/systemd/journald.conf
systemctl restart systemd-journald
service systemd-journald restart

# Creating startup 1 script using cat eof tricks
cat <<'Tsholoz' > /etc/Tsholostartup
#!/bin/sh

# Firewall Protection ( Torrent, Brute Force, Port Scanning )
iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP
iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP

# Setting server local time
ln -fs /usr/share/zoneinfo/MyTimeZone /etc/localtime

# Prevent DOS-like UI when installing using APT (Disabling APT interactive dialog)
export DEBIAN_FRONTEND=noninteractive

# Allowing ALL TCP ports for our machine (Simple workaround for policy-based VPS)
iptables -A INPUT -s $(wget -4qO- http://ipinfo.io/ip) -p tcp -m multiport --dport 1:65535 -j ACCEPT

# Allowing OpenVPN to Forward traffic
/bin/bash /etc/openvpn/openvpn.bash

# Disable IpV6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6

# add DNS server ipv4
echo "nameserver DNS1" > /etc/resolv.conf
echo "nameserver DNS2" >> /etc/resolv.conf

######                 WARNING                           
###### MAKE SURE YOU ONLY PUT [FULLY WORKING APPS] 
######          WHOLE SCRIPT WILL COLLAPSE         
######         IF YOU ADD NOT WORKING SCRIPT       
######    TEST IT BEFORE ADD YOUR COMMAND HERE     
######              by: TsholoVPN
Tsholoz

sed -i "s|MyTimeZone|$MyVPS_Time|g" /etc/Tsholostartup
sed -i "s|DNS1|$Dns_1|g" /etc/Tsholostartup
sed -i "s|DNS2|$Dns_2|g" /etc/Tsholostartup
rm -rf /etc/sysctl.d/99*

 # Setting our startup script to run every machine boots 
cat <<'Tsholox' > /etc/systemd/system/Tsholostartup.service
[Unit] 
Description=/etc/Tsholostartup
ConditionPathExists=/etc/Tsholostartup

[Service] 
Type=forking 
ExecStart=/etc/Tsholostartup start 
TimeoutSec=0
StandardOutput=tty 
RemainAfterExit=yes 
SysVStartPriority=99 

[Install] 
WantedBy=multi-user.target
Tsholox

chmod +x /etc/Tsholostartup
systemctl enable Tsholostartup
systemctl start Tsholostartup
service Tsholostartup restart
cd

# Pull BadVPN Binary 64bit or 32bit
if [ "$(getconf LONG_BIT)" == "64" ]; then
 wget -O /usr/bin/badvpn-udpgw "https://www.dropbox.com/s/jo6qznzwbsf1xhi/badvpn-udpgw64"
else
 wget -O /usr/bin/badvpn-udpgw "https://www.dropbox.com/s/8gemt9c6k1fph26/badvpn-udpgw"
fi

# Change Permission to make it Executable
chmod +x /usr/bin/badvpn-udpgw
 
# Setting our startup script for badvpn
cat <<'Tsholob' > /etc/systemd/system/badvpn.service
[Unit]
Description=badvpn tun2socks service
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/bin/badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 1000 --max-connections-for-client 10

[Install]
WantedBy=multi-user.target
Tsholob

systemctl enable badvpn
systemctl start badvpn
service badvpn restart

# TCP BBR
brloc=/etc/modules-load.d/modules.conf
if [[ ! `cat $brloc` =~ "tcp_bbr" ]];then
modprobe tcp_bbr
echo tcp_bbr >> $brloc; fi

#Tweak for IPV4 TCP/UDP speed and maximize capability function Status: OFF
cd
mkdir -p /etc/Tsholo-script/others
echo "off" > /etc/Tsholo-script/others/tcptweaks
echo '' > /etc/sysctl.conf &> /dev/null
echo "# Kernel sysctl configuration file for Red Hat Linux
#
# For binary values, 0 is disabled, 1 is enabled.  See sysctl(8) and
# sysctl.conf(5) for more details.
#
# Use '/sbin/sysctl -a' to list all possible parameters.
# Controls IP packet forwarding
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.default.accept_source_route = 0
kernel.sysrq = 0
kernel.core_uses_pid = 1
net.ipv4.tcp_syncookies = 1
kernel.msgmnb = 65536
kernel.msgmax = 65536
kernel.shmmax = 68719476736
kernel.shmall = 4294967296
net.ipv4.ip_forward = 1
fs.file-max = 65535
net.core.rmem_default = 262144
net.core.rmem_max = 262144
net.core.wmem_default = 262144
net.core.wmem_max = 262144
net.ipv4.tcp_rmem = 4096 87380 8388608
net.ipv4.tcp_wmem = 4096 65536 8388608
net.ipv4.tcp_mem = 4096 4096 4096
net.ipv4.tcp_low_latency = 1
net.core.netdev_max_backlog = 4000
net.ipv4.ip_local_port_range = 1024 65000
net.ipv4.tcp_max_syn_backlog = 16384"| sudo tee /etc/sysctl.conf
sysctl -p &> /dev/null

# Creating file paths
mkdir -p /etc/xray
touch /etc/xray/access.log
touch /etc/xray/error.log
chmod 777 /etc/xray/access.log
chmod 777 /etc/xray/error.log

# Get Xray Latest Release
latest_version="$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"

# Installation Xray Core
xraycore_link="https://github.com/XTLS/Xray-core/releases/download/v$latest_version/xray-linux-64.zip"

# Download Xray and Unzip
curl -sL "$xraycore_link" -o /etc/xray/xray.zip
cd /etc/xray/
unzip -q /etc/xray/xray.zip && rm -rf /etc/xray/xray.zip
chmod +x /etc/xray/xray
cd

# Xray Service
cat <<'dkxrayservice' > /etc/systemd/system/xray.service
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=www-data
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/etc/xray/xray run -config /etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
dkxrayservice

# Service Xray multi ports
cat <<'dksuperxrayservice' > /etc/systemd/system/superxray.service
[Unit]
Description=superxray multi port
After=network.target

[Service]
Type=simple
ExecStartPre=-/bin/mkdir -p /var/run/xray
ExecStart=/bin/chown www-data:www-data /var/run/xray
Restart=on-abort

[Install]
WantedBy=multi-user.target
dksuperxrayservice

# Dk xray config
cat> /etc/xray/config.json << END
{
  "log" : {
    "access": "/etc/xray/access.log",
    "error": "/etc/xray/error.log",
    "loglevel": "warning"
  },
  "inbounds": [
      {
      "listen": "127.0.0.1",
      "port": $V2ray_Port1,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "127.0.0.1"
      },
      "tag": "api"
    },
   {
     "listen": "/run/xray/vless_ws.sock",
     "protocol": "vless",
      "settings": {
          "decryption":"none",
            "clients": [
               {
                 "id": "$UUID"                 
#vless
             }
          ]
       },
       "streamSettings":{
         "network": "ws",
            "wsSettings": {
                "path": "/dkws"
          }
        }
     },
     {
     "listen": "/run/xray/vmess_ws.sock",
     "protocol": "vmess",
      "settings": {
            "clients": [
               {
                 "id": "$UUID",
                 "alterId": 0
#vmess
             }
          ]
       },
       "streamSettings":{
         "network": "ws",
            "wsSettings": {
                "path": "/dkvws"
          }
        }
     },
    {
      "listen": "/run/xray/trojan_ws.sock",
      "protocol": "trojan",
      "settings": {
          "decryption":"none",		
           "clients": [
              {
                 "password": "$UUID"
#trojanws
              }
          ],
         "udp": true
       },
       "streamSettings":{
           "network": "ws",
           "wsSettings": {
               "path": "/dktrojanws"
            }
         }
     },
    {
         "listen": "127.0.0.1",
        "port": "$V2ray_Port2",
        "protocol": "shadowsocks",
        "settings": {
           "clients": [
           {
           "method": "aes-128-gcm",
          "password": "$UUID"
#ssws
           }
          ],
          "network": "tcp,udp"
       },
       "streamSettings":{
          "network": "ws",
             "wsSettings": {
               "path": "/dkssws"
           }
        }
     },	
      {
        "listen": "/run/xray/vless_grpc.sock",
        "protocol": "vless",
        "settings": {
         "decryption":"none",
           "clients": [
             {
               "id": "$UUID"
#vlessgrpc
             }
          ]
       },
          "streamSettings":{
             "network": "grpc",
             "grpcSettings": {
                "serviceName": "vless-grpc"
           }
        }
     },
     {
      "listen": "/run/xray/vmess_grpc.sock",
     "protocol": "vmess",
      "settings": {
            "clients": [
               {
                 "id": "$UUID",
                 "alterId": 0
#vmessgrpc
             }
          ]
       },
       "streamSettings":{
         "network": "grpc",
            "grpcSettings": {
                "serviceName": "vmess-grpc"
          }
        }
     },
     {
        "listen": "/run/xray/trojan_grpc.sock",
        "protocol": "trojan",
        "settings": {
          "decryption":"none",
             "clients": [
               {
                 "password": "$UUID"
#trojangrpc
               }
           ]
        },
         "streamSettings":{
         "network": "grpc",
           "grpcSettings": {
               "serviceName": "trojan-grpc"
         }
      }
   },
   {
    "listen": "127.0.0.1",
    "port": "$V2ray_Port3",
    "protocol": "shadowsocks",
    "settings": {
        "clients": [
          {
             "method": "aes-128-gcm",
             "password": "$UUID"
#ssgrpc
           }
         ],
           "network": "tcp,udp"
      },
    "streamSettings":{
     "network": "grpc",
        "grpcSettings": {
           "serviceName": "ss-grpc"
          }
       }
    }	
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "ip": [
          "0.0.0.0/8",
          "10.0.0.0/8",
          "100.64.0.0/10",
          "169.254.0.0/16",
          "172.16.0.0/12",
          "192.0.0.0/24",
          "192.0.2.0/24",
          "192.168.0.0/16",
          "198.18.0.0/15",
          "198.51.100.0/24",
          "203.0.113.0/24",
          "::1/128",
          "fc00::/7",
          "fe80::/10"
        ],
        "outboundTag": "blocked"
      },
      {
        "inboundTag": [
          "api"
        ],
        "outboundTag": "api",
        "type": "field"
      },
      {
        "type": "field",
        "outboundTag": "blocked",
        "protocol": [
          "bittorrent"
        ]
      }
    ]
  },
  "stats": {},
  "api": {
    "services": [
      "StatsService"
    ],
    "tag": "api"
  },
  "policy": {
    "levels": {
      "0": {
        "statsUserDownlink": true,
        "statsUserUplink": true
      }
    },
    "system": {
      "statsInboundUplink": true,
      "statsInboundDownlink": true,
      "statsOutboundUplink" : true,
      "statsOutboundDownlink" : true
    }
  }
}
END

# Enable & restart xray
systemctl daemon-reload
systemctl enable xray
systemctl restart xray
systemctl enable superxray
systemctl restart superxray
systemctl status --no-pager xray
service xray restart
service superxray restart

#wget -O /usr/local/v2-ui-linux.tar.gz "https://www.dropbox.com/s/gg3043jt5rumift/v2-ui-linux.tar.gz"
#cd /usr/local/
#tar zxvf v2-ui-linux.tar.gz
#rm v2-ui-linux.tar.gz -f
#cd v2-ui
#chmod +x v2-ui bin/v2ray-v2-ui bin/v2ctl
#cp -f v2-ui.service /etc/systemd/system/
#cd

# download script
cd /usr/local/bin
wget -O premium-script.tar.gz "https://www.dropbox.com/s/1ex9tr7hzoh53ln/premium-script.tar.gz"
tar -xvf premium-script.tar.gz
rm -f premium-script.tar.gz
cp /usr/local/bin/menu /usr/bin/menu
cp /usr/local/bin/menu /usr/bin/Menu
chmod +x /usr/bin/Menu
chmod +x /usr/bin/menu
chmod +x ./*
cd

clear
cd
echo " "
echo " "
echo "PREMIUM SCRIPT SUCCESSFULLY INSTALLED!"
echo "SCRIPT BY DOPE~KID"
echo "PLEASE WAIT..."
echo " "

# Finishing
chown -R www-data:www-data /home/vps/public_html

clear
echo ""
echo " INSTALLATION FINISH! "
echo ""
echo ""
echo "Server Information: " | tee -a log-install.txt | lolcat
echo "   • Timezone       : $MyVPS_Time "  | tee -a log-install.txt | lolcat
echo "   • Fail2Ban       : [ON]"  | tee -a log-install.txt | lolcat
echo "   • IPtables       : [ON]"  | tee -a log-install.txt | lolcat
echo "   • Auto-Reboot    : [OFF] See menu to [ON] "  | tee -a log-install.txt | lolcat
echo "   • TCP Speed Tweak: [OFF] See menu to [ON]" | tee -a log-install.txt | lolcat
echo "   • Squid Cache    : [ON]" | tee -a log-install.txt | lolcat
echo "   • IPv6           : [OFF]"  | tee -a log-install.txt  | lolcat

echo " "| tee -a log-install.txt | lolcat
echo "Automated Features:"| tee -a log-install.txt | lolcat
echo "   • Auto delete expired user account"| tee -a log-install.txt | lolcat
echo "   • Auto restart server "| tee -a log-install.txt | lolcat
echo "   • Auto disconnect multilogin users [Openvpn not included]."| tee -a log-install.txt | lolcat
echo "   • Auto configure firewall every reboot[Protection for torrent and etc..]"| tee -a log-install.txt | lolcat
echo "   • Auto updated firewall[if port changed firewall will adapt your new port]"| tee -a log-install.txt | lolcat

echo " " | tee -a log-install.txt | lolcat
echo "Services & Port Information:" | tee -a log-install.txt | lolcat
echo "   • OpenVPN              : [ON] : TCP: $OpenVPN_TCP_Port | UDP: $OpenVPN_UDP_Port" | tee -a log-install.txt | lolcat
echo "   • Dropbear             : [ON] : $Dropbear_Port1 | $Dropbear_Port2 " | tee -a log-install.txt | lolcat
echo "   • Squid Proxy          : [ON] : $Squid_Port1 | $Squid_Port2 |$Squid_Port3 | limit to IP Server" | tee -a log-install.txt | lolcat
echo "   • Nginx                : [ON] : $Apache_Port | $Openvpn_Monitoring |$Nginx_Port | $Nginx_vpn" | tee -a log-install.txt | lolcat
echo "   • SSL through Dropbear : [ON] : $Stunnel_Port1 | $Stunnel_Port5 " | tee -a log-install.txt | lolcat
echo "   • SSL through OpenSSH  : [ON] : $Stunnel_Port2 " | tee -a log-install.txt | lolcat
echo "   • SSL through Openvpn  : [ON] : $Stunnel_Port3 | $Stunnel_Port5" | tee -a log-install.txt | lolcat
echo "   • SSL through Websocket: [ON] : $Stunnel_Port4 " | tee -a log-install.txt | lolcat
echo "   • OpenVPN Websocket    : [ON] : 443 | 80 | $WsPort" | tee -a log-install.txt | lolcat
echo "   • SSH Websocket        : [ON] : 443 | 80 | $WsPort " | tee -a log-install.txt | lolcat
echo "   • Xray Trojan Ws       : [ON] : 443 | 80" | tee -a log-install.txt | lolcat
echo "   • Xray Shadowsocks Ws  : [ON] : 443 | 80" | tee -a log-install.txt | lolcat
echo "   • Xray Vless Ws        : [ON] : 443 | 80" | tee -a log-install.txt | lolcat
echo "   • Xray Vmess Ws        : [ON] : 443 | 80" | tee -a log-install.txt | lolcat
echo "   • Xray Trojan Grpc     : [ON] : 443 | 80" | tee -a log-install.txt | lolcat
echo "   • Xray Shadowsocks Grpc: [ON] : 443 | 80" | tee -a log-install.txt | lolcat
echo "   • Xray Vmess Grpc      : [ON] : 443 | 80" | tee -a log-install.txt | lolcat
echo "   • Xray Vless Grpc      : [ON] : 443 | 80" | tee -a log-install.txt | lolcat
echo "   • BADVPN               : [ON] : 7300 " | tee -a log-install.txt | lolcat
echo "   • Additional SSHD Port : [ON] : $SSH_Port2" | tee -a log-install.txt | lolcat
echo "   • OCS Panel            : [ON] : http://$IPADDR:$Nginx_Port" | tee -a log-install.txt | lolcat
echo "   • Openvpn Monitoring   : [ON] : http://$IPADDR:$Openvpn_Monitoring" | tee -a log-install.txt | lolcat
#echo "   • V2ray Panel          : [ON] : http://$IPADDR:65432 " | tee -a log-install.txt | lolcat

echo "" | tee -a log-install.txt | lolcat
echo "Notes:" | tee -a log-install.txt | lolcat
echo "  ★ Torrent Protection [ add newest torrent port] " | tee -a log-install.txt | lolcat
echo "  ★ Port Scanner Basic Protection  " | tee -a log-install.txt | lolcat
echo "  ★ Brute Force Attack Basic Protection  " | tee -a log-install.txt | lolcat
echo "  ★ All ports can be edited in Edit Menu. " | tee -a log-install.txt | lolcat
echo "  ★ Multi-login Limit customize per user [see menu]. " | tee -a log-install.txt | lolcat
echo "  ★ To display list of commands:  " [ menu ] or [ menu dk ] "" | tee -a log-install.txt | lolcat
echo "" | tee -a log-install.txt | lolcat
echo "  ★ Other concern and questions of these auto-scripts?" | tee -a log-install.txt | lolcat
echo "    Direct Messege : https://t.me/TsholoVPN" | tee -a log-install.txt | lolcat
echo ""
read -p " Press enter.."

clear
echo ""
echo ""
figlet Tsholo Script -c | lolcat
echo ""
echo "       Installation Complete! System need to reboot to apply all changes! "
read -p "                      Press Enter to reboot..."
reboot
