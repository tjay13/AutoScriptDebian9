#!/bin/bash
#    ░▒▓█ ☁️ TsholoVPN Script 1.0.0 ☁️ █▓▒░" 
#                         by: TsholoVPN

#########################################################
###      Input Your Desired Configuration Information
#########################################################

# Script Name
MyScriptName='TsholoVPN'

# Server Name for openvpn config and banner
ServerName='TsholoVPN'

# OpenSSH Ports
SSH_Port1='22'
SSH_Port2='299'

# Dropbear Ports
Dropbear_Port1='790'
Dropbear_Port2='2770'

# Stunnel Ports
Stunnel_Port1='443' # through Dropbear
Stunnel_Port2='444' # through OpenSSH
Stunnel_Port3='445' # through Openvpn
Stunnel_Port4='441' # through WebSocket

# OpenVPN Ports
OpenVPN_TCP_Port='1194'
OpenVPN_UDP_Port='1195'

# Squid Ports
Squid_Port1='3128'
Squid_Port2='8080'
Squid_Port3='9005'

# Python Vars for deb9
Python_Url=https://github.com/tjay13/AutoScriptDebian9/blob/main/Tools/Python-3.6.9.tar.xz?raw=true

# Python Socks Proxy
WsPort='80'  # for port 8080 change cloudflare SSL/TLS to full
WsResponse='HTTP/1.1 101 Switching Protocols\r\n\r\n'
WsHTTPResponse='HTTP/1.1 200 OK\r\n\r\n'

# SSLH Port
MainPort='442' # main port to tunnel default 443

# WebServer Ports
Php_Socket='9000'
Openvpn_Monitoring='89'
Tcp_Monitor_Port='450'
Udp_Monitor_Port='451'
Nginx_Port='85' 
Apache_Port='81' # for openvpn panel stat port

# DNS Resolver
Dns_1='8.8.8.8' # GoogleDNS
Dns_2='8.8.4.4' # GoogleDNS

# Server local time
MyVPS_Time='Africa/Johannesburg'

# Database Info for panel
DatabaseHost='185.61.137.174';
DatabaseName='vpnquest1_dbase';
DatabaseUser='vpnquest1_user';
DatabasePass='s+(WT#r4CaB&';
DatabasePort='3306';

#########################################################
###        TsholoVPN Script AutoScript Code Begins...
#########################################################

function ip_address(){
  local IP="$( ip addr | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | egrep -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1 )"
  [ -z "${IP}" ] && IP="$( wget -qO- -t1 -T2 ipv4.icanhazip.com )"
  [ -z "${IP}" ] && IP="$( wget -qO- -t1 -T2 ipinfo.io/ip )"
  [ ! -z "${IP}" ] && echo "${IP}" || echo
} 
IPADDR="$(ip_address)"

# Colours
white='\e[0;37m'
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

# Setting Terminal Message
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

# Install Apache2
sudo apt-get install apache2 -y

# Setup Apache
sed -i "s|Listen 80|Listen $Apache_Port|g" /etc/apache2/ports.conf
service apache2 restart
systemctl reload apache2 #activate

cd /etc/default/
mv sslh sslh-old
cat << sslh > /etc/default/sslh
RUN=yes

DAEMON=/usr/sbin/sslh

DAEMON_OPTS="--user sslh --listen 0.0.0.0:$MainPort --ssh 127.0.0.1:$Dropbear_Port2 --openvpn 127.0.0.1:$OpenVPN_TCP_Port --ssl 127.0.0.1:4443 --pidfile /var/run/sslh/sslh.pid"
sslh

#Restart Service
systemctl daemon-reload
systemctl enable sslh
systemctl start sslh
systemctl restart sslh

# Install Webmin
wget https://github.com/tjay13/AutoScriptDebian9/blob/main/Tools/webmin_1.801_all.deb?raw=true
dpkg --install webmin_1.801_all.deb
sleep 1
rm -rf webmin_1.801_all.deb
 
# Configuring webmin server config to use only http instead of https
sed -i 's|ssl=1|ssl=0|g' /etc/webmin/miniserv.conf
 
# Then restart to take effect
systemctl restart webmin

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
sed -i 's/bind-address/#bind-address/g' /etc/mysql/mariadb.conf.d/50-server.cnf
sed -i '/max_connections/c\max_connections = 5000' /etc/mysql/mariadb.conf.d/50-server.cnf
 
# Then restart to take effect
systemctl restart mysql

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
# TsholoVPN Script OpenSSH Server config
# TsholoVPN Script
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
  
# Removing some duplicate config file
rm -rf /etc/default/dropbear*
 
# creating dropbear config using cat eof tricks
cat <<'MyDropbear' > /etc/default/dropbear
# TsholoVPN Script Dropbear Config
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

# STUNNEL
StunnelDir=$(ls /etc/default | grep stunnel | head -n1)

# Creating stunnel startup config using cat eof tricks
cat <<'MyStunnelD' > /etc/default/$StunnelDir
# TsholoVPN Script Stunnel Config
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
openssl req -new -x509 -days 9999 -nodes -subj "/C=SA/ST=GP/L=Sebokeng/O=$MyScriptName/OU=$MyScriptName/CN=$MyScriptName" -out /etc/stunnel/stunnel.pem -keyout /etc/stunnel/stunnel.pem

# Creating stunnel server config
cat <<'MyStunnelC' > /etc/stunnel/stunnel.conf
# My Stunnel Config
pid = /var/run/stunnel.pid
cert = /etc/stunnel/stunnel.pem
client = no
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
TIMEOUTclose = 0

[dropbear]
accept = Stunnel_Port1
connect = 127.0.0.1:MainPort
connect = 127.0.0.1:WsPort

MyStunnelC

# setting stunnel ports
sed -i "s|Stunnel_Port1|$Stunnel_Port1|g" /etc/stunnel/stunnel.conf
sed -i "s|Stunnel_Port2|$Stunnel_Port2|g" /etc/stunnel/stunnel.conf
sed -i "s|Stunnel_Port3|$Stunnel_Port3|g" /etc/stunnel/stunnel.conf
sed -i "s|Stunnel_Port4|$Stunnel_Port4|g" /etc/stunnel/stunnel.conf
sed -i "s|dropbear_port_c|$Dropbear_Port1|g" /etc/stunnel/stunnel.conf
sed -i "s|openssh_port_c|$SSH_Port1|g" /etc/stunnel/stunnel.conf
sed -i "s|openvpn_port_c|$OpenVPN_TCP_Port|g" /etc/stunnel/stunnel.conf
sed -i "s|WsPort|$WsPort|g" /etc/stunnel/stunnel.conf

# Restarting stunnel service
systemctl restart $StunnelDir

# SOCKS PROXY
mkdir -p /etc/TsholoVPN-script/py-socksproxy

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
#!/usr/bin/env python3
# encoding: utf-8
# SOCKs Proxy by TsholoVPN
import socket, threading, _thread, select, signal, sys, time, os, re
ploc=os.path.dirname(os.path.realpath(__file__))
recvbuff = 65536
success = b"$WsResponse" # RESPONSE MESSEGE FOR WEBSOCKET 
success2 = b"$WsHTTPResponse" # RESPONSE HTTP MESSAGE 

class Server(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.running = False
        self.host = '0.0.0.0'
        self.port = $WsPort # WEBSOCKET PORT
        self.dport= 19 # DON'T CHANGE
        self.threads = []
        self.threadsLock = threading.Lock()
        self.logLock = threading.Lock()
        print("Listening on host %s for port %s." % (self.host, self.port))

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
                conn.start()
                self.addConn(conn)
        finally:
            self.running = False
            self.soc.close()

    def printLog(self, log):
        self.logLock.acquire()
        print(log)
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

def reader(loc):
     f = open(loc, 'r')
     cont=f.read()
     f.close()
     return cont

def to_b(str):
    return bytes(str, 'utf-8')

def bsplitlines(bstr):
    return re.split(b'[\r\n]+', bstr)

def parser(req):
    try:
        lines=bsplitlines(req)
        if re.match(b"^GET", lines[0]):
            rloc=lines[0].decode('utf-8').split(' ')[1]
            wloc=ploc+'/web'+rloc
            if rloc == '/':
                wloc+='index.html'
                return b"HTTP/1.1 200 OK\r\n\r\n"+to_b(reader(wloc)) if os.path.exists(wloc) else failure
            else:
                return None
    except:
        return None

class ConnectionHandler(threading.Thread):
    def __init__(self, socClient, server, addr):
        threading.Thread.__init__(self)
        self.clientClosed = False
        self.targetClosed = True
        self.client = socClient
        self.client_buffer = ""
        self.server = server
        self.cl_addr = addr
        self.sshport = $Dropbear_Port1 # SSH PORT
        self.apacheport = $Apache_Port # APACHE PORT
        self.openvpnport = $OpenVPN_TCP_Port # OPENVPN PORT

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
        
        self.server.removeConn(self)
        print(self in self.server.threads)

    def log_time(self, msg):
        #print(time.strftime("[%H:%M:%S]"), msg)
        pass
    
    def proxy_apache(self, buff):
        (soc_family, soc_type, proto, _, address) = socket.getaddrinfo('127.0.0.1', self.apacheport)[0]
        apache = socket.socket(soc_family, soc_type, proto)
        apache.connect(address)
        apache.sendall(buff)
        apache_buff = apache.recv(recvbuff)
            
        # get rest of body
        resp = re.split(b"\r\n\r\n", apache_buff)
        header, body = resp[0], b"".join(resp[1:])

        remaining = int(self.findHeader("Content-Length", header.decode("utf-8"))) - len(body)
        body += apache.recv(remaining)

        self.client.sendall(header + b"\r\n\r\n" +  body)

    def run(self):
        sport=str(self.server.port)
        dport=str(self.server.dport)
        try:
            self.client_buffer = self.client.recv(recvbuff)
            buff = self.client_buffer
            
            hostPort = '127.0.0.1:'+str(self.server.dport)
            self.log_time("client: %s - server: %s - buff: %s" % (self.cl_addr, hostPort, buff))
            
            try:
                uhost = self.findHeader('Host', buff.decode('utf-8'))
                if uhost == "":
                    self.log_time(self.client.recv(recvbuff))
            except:
                pass

            uagent = self.findHeader('User-Agent', buff.decode('utf-8'))
            if uagent:     
                  self.proxy_apache(buff)
                  self.close()
                  return

            upgrade = self.findHeader('Upgrade', buff.decode('utf-8'))
            if upgrade == "":
                 self.client.send(success2)           
                 self.method_CONNECT(hostPort, self.openvpnport)
            else:
                if upgrade == "openvpn":
                    self.client.send(success)
                    self.method_CONNECT(hostPort, self.openvpnport)
                else:
                    self.client.send(success)
                    self.method_CONNECT(hostPort, self.sshport)
        except:
            pass
        finally:
            self.close()

    def findHeader(self, head, header):
        hdr={}
        for line in header.splitlines():
            ls=line.split(':')
            if len(ls) == 2:
                hdr[ls[0].strip()]=ls[1].strip()
        return hdr[head] if head in hdr else ""

    def connect_target(self, host, port):
        i = host.find(':')
        if i != -1:
            host = host[:i]
        
        (soc_family, soc_type, proto, _, address) = socket.getaddrinfo(host, port)[0]

        self.target = socket.socket(soc_family, soc_type, proto)
        self.target.setsockopt(socket.SOL_SOCKET, socket.TCP_NODELAY, 1)
        self.targetClosed = False
        self.target.connect(address)
        self.t_addr = address

    def method_CONNECT(self, path, port):
        self.connect_target(path, port)
        #self.client.send(success)
        self.client_buffer = ""
        self.doCONNECT()
    
    def doCONNECT(self):
        socs = [self.client, self.target]
        error = False
        count=0
        while True:
            (recv, _, err) = select.select(socs, [], socs, 3)
            if err:
                count+=1
                time.sleep(1)
            elif recv:
                for in_ in recv:
                    try:
                        data = in_.recv(recvbuff)
                        if data:
                            count=0
                            if in_ is self.target:
                                try:
                                    self.client.connect(self.cl_addr)
                                except:
                                    pass
                                self.client.send(data)
                            else:
                                try:
                                    self.target.connect(self.t_addr)
                                except Exception as e:
                                    pass
                                while data:
                                    byte = self.target.send(data)
                                    data = data[byte:]
                        else:
                            time.sleep(1)
                            count+=1
                            break
                    except Exception as e:
                        count+=1
                        print(f"{type(e).__name__}: {e}")
                else:
                    continue
                break

def main():
    pidx=str(os.getpid())
    pid=open(ploc+'/.pid', 'w')
    pid.write(pidx)
    pid.close()
    print("\033[0;34m="*8,"\033[1;32mPROXY SOCKS","\033[0;34m="*8,"\n\033[1;33m\033[1;32m")
    server = Server()
    server.start()
    print('PID:', pidx)
    print('\n'+"\033[0;34m="*11,"\033[1;32mTsholoVPN","\033[0;34m=\033[1;37m"*11,"\n")
    while True:
        try:
            time.sleep(2)
        except KeyboardInterrupt:
            server.close()
            print("\nCancelled...")
            exit()

if __name__ == "__main__":
    main()
Socks

# Fix For Debian 9
if [ $(cat /etc/debian_version) == '9.13' ]; then
  VERSION=9.13
echo -e "Updating Python3 This May Take  A While"
apt-get install build-essential zlib1g-dev libncurses5-dev libgdbm-dev libnss3-dev libssl-dev libreadline-dev libffi-dev curl libbz2-dev -y
wget $Python_Url
tar xf Python-$Python_Version.tar.xz
cd Python-$Python_Version
./configure --disable-tests
cd
make -C Python-$Python_Version -j8 EXTRATESTOPTS=--list-tests install
# creating a service for socks proxy debian 9
cat << service > /etc/systemd/system/socksproxy.service
[Unit]
Description=Socks Proxy
Wants=network.target
After=network.target
[Service]
Type=simple
ExecStart=/usr/bin/env python3.6 /etc/socksproxy/proxy.py
ExecStop=/bin/bash -c "kill -15 \`cat $loc/.pid\`"
[Install]
WantedBy=network.target
service
else
# creating a service
cat << service > /etc/systemd/system/socksproxy.service
[Unit]
Description=Socks Proxy
Wants=network.target
After=network.target
[Service]
Type=simple
ExecStart=/usr/bin/python3 /etc/socksproxy/proxy.py
ExecStop=/bin/bash -c "kill -15 \`cat $loc/.pid\`"
[Install]
WantedBy=network.target
service
fi

# start the service
systemctl daemon-reload
systemctl enable socksproxy
systemctl restart socksproxy
systemctl status --no-pager socksproxy

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
chmod -R 755 /etc/socksproxy/socksproxy.sh

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
status /var/www/html/stat/tcp.txt 1
myOpenVPNconf

cat <<'myOpenVPNconf2' > /etc/openvpn/server_udp.conf
# OpenVPN UDP
port OVPNUDP
management 127.0.0.1 Udp_Monitor_Port
proto udp
dev tun
ca /etc/openvpn/ca.crt
cert /etc/openvpn/TsholoVPNVPN.crt
key /etc/openvpn/TsholoVPNVPN.key
dh /etc/openvpn/dh2048.pem
username-as-common-name
client-cert-not-required
auth-user-pass-verify "/etc/openvpn/script/auth_vpn.sh" via-file # 
#client-connect /etc/openvpn/script/connect.sh
#client-disconnect /etc/openvpn/script/disconnect.sh
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

# OpenVPN Cert CA
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
chmod -R 755 /etc/openvpn/script
 
# Starting OpenVPN server
systemctl start openvpn@server_tcp
systemctl restart openvpn@server_tcp
systemctl status --no-pager openvpn@server_tcp
systemctl enable openvpn@server_tcp
systemctl start openvpn@server_udp
systemctl restart openvpn@server_udp
systemctl status --no-pager openvpn@server_udp
systemctl enable openvpn@server_udp
 
# Set Permission To Stat
chmod -R 755 /var/www/html/stat

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
#http_access allow server
#http_access allow checker
#http_access deny all
http_access allow all
forwarded_for off
via off
#request_header_access Host allow all
#request_header_access Content-Length allow all
#request_header_access Content-Type allow all
#request_header_access All deny all
hierarchy_stoplist cgi-bin ?
coredump_dir /var/spool/squid
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320
visible_hostname TsholoVPN.com
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

chmod -R 755 /etc/sshlogin/connection.php

echo "* * * * * root /usr/bin/php /etc/sshlogin/connection.php >/dev/null 2>&1" > /etc/cron.d/connection-ssh
echo "* * * * * root /bin/bash /etc/sshlogin/active.sh>/dev/null 2>&1"> /etc/cron.d/active-users
echo "* * * * * root /bin/bash /etc/sshlogin/inactive.sh >/dev/null 2>&1" > /etc/cron.d/inactive-users

# SSH to check online users on panel 
cat <<'Sshonline' > /etc/sshlogin/sshusers.sh
#!/bin/bash
#SSH USERS 
#BY TsholoVPN

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
chmod -R 755 /etc/sshlogin/sshusers.sh
/bin/bash /etc/sshlogin/sshusers.sh  >/dev/null 2>&1
chmod -R 755 /var/www/html/stat/ssh.txt

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

chmod -R 755 /etc/sshlogin/mysql.class.php

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

chmod -R 755 /etc/sshlogin/sshauth.sh
/bin/bash /etc/sshlogin/sshauth.sh  >/dev/null 2>&1
chmod -R 755 /etc/sshlogin/cronjob_ssh_task.php

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

chmod -R 755 /etc/sshlogin/set_multilogin_autokill_lib

# Webmin Configuration
sed -i '$ i\tsholo: acl adsl-client ajaxterm apache at backup-config bacula-backup bandwidth bind8 burner change-user cluster-copy cluster-cron cluster-passwd cluster-shell cluster-software cluster-useradmin cluster-usermin cluster-webmin cpan cron custom dfsadmin dhcpd dovecot exim exports fail2ban fdisk fetchmail file filemin filter firewall firewalld fsdump grub heartbeat htaccess-htpasswd idmapd inetd init inittab ipfilter ipfw ipsec iscsi-client iscsi-server iscsi-target iscsi-tgtd jabber krb5 ldap-client ldap-server ldap-useradmin logrotate lpadmin lvm mailboxes mailcap man mon mount mysql net nis openslp package-updates pam pap passwd phpini postfix postgresql ppp-client pptp-client pptp-server proc procmail proftpd qmailadmin quota raid samba sarg sendmail servers shell shorewall shorewall6 smart-status smf software spam squid sshd status stunnel syslog-ng syslog system-status tcpwrappers telnet time tunnel updown useradmin usermin vgetty webalizer webmin webmincron webminlog wuftpd xinetd' /etc/webmin/webmin.acl
sed -i '$ i\tsholo:x:0' /etc/webmin/miniserv.users
/usr/share/webmin/changepass.pl /etc/webmin tsholo 27422

# Some Cron Job
echo "* * * * * root /bin/bash /etc/sshlogin/set_multilogin_autokill_lib 1 >/dev/null 2>&1" >> "/etc/cron.d/set_multilogin_autokill_lib"
echo "* * * * * root /bin/bash /etc/sshlogin/sshusers.sh >/dev/null 2>&1" >> "/etc/cron.d/sshlogin"
echo "* * * * * root /bin/bash /usr/local/sbin/TsholoVPN-user-delete-expired &> /dev/null" >> "/etc/cron.d/user-delete-expired"

# Some Settings
sed -i "s|#SystemMaxUse=|SystemMaxUse=10M|g" /etc/systemd/journald.conf
sed -i "s|#SystemMaxFileSize=|SystemMaxFileSize=1M|g" /etc/systemd/journald.conf
systemctl restart systemd-journald

# Creating startup 1 script using cat eof tricks
cat <<'TsholoVPNz' > /etc/TsholoVPNstartup
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
TsholoVPNz

sed -i "s|MyTimeZone|$MyVPS_Time|g" /etc/TsholoVPNstartup
sed -i "s|DNS1|$Dns_1|g" /etc/TsholoVPNstartup
sed -i "s|DNS2|$Dns_2|g" /etc/TsholoVPNstartup
rm -rf /etc/sysctl.d/99*

 # Setting our startup script to run every machine boots 
cat <<'TsholoVPNx' > /etc/systemd/system/TsholoVPNstartup.service
[Unit] 
Description=/etc/TsholoVPNstartup
ConditionPathExists=/etc/TsholoVPNstartup

[Service] 
Type=forking 
ExecStart=/etc/TsholoVPNstartup start 
TimeoutSec=0
StandardOutput=tty 
RemainAfterExit=yes 
SysVStartPriority=99 

[Install] 
WantedBy=multi-user.target
TsholoVPNx

chmod +x /etc/TsholoVPNstartup
systemctl enable TsholoVPNstartup
systemctl start TsholoVPNstartup
cd

# Pull BadVPN Binary 64bit or 32bit
if [ "$(getconf LONG_BIT)" == "64" ]; then
 wget -O /usr/bin/badvpn-udpgw "https://github.com/tjay13/AutoScriptDebian9/blob/main/Tools/badvpn-udpgw64?raw=true"
else
 wget -O /usr/bin/badvpn-udpgw "https://github.com/tjay13/AutoScriptDebian9/blob/main/Tools/badvpn-udpgw?raw=true"
fi

# Change Permission to make it Executable
chmod +x /usr/bin/badvpn-udpgw
 
# Setting our startup script for badvpn
cat <<'TsholoVPNb' > /etc/systemd/system/badvpn.service
[Unit]
Description=badvpn tun2socks service
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/bin/badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 1000 --max-connections-for-client 10

[Install]
WantedBy=multi-user.target
TsholoVPNb

systemctl enable badvpn
systemctl start badvpn

# TCP BBR
brloc=/etc/modules-load.d/modules.conf
if [[ ! `cat $brloc` =~ "tcp_bbr" ]];then
modprobe tcp_bbr
echo tcp_bbr >> $brloc; fi

#Tweak for IPV4 TCP/UDP speed and maximize capability function Status: OFF
cd
mkdir -p /etc/TsholoVPN-script/others
echo "off" > /etc/TsholoVPN-script/others/tcptweaks
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

# V2RAY
wget -O /usr/local/v2-ui-linux.tar.gz "https://www.dropbox.com/s/gg3043jt5rumift/v2-ui-linux.tar.gz"
cd /usr/local/
tar zxvf v2-ui-linux.tar.gz
rm v2-ui-linux.tar.gz -f
cd v2-ui
chmod +x v2-ui bin/v2ray-v2-ui bin/v2ctl
cp -f v2-ui.service /etc/systemd/system/
cd

# Start V2-ui 
systemctl daemon-reload
systemctl start v2-ui
systemctl enable v2-ui
systemctl status --no-pager v2-ui

# download script
cd /usr/local/bin
wget -O premium-script.tar.gz "https://github.com/tjay13/AutoScriptDebian9/blob/main/Tools/premium-script.tar.gz?raw=true"
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
echo "SCRIPT BY TsholoVPN"
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
echo "   • SSL through Dropbear : [ON] : $Stunnel_Port1  " | tee -a log-install.txt | lolcat
echo "   • SSL through OpenSSH  : [ON] : $Stunnel_Port2" | tee -a log-install.txt | lolcat
echo "   • SSL through Openvpn  : [ON] : $Stunnel_Port3 " | tee -a log-install.txt | lolcat
echo "   • SSL through Websocket: [ON] : $Stunnel_Port4 " | tee -a log-install.txt | lolcat
echo "   • Websocket Socks Proxy: [ON] : $WsPort " | tee -a log-install.txt | lolcat
echo "   • BADVPN               : [ON] : 7300 " | tee -a log-install.txt | lolcat
echo "   • Additional SSHD Port : [ON] : $SSH_Port2" | tee -a log-install.txt | lolcat
echo "   • OCS Panel            : [ON] : http://$IPADDR:$Nginx_Port" | tee -a log-install.txt | lolcat
echo "   • Openvpn Monitoring   : [ON] : http://$IPADDR:$Openvpn_Monitoring" | tee -a log-install.txt | lolcat
echo "   • V2ray Panel          : [ON] : http://$IPADDR:65432 " | tee -a log-install.txt | lolcat

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
figlet TsholoVPN Script -c | lolcat
echo ""
echo "       Installation Complete! System need to reboot to apply all changes! "
read -p "                      Press Enter to reboot..."
reboot
