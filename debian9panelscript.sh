#!/bin/bash
# Created by https://www.facebook.com/joash.singh.90
# Script by Dope~kid

# requirement
apt-get -y update && apt-get -y upgrade
apt-get -y install curl wget

# initializing IP
export DEBIAN_FRONTEND=noninteractive
OS=`uname -m`;
MYIP=$(wget -qO- ipv4.icanhazip.com);
MYIP2="s/xxxxxxxxx/$MYIP/g";

# Stunnel Cert Info
country=ZA
state=Africa
locality=Durban
organization=DeekayVPN
organizationalunit=DeekayVPN
commonname=DeekayVPN
email=deekayvpn@gmail.com

# Mysql Database Info
DatabasePass='D03Ekid2021'
DatabaseName='dopekid_vpn18'

# configure rc.local
cat <<EOF >/etc/rc.local
#!/bin/sh -e
ln -fs /usr/share/zoneinfo/Africa/Johannesburg /etc/localtime
export DEBIAN_FRONTEND=noninteractive
exit 0
EOF
chmod +x /etc/rc.local
systemctl daemon-reload
systemctl start rc-local

# disable ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

# add DNS server ipv4
echo "nameserver 8.8.8.8" > /etc/resolv.conf
echo "nameserver 8.8.4.4" >> /etc/resolv.conf
sed -i '$ i\echo "nameserver 8.8.8.8" > /etc/resolv.conf' /etc/rc.local
sed -i '$ i\echo "nameserver 8.8.4.4" >> /etc/resolv.conf' /etc/rc.local

# remove unused
apt-get -y --purge remove samba*;
apt-get -y --purge remove apache2*;
apt-get -y --purge remove sendmail*;
apt-get -y --purge remove bind9*;

# set repo
wget "http://www.dotdeb.org/dotdeb.gpg"
cat dotdeb.gpg | apt-key add -;rm dotdeb.gpg

# set time GMT +2
ln -fs /usr/share/zoneinfo/Africa/Johannesburg /etc/localtime

# set locale
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config

# update
apt-get update; apt-get -y upgrade;

# install webserver extensions
apt-get -y install nginx
apt-get -y install php7.0-fpm php7.0-cli libssh2-1 php-ssh2 php7.0 php7.0-mysql

# install essential package
apt-get -y install nano iptables-persistent dnsutils screen whois ngrep unzip tar zip
apt-get -y install build-essential 
apt-get -y install libio-pty-perl libauthen-pam-perl apt-show-versions libnet-ssleay-perl shared-mime-info

# install screenfetch
cd
wget -O /usr/bin/screenfetch "https://www.dropbox.com/s/na1f4maovye2xq0/screenfetch"
chmod +x /usr/bin/screenfetch
echo "clear" >> .profile
echo "screenfetch" >> .profile

# install webserver
cd
rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default
wget -O /etc/nginx/nginx.conf "https://www.dropbox.com/s/ks0qw6p1bx9ytff/nginx.conf"
wget -O /etc/nginx/conf.d/vps.conf "https://www.dropbox.com/s/f9ygxijg948yet6/vps.conf"
wget -O /etc/nginx/conf.d/monitoring.conf "https://www.dropbox.com/s/38xvvcacdzmz2mj/monitoring.conf"
mkdir -p /home/vps/public_html
wget -O /home/vps/public_html/index.php "https://www.dropbox.com/s/hdt2kz74n6803f3/index.php"
sed -i 's/listen = \/run\/php\/php7.0-fpm.sock/listen = 127.0.0.1:9000/g' /etc/php/7.0/fpm/pool.d/www.conf
service php7.0-fpm restart
service nginx restart

# Setup Openvpn
apt-get -y install openvpn telnet
if [[ ! -e /etc/openvpn ]]; then
mkdir -p /etc/openvpn
fi
rm -rf /etc/openvpn/*

# Install openvpn
wget -O /etc/openvpn/openvpn.tar "https://www.dropbox.com/s/6wyq0knoxhwfmvw/openvpn-debian.tar"
cd /etc/openvpn/
tar xf openvpn.tar

# openvpn config
cat > /home/vps/public_html/Dopekid.ovpn <<-END
# OpenVPN Configuration By Dopekid

client
dev tun
proto tcp
remote $MYIP 1194
http-proxy $MYIP 8080
nobind
persist-key
persist-tun
resolv-retry infinite
auth-user-pass
verb 3
chiper AES-128 -CBC
auth SHA1
setenv CLIENT_CERT 0
reneg-sec 0
route $MYIP 255.255.255.255 net_gateway

END
echo '<ca>' >> /home/vps/public_html/Dopekid.ovpn
cat /etc/openvpn/keys/ca.crt >> /home/vps/public_html/Dopekid.ovpn
echo '</ca>' >> /home/vps/public_html/Dopekid.ovpn
cd /home/vps/public_html/
tar -czf /home/vps/public_html/DopekidVPN.tar.gz Dopekid.ovpn
tar -czf /home/vps/public_html/Dopekid.tar.gz Dopekid.ovpn
cd

# Deb9 OVPN Bug Workaround
mkdir -p /dev/net
mknod /dev/net/tun c 10 200
chmod 600 /dev/net/tun

# Deb9 OVPN Bug2 Workaround 
sed -i 's@LimitNPROC=10@@g' /lib/systemd/system/openvpn@.service

# Create Openvpn Stat Parts
mkdir /var/www/html/stat
chmod -R 777 /var/www/html/stat

# Setting Permissions
chmod +x /etc/openvpn/script/config.sh
chmod +x /etc/openvpn/script/premium.sh
chmod +x /etc/openvpn/script/connectpremium.sh
chmod +x /etc/openvpn/script/disconnectpremium.sh

# Restarting Openvpn
systemctl daemon-reload
systemctl start openvpn@server
systemctl enable openvpn@server
systemctl status --no-pager openvpn@server

# Give Openvpn Status Permission
chmod 777 /var/www/html/stat/tcp.txt

# Setting UFW
apt-get install ufw
ufw allow ssh
ufw allow 443/tcp
sed -i 's|DEFAULT_INPUT_POLICY="DROP"|DEFAULT_INPUT_POLICY="ACCEPT"|' /etc/default/ufw
sed -i 's|DEFAULT_FORWARD_POLICY="DROP"|DEFAULT_FORWARD_POLICY="ACCEPT"|' /etc/default/ufw
ufw status
ufw disable

# set ipv4 forward
echo 1 > /proc/sys/net/ipv4/ip_forward
sed -i 's|#net.ipv4.ip_forward=1|net.ipv4.ip_forward=1|' /etc/sysctl.conf

# OpenVPN monitoring
apt-get install -y gcc libgeoip-dev python-virtualenv python-dev geoip-database-extra uwsgi uwsgi-plugin-python
wget -O /srv/openvpn-monitor.tar "https://www.dropbox.com/s/ctir8hzz21i8zbm/openvpn-monitor.tar"
cd /srv
tar xf openvpn-monitor.tar
cd openvpn-monitor
virtualenv .
. bin/activate
pip install -r requirements.txt
wget -O /etc/uwsgi/apps-available/openvpn-monitor.ini "https://www.dropbox.com/s/mz26bgge83yo7ji/openvpn-monitor.ini"
ln -s /etc/uwsgi/apps-available/openvpn-monitor.ini /etc/uwsgi/apps-enabled/
rm /srv/openvpn-monitor.tar

# GeoIP For OpenVPN Monitor
mkdir -p /var/lib/GeoIP
wget -O /var/lib/GeoIP/GeoLite2-City.mmdb.gz "https://www.dropbox.com/s/nd76t3zxvdwvk79/GeoLite2-City.mmdb.gz"
gzip -d /var/lib/GeoIP/GeoLite2-City.mmdb.gz

# install badvpn
cd
wget -O /usr/bin/badvpn-udpgw "https://www.dropbox.com/s/lfqnoh2zwy98x2w/badvpn-udpgw64"
chmod +x /usr/bin/badvpn-udpgw

# badvpn service
wget -O /etc/systemd/system/badvpn.service "https://www.dropbox.com/s/p44ths5rwzjxqss/badvpn.service"

# enable and start badvpn
systemctl daemon-reload
systemctl enable badvpn.service
systemctl start badvpn.service
systemctl restart badvpn.service

# setting port ssh
sed -i '/#Port 22/a Port 143' /etc/ssh/sshd_config
sed -i '/#Port 22/a Port  90' /etc/ssh/sshd_config
sed -i 's/#Port 22/Port  22/g' /etc/ssh/sshd_config
/etc/init.d/ssh restart

# install dropbear
apt-get -y install dropbear
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=442/g' /etc/default/dropbear
sed -i 's/DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-p 109 -p 110 -p 81"/g' /etc/default/dropbear
echo "/bin/false" >> /etc/shells
perl -pi -e 's/dropbear_2016.74/deekayvpn_2021.7/g' /usr/sbin/dropbear
/etc/init.d/dropbear restart

# install squid
apt-get -y install squid
cat > /etc/squid/squid.conf <<-END
acl server dst xxxxxxxxx/32 localhost
acl checker src 188.93.95.137
acl ports_ port 14 22 53 21 8080 8081 8000 3128 1193 1194 440 441 442 443 80
http_port 3128
http_port 8000
http_port 8080
http_port 8888
access_log none
cache_log /dev/null
logfile_rotate 0
http_access allow server
http_access allow checker
http_access deny all
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
visible_hostname dopekid.cf
END
sed -i $MYIP2 /etc/squid/squid.conf;
service squid restart

# V2-ui Panel Setup
wget -O /usr/local/v2-ui-linux.tar.gz "https://www.dropbox.com/s/6yoi0gn1vcx6na9/v2-ui-linux.tar.gz"
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

# installing webmin
wget "https://download.webmin.com/download/repository/pool/contrib/w/webmin/webmin_1.801_all.deb"
dpkg --install webmin_1.801_all.deb;
apt-get -y -f install;
sed -i 's/ssl=1/ssl=0/g' /etc/webmin/miniserv.conf
rm /root/webmin_1.801_all.deb
service webmin restart

# Install Stunnel
apt-get -y install stunnel4
cat > /etc/stunnel/stunnel.conf <<-END
cert = /etc/stunnel/stunnel.pem
client = no
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
TIMEOUTclose = 0

[dropbear]
accept = 444
connect = 127.0.0.1:442
END

# Restart Stunnel
sed -i '/ENABLED=/{s/0/1/g}' /etc/init.d/stunnel4
sed -i '/ENABLED=/{s/0/1/g}' /etc/default/stunnel4

# Make Stunnel Certificate 
openssl genrsa -out key.pem 2048
openssl req -new -x509 -key key.pem -out cert.pem -days 1095 \
-subj "/C=$country/ST=$state/L=$locality/O=$organization/OU=$organizationalunit/CN=$commonname/emailAddress=$email"
cat key.pem cert.pem >> /etc/stunnel/stunnel.pem

# Restarting Stunnel
service stunnel4 restart
systemctl daemon-reload

# install fail2ban
apt-get -y install jq fail2ban
systemctl enable fail2ban &> /dev/null
systemctl start fail2ban &> /dev/null
systemctl enable cron

# install ddos deflate
cd
apt-get -y install dnsutils dsniff net-tools tcpdump grepcidr
wget https://www.dropbox.com/s/0i5ohkqwm8127si/ddos-deflate-master.zip
unzip ddos-deflate-master.zip
cd ddos-deflate-master
./install.sh
rm -rf /root/ddos-deflate-master.zip

# banner /etc/banner
wget -O /etc/banner "https://www.dropbox.com/s/133dy7jj2l07zef/banner"
sed -i 's@#Banner none@Banner /etc/banner@g' /etc/ssh/sshd_config
sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/banner"@g' /etc/default/dropbear

# Setup Mysql
apt -y install expect mysql-server lsb-release apt-transport-https ca-certificates lsb-release libdbi-perl libecap3

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

# Setting SSH To Work With Panel
mkdir /usr/sbin/kpn
wget -O /usr/sbin/kpn/connection.php "https://www.dropbox.com/s/tn8mp7841mf66ej/connection.php"
chmod -R 777 /usr/sbin/kpn/connection.php

# Webmin Configuration
sed -i '$ i\dope: acl adsl-client ajaxterm apache at backup-config bacula-backup bandwidth bind8 burner change-user cluster-copy cluster-cron cluster-passwd cluster-shell cluster-software cluster-useradmin cluster-usermin cluster-webmin cpan cron custom dfsadmin dhcpd dovecot exim exports fail2ban fdisk fetchmail file filemin filter firewall firewalld fsdump grub heartbeat htaccess-htpasswd idmapd inetd init inittab ipfilter ipfw ipsec iscsi-client iscsi-server iscsi-target iscsi-tgtd jabber krb5 ldap-client ldap-server ldap-useradmin logrotate lpadmin lvm mailboxes mailcap man mon mount mysql net nis openslp package-updates pam pap passwd phpini postfix postgresql ppp-client pptp-client pptp-server proc procmail proftpd qmailadmin quota raid samba sarg sendmail servers shell shorewall shorewall6 smart-status smf software spam squid sshd status stunnel syslog-ng syslog system-status tcpwrappers telnet time tunnel updown useradmin usermin vgetty webalizer webmin webmincron webminlog wuftpd xinetd' /etc/webmin/webmin.acl
sed -i '$ i\dope:x:0' /etc/webmin/miniserv.users
/usr/share/webmin/changepass.pl /etc/webmin dope 12345

# Setting IPtables
cat > /etc/iptables.up.rules <<-END
*nat
:PREROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -j SNAT --to-source xxxxxxxxx
-A POSTROUTING -o eth0 -j MASQUERADE
-A POSTROUTING -s 192.168.100.0/24 -o eth0 -j MASQUERADE
-A POSTROUTING -s 192.168.10.0/24 -o eth0 -j MASQUERADE
COMMIT
*filter
:INPUT ACCEPT [19406:27313311]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [9393:434129]
:fail2ban-ssh - [0:0]
-A FORWARD -i eth0 -o ppp0 -m state --state RELATED,ESTABLISHED -j ACCEPT
-A FORWARD -i ppp0 -o eth0 -j ACCEPT
-A INPUT -p tcp -m multiport --dports 22 -j fail2ban-ssh
-A INPUT -p ICMP --icmp-type 8 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 53 -j ACCEPT
-A INPUT -p tcp --dport 22  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 80  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 80  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 8888  -m state --state NEW -j ACCEPT
-A INPUT -p udp --dport 8888  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 142  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 143  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 109  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 110  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 443  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 1194  -m state --state NEW -j ACCEPT
-A INPUT -p udp --dport 1194  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 1732  -m state --state NEW -j ACCEPT
-A INPUT -p udp --dport 1732  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 3128  -m state --state NEW -j ACCEPT
-A INPUT -p udp --dport 3128  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 7300  -m state --state NEW -j ACCEPT
-A INPUT -p udp --dport 7300  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 8000  -m state --state NEW -j ACCEPT
-A INPUT -p udp --dport 8000  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 8080  -m state --state NEW -j ACCEPT
-A INPUT -p udp --dport 8080  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 10000  -m state --state NEW -j ACCEPT
-A fail2ban-ssh -j RETURN
COMMIT
*raw
:PREROUTING ACCEPT [158575:227800758]
:OUTPUT ACCEPT [46145:2312668]
COMMIT
*mangle
:PREROUTING ACCEPT [158575:227800758]
:INPUT ACCEPT [158575:227800758]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [46145:2312668]
:POSTROUTING ACCEPT [46145:2312668]
COMMIT
END
sed -i '$ i\iptables-restore < /etc/iptables.up.rules' /etc/rc.local
sed -i $MYIP2 /etc/iptables.up.rules;
iptables-restore < /etc/iptables.up.rules

# xml parser
cd
apt-get install -y libxml-parser-perl

# download script
wget https://www.dropbox.com/s/b8u2zz66dsg4j8a/install-premiumscript.sh -O - -o /dev/null|sh

# finishing
chown -R www-data:www-data /home/vps/public_html
chown -R mysql:mysql /var/lib/mysql/
chmod -R 777 /var/lib/mysql/
/etc/init.d/nginx restart
/etc/init.d/openvpn restart
/etc/init.d/cron restart
/etc/init.d/ssh restart
/etc/init.d/dropbear restart
/etc/init.d/fail2ban restart
/etc/init.d/stunnel4 restart
service php7.0-fpm restart
service uwsgi restart
systemctl daemon-reload
systemctl restart v2-ui
systemctl restart mysql
systemctl restart badvpn
service squid restart
/etc/init.d/webmin restart

# clearing history
rm -f ~/.bash_history && history -c
echo "unset HISTFILE" >> /etc/profile

# remove unnecessary files
apt -y autoremove
apt -y autoclean
apt -y clean

# info
clear
echo " "
echo "INSTALLATION COMPLETE!"
echo " "
echo "------------------------ Configuration Setup Server -----------------------"
echo "                    Copyright https://t.me/Dopekidfreenet                  "
echo "                             Created By Dope~kid                           "
echo "---------------------------------------------------------------------------"
echo ""  | tee -a log-install.txt
echo "Server Information"  | tee -a log-install.txt
echo "   - Timezone    : Africa/Johannesburg (GMT +2)"  | tee -a log-install.txt
echo "   - Fail2Ban    : [ON]"  | tee -a log-install.txt
echo "   - Dflate      : [ON]"  | tee -a log-install.txt
echo "   - IPtables    : [ON]"  | tee -a log-install.txt
echo "   - Auto-Reboot : [OFF]"  | tee -a log-install.txt
echo "   - IPv6        : [OFF]"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "Application & Port Information"  | tee -a log-install.txt
echo "   - OpenVPN     : TCP 1194"  | tee -a log-install.txt
echo "   - OpenSSH     : 22, 90, 143"  | tee -a log-install.txt
echo "   - Stunnel4    : 444"  | tee -a log-install.txt
echo "   - Dropbear    : 81, 109, 110, 442"  | tee -a log-install.txt
echo "   - Squid Proxy : 3128, 8000, 8080, 8888"  | tee -a log-install.txt
echo "   - Badvpn      : 7300"  | tee -a log-install.txt
echo "   - Nginx       : 85"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "Server Tools"  | tee -a log-install.txt
echo "   - htop"  | tee -a log-install.txt
echo "   - iftop"  | tee -a log-install.txt
echo "   - mtr"  | tee -a log-install.txt
echo "   - nethogs"  | tee -a log-install.txt
echo "   - screenfetch"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "Premium Script Information"  | tee -a log-install.txt
echo "   To display list of commands: menu"  | tee -a log-install.txt
echo "   V2ray panel password and username: admin"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "   Explanation of scripts and VPS setup" | tee -a log-install.txt
echo "   follow this link: https://t.me/DopekidFreeNet/"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "Important Information"  | tee -a log-install.txt
echo "   - Download Config OpenVPN : http://$MYIP:85/Dopekid.ovpn"  | tee -a log-install.txt
echo "   - Mirror (*.tar.gz)       : http://$MYIP:85/DopekidVPN.tar.gz"  | tee -a log-install.txt
echo "   - Simple Panel            : http://$MYIP:85/"  | tee -a log-install.txt
echo "   - Openvpn Monitor         : http://$MYIP:89/"  | tee -a log-install.txt
echo "   - V2ray Panel             : http://$MYIP:65432/"  | tee -a log-install.txt
echo "   - Webmin                  : http://$MYIP:10000/"  | tee -a log-install.txt
echo "   - Installation Log        : cat /root/log-install.txt"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "---------------- Script By Dope~kid(fb.com/joash.singh.90) ----------------"
echo "                              Script By Dope~kid                           "
echo "---------------------------------------------------------------------------"
rm -f /root/debian9panelscript.sh
