#!/bin/bash
# Script by TsholoVPN

# requirement
apt-get -y update
apt-get -y install curl wget

# initializing IP
export DEBIAN_FRONTEND=noninteractive
OS=`uname -m`;
MYIP=$(wget -qO- ipv4.icanhazip.com);
MYIP2="s/xxxxxxxxx/$MYIP/g";

# configure rc.local
cat <<EOF >/etc/rc.local
#!/bin/sh -e
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

# set time GMT +2
ln -fs /usr/share/zoneinfo/Africa/Johannesburg /etc/localtime

# disable se linux
echo 0 > /selinux/enforce
sed -i 's/SELINUX=enforcing/SELINUX=disabled/g'  /etc/sysconfig/selinux


# set locale
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config

# update
apt-get update;

# install screenfetch
cd
wget -O /usr/bin/screenfetch "https://raw.githubusercontent.com/tjay13/AutoScriptDebian9/main/Res/Screenfetch/screenfetch"
chmod +x /usr/bin/screenfetch
echo "clear" >> .profile
echo "screenfetch" >> .profile

# install webserver
apt-get install apache2 -y
mkdir -p /var/www/html/status
chmod -R 755 /var/www/html
sed -i 's/Listen 80/Listen 81/g' /etc/httpd/conf/httpd.conf
service apache2 restart

# install openvpn
apt-get -y install openvpn && apt-get -y install unzip
wget -O /etc/openvpn/openvpn.zip "https://raw.githubusercontent.com/tjay13/AutoScriptDebian9/main/Res/OpenVPN/openvpn-debian.zip"
cd /etc/openvpn/
unzip openvpn.zip
chmod -R 755 /etc/openvpn
sed -i $MYIP2 /etc/openvpn/server.conf

# Deb9 OVPN Bug Workaround
mkdir -p /dev/net
mknod /dev/net/tun c 10 200
chmod 600 /dev/net/tun

# Deb9 OVPN Bug2 Workaround 
sed -i 's@LimitNPROC=10@@g' /lib/systemd/system/openvpn@.service

# Restart openvpn
systemctl daemon-reload
systemctl start openvpn@server
systemctl enable openvpn@server
systemctl status --no-pager openvpn@server

# set ipv4 forward
echo 1 > /proc/sys/net/ipv4/ip_forward
sed -i 's|#net.ipv4.ip_forward=1|net.ipv4.ip_forward=1|' /etc/sysctl.conf

# install badvpn
cd
wget -O /usr/bin/badvpn-udpgw "https://raw.githubusercontent.com/tjay13/AutoScriptDebian9/main/Res/BadVPN/badvpn-udpgw64"
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 1000 --max-connections-for-client 10' /etc/rc.local
chmod +x /usr/bin/badvpn-udpgw
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 1000 --max-connections-for-client 10

# setting port ssh
sed -i '/#Port 22/a Port 143' /etc/ssh/sshd_config
sed -i '/#Port 22/a Port  90' /etc/ssh/sshd_config
sed -i 's/#Port 22/Port  22/g' /etc/ssh/sshd_config
/etc/init.d/ssh restart

# install dropbear
apt-get -y install dropbear
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=442/g' /etc/default/dropbear
sed -i 's/DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-p 109 -p 110 -p 82"/g' /etc/default/dropbear
echo "/bin/false" >> /etc/shells
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
visible_hostname tsholovpn.tk
END
sed -i $MYIP2 /etc/squid/squid.conf;
service squid restart

# install fail2ban
apt-get -y install fail2ban

# install ddos deflate
cd
apt-get -y install dnsutils dsniff
wget https://raw.githubusercontent.com/tjay13/AutoScriptDebian9/main/Res/DDOS/ddos-deflate-master.zip
unzip ddos-deflate-master.zip
cd ddos-deflate-master
./install.sh
rm -rf /root/ddos-deflate-master.zip

# banner /etc/banner
wget -O /etc/banner "https://raw.githubusercontent.com/tjay13/AutoScriptDebian9/main/Res/Other/banner"
sed -i 's@#Banner none@Banner /etc/banner@g' /etc/ssh/sshd_config
sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/banner"@g' /etc/default/dropbear

# xml parser
cd
apt-get install -y libxml-parser-perl

# download script
cd
wget https://raw.githubusercontent.com/tjay13/AutoScriptDebian9/main/Res/Menu/install-premiumscript.sh -O - -o /dev/null|sh

# finishing
cd
/etc/init.d/apache2 restart
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
service squid restart
/etc/init.d/webmin restart

# clearing history
rm -rf ~/.bash_history && history -c
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
echo "------------------------- Configuration Setup Server ------------------------"
echo "                    Copyright TsholoVPN 2021 All rights Reserved             "
echo "                             Created By TsholoVPN                            "
echo "-----------------------------------------------------------------------------"
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
echo "   - OpenVPN     : TCP 443"  | tee -a log-install.txt
echo "   - OpenSSH     : 22, 90, 143"  | tee -a log-install.txt
echo "   - Stunnel4    : 444"  | tee -a log-install.txt
echo "   - Dropbear    : 80, 109, 110, 442"  | tee -a log-install.txt
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
echo "----------------------- Script By TsholoVPN) --------------------------------"
echo "                              Script By TsholoVPN                            "
echo "-----------------------------------------------------------------------------"
