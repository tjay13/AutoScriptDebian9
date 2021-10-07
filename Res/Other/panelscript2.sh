#!/bin/bash
#BY DEEKAY VPN
#Setup Panel On VPS
clear
echo "INSTALLING VPN WEB PANEL"
sleep 1
echo Setup By Deekay VPN...
sleep 0.5
cd

# Database Info
DatabaseName='vpnquest1_dbase'
DatabaseUser='vpnquest1_user'
DatabasePass='s+(WT#r4CaB&'

# Install Required Packages
apt-get -y install apache2 php7.0 php7.0-fpm php7.0-mcrypt php7.0-pdo php7.0-sqlite3 php7.0-mbstring php7.0-curl php7.0-cli php7.0-mysql php7.0-gd php7.0-intl php7.0-xsl php7.0-xml php7.0-zip php7.0-xmlrpc libapache2-mod-php7.0

# Configure Some Settings
sed -i 's/;cgi.fix_pathinfo=1/cgi.fix_pathinfo=0/g;/display_errors =/{s/Off/On/g}' /etc/php/7.0/fpm/php.ini
sed -i '/;session.save_path =/{s/;//g}' /etc/php/7.0/fpm/php.ini

# Create Panel Database Using Info
so2=$(expect -c "
spawn mysql -u root -p; sleep 3
expect \"\";  sleep 3; send \"$DatabasePass\r\"
expect \"\";  sleep 3; send \"CREATE DATABASE IF NOT EXISTS $DatabaseName;\r\"
expect \"\";  sleep 3; send \"GRANT ALL PRIVILEGES ON *.* TO '$DatabaseName'@'localhost' IDENTIFIED BY '$DatabasePass'; \r\"
expect \"\";  sleep 3; send \"FLUSH PRIVILEGES;\r\"
expect \"\";  sleep 3; send \"EXIT;\r\"
expect eof; ")
echo "$so2"

# Import Database
wget -qO- https://www.dropbox.com/s/xu5owk990w1o108/deekay_panel.sql | mysql -uroot $DatabaseName 2> /dev/null

# Clear Web Folder And Download Panel
rm -f /var/www/html/*
cd /var/www/html
wget -qO- https://www.dropbox.com/s/30jme1sv4hsoqek/deekay_panel.tar.gz | tar xz

# Remove Default Cronjobs
cd /etc/cron.d
rm -f cronjob-duration
rm -f cronjob-server
cd

# Setting Panel Cronjob 
cat << cron > /etc/cron.d/panel-cronjobs
* * * * * root /usr/bin/php /var/www/html/db/cronjob/bandwidth_reset.php
* * * * * root /usr/bin/php /var/www/html/db/cronjob/cron_durations_vpnmoto.php 
0 1 * * * root /usr/bin/php /var/www/html/db/cronjob/cron_servers.php
30 * * * * root /usr/bin/php /var/www/html/db/cronjob/cron_unsuspend.php
cron

# Some Permission Settings
touch cdn/udel.txt 2> /dev/null
chmod -R a+wrx *
cd

# Enable & Disable Required Apache Mods
a2dismod mpm_event
a2enmod php7.0
a2enmod rewrite
a2enmod proxy_fcgi setenvif
a2enconf php7.0-fpm

# Apache Web Server Settings
cd /etc/apache2
ln -sf /etc/apache2/mods-available/headers.load mods-enabled/headers.load
rm -f sites-enabled/*
cat << deekay > sites-enabled/panel.conf
<VirtualHost *:80>
    ServerName deekay-vpn.cf
    ServerAlias www.deekay-vpn.cf
    ServerAdmin DEEKAY
    DocumentRoot /var/www/html
    
    <Directory "/var/www/html">
        Order allow,deny
        AllowOverride All
        Allow from all
        Require all granted
    </Directory>
    #ErrorLog \${APACHE_LOG_DIR}/error.log
    #CustomLog \${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
deekay

# Restart Web Server Packages 
cd
service apache2 restart
service php7.0-fpm restart
service mysql restart

# Installation Complete
clear
cd
echo " "
echo " "
echo " VPN WEB PANEL SUCCESSFULLY INSTALLED!"
echo "SCRIPT BY DOPE~KID"
rm -f /root/panelscript2.sh