#!/bin/bash
# Version: 0.4.r2
export DEBIAN_FRONTEND=noninteractive
history -c && rm -rf ~/.bash_history
# Check VPS Is Debian
source /etc/os-release
if [[ "$ID" != 'debian' ]]; then
echo -e "[\e[1;31mError\e[0m] This script is for Debian only, exiting..." 
exit 1
fi

if [[ $EUID -ne 0 ]];then
echo -e "[\e[1;31mError\e[0m] This script must be run as root, exiting..."
exit 1
fi

# Gather input
echo -e " To exit the script, kindly Press \e[1;32mCRTL\e[0m key together with \e[1;32mC\e[0m"
echo -e ""
echo -e " Choose VPN Server installation type:"
echo -e " [1] Premium Server"
echo -e " [2] VIP Server"
echo -e " [3] Private Server"
until [[ "$opts" =~ ^[1-3]$ ]]; do
read -rp " Choose from [1-3]: " -e opts
done

# Script name
MyScriptName='TsholoVPN Premium Script'
VPN_Owner='TsholoVPN'
VPN_Name='TsholoVPN'
Filename_alias='tsholovpn'

# Server local time
MyVPS_Time='Africa/Johannesburg'

# OpenSSH Ports
SSH_Port1='22'
SSH_Port2='109'

# Dropbear Ports
Dropbear_Port1='442'
Dropbear_Port2='445'

# Stunnel Ports
Stunnel_Port1='143' # through Dropbear
Stunnel_Port2='444' # through OpenSSH
Stunnel_Port3='441' # through OpenVPN
Stunnel_Port4='443' # through Web Socket

# OpenVPN Ports
OpenVPN_TCP_Port='1194'
OpenVPN_UDP_Port='9019'

# Squid Ports
Squid_Port1='8080'
Squid_Port2='3128'
Squid_Port3='60000'

# Nginx port
Nginx_Port='85'

# Apache Port
Apache_Port='80'

# Monitor Ports
MGMT_TCP_PORT='5555'
MGMT_UDP_PORT='5556'
Monitor_Port='5000'

# Websocket Vars
WsPort='8880'
WsConnectPort='22'
WsResponse='HTTP/1.1 101 Switching Protocols\r\n\r\n'

# V2Ray Vars
V2ray_Port1='8443' # through vmess tls
V2ray_Port2='2082' # through vmess none tls
V2ray_Port3='2053' # through vless tls
V2ray_Port4='2083' # through vless none tls
UUID='37fb4c33-c93d-4274-9334-716a7be713bb'
domain='dexter.wtb-crackers.tk'

# Database Info
DatabaseHost='185.61.137.174';
DatabaseName='vpnquest1_dbase';
DatabaseUser='vpnquest1_user';
DatabasePass='s+(WT#r4CaB&';
DatabasePort='3306';

# Apache Directory
web=/var/www/html

# Get Public IP
IPADDR="$( wget -qO- ipv4.icanhazip.com)"

# Update VPS
APT="apt-get --allow-unauthenticated -y"
$APT update
yes | $APT upgrade

systemctl stop apache2
$APT install dropbear openvpn stunnel4 squid python3 apt-transport-https software-properties-common gnupg2 ca-certificates curl nginx fail2ban mariadb-server

# Removing Unnecessary packages
$APT remove --purge ufw firewalld
$APT autoremove

# Configure SSH
mv /etc/ssh/sshd_config /etc/ssh/sshd-config-old
cat << MySSHConfig > /etc/ssh/sshd_config
Port $SSH_Port1
Port $SSH_Port2
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
ClientAliveCountMax 2
Banner /etc/banner
AcceptEnv LANG LC_*
Subsystem   sftp  /usr/lib/openssh/sftp-server
MySSHConfig

# Creating Banner Message
ipadd=$(wget -qO- ipv4.icanhazip.com);
geoip=$(geoiplookup $ipadd | cut -d : -f 2);
cat << banner > /etc/banner
<br><font color="blue"><b>Thank you for Using TsholoVPN</b><br></font><br>
<br><font color="red"><b> Location Server: $geoip</b></font><br>
banner

# SSH Fixes
sed -i '/password\s*requisite\s*pam_cracklib.s.*/d;s/use_authtok //g' /etc/pam.d/common-password
sed -i '/\/bin\/false/d' /etc/shells
sed -i '/\/usr\/sbin\/nologin/d' /etc/shells
echo '/bin/false' >> /etc/shells
echo '/usr/sbin/nologin' >> /etc/shells
systemctl restart ssh

# Install Dropbear
mv /etc/default/dropbear /etc/default/dropbear-old
cat << MyDropbear > /etc/default/dropbear
NO_START=0
DROPBEAR_PORT=$Dropbear_Port1
DROPBEAR_EXTRA_ARGS="-p $Dropbear_Port2"
DROPBEAR_BANNER="/etc/banner"
DROPBEAR_RSAKEY="/etc/dropbear/dropbear_rsa_host_key"
DROPBEAR_DSSKEY="/etc/dropbear/dropbear_dss_host_key"
DROPBEAR_ECDSAKEY="/etc/dropbear/dropbear_ecdsa_host_key"
DROPBEAR_RECEIVE_WINDOW=65536
MyDropbear
systemctl restart dropbear

# Install Stunnel
StunnelDir=$(ls /etc/default | grep stunnel | head -n1)
cat << MyStunnelD > /etc/default/stunnel4
ENABLED=1
FILES="/etc/stunnel/*.conf"
OPTIONS=""
BANNER="/etc/banner"
PPP_RESTART=0
# RLIMITS="-n 4096 -d unlimited"
RLIMITS=""
MyStunnelD
sed -i '/ENABLED=/{s/0/1/g}' /etc/init.d/stunnel4
rm -rf /etc/stunnel/*

# Create SSL Certs
openssl req -new -x509 -days 9999 -nodes -subj "/C=PH/ST=NCR/L=Manila/O=$MyScriptName/OU=$MyScriptName/CN=$MyScriptName" -out /etc/stunnel/stunnel.pem -keyout /etc/stunnel/stunnel.pem &> /dev/null

# Creating Stunnel Config
cat << MyStunnelC > /etc/stunnel/stunnel.conf
pid = /var/run/stunnel.pid
cert = /etc/stunnel/stunnel.pem
client = no
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
TIMEOUTclose = 0

[dropbear]
accept = $Stunnel_Port1
connect = 127.0.0.1:$Dropbear_Port1

[openssh]
accept = $Stunnel_Port2
connect = 127.0.0.1:$SSH_Port1

[openvpn]
accept = $Stunnel_Port3
connect = 127.0.0.1:$OpenVPN_TCP_Port

[websocket]
accept = $Stunnel_Port4
connect = 127.0.0.1:$WsPort
MyStunnelC

# Restarting Stunnel
systemctl daemon-reload
systemctl restart stunnel4

# [ Setup Openvpn ]
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

# Some workaround for OpenVZ machines for "Startup error" openvpn service
if [[ "$(hostnamectl | grep -i Virtualization | awk '{print $2}' | head -n1)" == 'openvz' ]]; then
sed -i 's|LimitNPROC|#LimitNPROC|g' /lib/systemd/system/openvpn*
systemctl daemon-reload
fi

# Iptables Rule for OpenVPN server
cat << 'EOFipt' > /etc/openvpn/openvpn.bash
#!/bin/bash
PUBLIC_INET="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
IPCIDR='10.200.0.0/16'
IPCIDR2='10.201.0.0/16'
iptables -I FORWARD -s $IPCIDR -j ACCEPT
iptables -I FORWARD -s $IPCIDR2 -j ACCEPT
iptables -t nat -A POSTROUTING -o $PUBLIC_INET -j MASQUERADE
iptables -t nat -A POSTROUTING -s $IPCIDR -o $PUBLIC_INET -j MASQUERADE
iptables -t nat -A POSTROUTING -s $IPCIDR2 -o $PUBLIC_INET -j MASQUERADE
EOFipt
chmod +x /etc/openvpn/openvpn.bash
bash /etc/openvpn/openvpn.bash

# Setting Up Squid 
rm -rf /etc/squid/squid.con*
cat << mySquid > /etc/squid/squid.conf
acl VPN dst $IPADDR/32
http_access allow VPN
http_access deny all 
http_port 0.0.0.0:$Squid_Port1
http_port 0.0.0.0:$Squid_Port2
http_port 0.0.0.0:$Squid_Port3
request_header_access Allow allow all 
request_header_access Authorization allow all 
request_header_access WWW-Authenticate allow all 
request_header_access Proxy-Authorization allow all 
request_header_access Proxy-Authenticate allow all 
request_header_access Cache-Control allow all 
request_header_access Content-Encoding allow all 
request_header_access Content-Length allow all 
request_header_access Content-Type allow all 
request_header_access Date allow all 
request_header_access Expires allow all 
request_header_access Host allow all 
request_header_access If-Modified-Since allow all 
request_header_access Last-Modified allow all 
request_header_access Location allow all 
request_header_access Pragma allow all 
request_header_access Accept allow all 
request_header_access Accept-Charset allow all 
request_header_access Accept-Encoding allow all 
request_header_access Accept-Language allow all 
request_header_access Content-Language allow all 
request_header_access Mime-Version allow all 
request_header_access Retry-After allow all 
request_header_access Title allow all 
request_header_access Connection allow all 
request_header_access Proxy-Connection allow all 
request_header_access User-Agent allow all 
request_header_access Cookie allow all 
request_header_access All deny all
reply_header_access Allow allow all 
reply_header_access Authorization allow all 
reply_header_access WWW-Authenticate allow all 
reply_header_access Proxy-Authorization allow all 
reply_header_access Proxy-Authenticate allow all 
reply_header_access Cache-Control allow all 
reply_header_access Content-Encoding allow all 
reply_header_access Content-Length allow all 
reply_header_access Content-Type allow all 
reply_header_access Date allow all 
reply_header_access Expires allow all 
reply_header_access Host allow all 
reply_header_access If-Modified-Since allow all 
reply_header_access Last-Modified allow all 
reply_header_access Location allow all 
reply_header_access Pragma allow all 
reply_header_access Accept allow all 
reply_header_access Accept-Charset allow all 
reply_header_access Accept-Encoding allow all 
reply_header_access Accept-Language allow all 
reply_header_access Content-Language allow all 
reply_header_access Mime-Version allow all 
reply_header_access Retry-After allow all 
reply_header_access Title allow all 
reply_header_access Connection allow all 
reply_header_access Proxy-Connection allow all 
reply_header_access User-Agent allow all 
reply_header_access Cookie allow all 
reply_header_access All deny all
coredump_dir /var/spool/squid
dns_nameservers 8.8.8.8 8.8.4.4
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320
visible_hostname TsholoVPN
mySquid

# Restarting Squid Proxy
echo -e "Restarting proxy server..."
systemctl restart squid

# Setting System Time
ln -fs /usr/share/zoneinfo/$MyVPS_Time /etc/localtime

# Setting Terminal Message
[[ `cat .profile` =~ Dexter ]] ||
cat << 'intro' >> .profile
clear
echo -e '
    |$$$$$$$$$$$$| |$$$$$$$$$$$$|
         |$$|           |$$|
         |$$|           |$$|
         |$$|           |$$|
         |$$|           |$$|
         |$$|           |$$|
         |$$|       |$$$$$$|
         |__|       \______/  
' && echo "
                       TeeJaY's Script
"
intro

# TCP BBR
brloc=/etc/modules-load.d/modules.conf
if [[ ! `cat $brloc` =~ "tcp_bbr" ]];then
modprobe tcp_bbr
echo tcp_bbr >> $brloc; fi

# System Settings
cat << sysctl > /etc/sysctl.d/xdcb.conf
net.ipv4.ip_forward=1
net.ipv4.tcp_rmem=65535 131072 4194304
net.ipv4.tcp_wmem=65535 131072 194304
net.ipv4.ip_default_ttl=50
net.ipv4.tcp_congestion_control=bbr
net.core.wmem_default=262144
net.core.wmem_max=4194304
net.core.rmem_default=262144
net.core.rmem_max=4194304
net.core.netdev_budget=600
net.core.default_qdisc=fq
net.ipv6.conf.all.accept_ra=2
sysctl
sysctl --system

# Startup scripts setup
mkdir -p /etc/wago
cat <<EOFSH > /etc/wago/startup.sh
#!/bin/bash
ln -fs /usr/share/zoneinfo/$MyVPS_Time /etc/localtime
export DEBIAN_FRONTEND=noninteractive
iptables -A INPUT -s $(wget -4qO- http://ipinfo.io/ip) -p tcp -m multiport --dport 1:65535 -j ACCEPT
/bin/bash /etc/openvpn/openvpn.bash
iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport $V2ray_Port1 -j ACCEPT
iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport $V2ray_Port2 -j ACCEPT
iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport $V2ray_Port3 -j ACCEPT
iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport $V2ray_Port4 -j ACCEPT
iptables -I INPUT -m state --state NEW -m udp -p udp --dport $V2ray_Port1 -j ACCEPT
iptables -I INPUT -m state --state NEW -m udp -p udp --dport $V2ray_Port2 -j ACCEPT
iptables -I INPUT -m state --state NEW -m udp -p udp --dport $V2ray_Port3 -j ACCEPT
iptables -I INPUT -m state --state NEW -m udp -p udp --dport $V2ray_Port4 -j ACCEPT
exit 0
EOFSH

# Startup Script
cat << tsholo > /etc/systemd/system/tsholo.service
[Unit]
Description=Tsholo Startup Script
Wants=network.target
After=network.target
[Service]
Type=oneshot
ExecStart=/bin/bash /etc/tsholo/startup.sh
RemainAfterExit=yes
[Install]
WantedBy=network.target
tsholo

chmod +x /etc/tsholo/startup.sh
systemctl daemon-reload
systemctl enable tsholo
systemctl start tsholo

# Database Auth
cat << EOF > /etc/openvpn/script/config.sh
#!/bin/bash
HOST='$DatabaseHost'
USER='$DatabaseUser'
PASS='$DatabasePass'
DB='$DatabaseName'
PORT='$DatabasePort'
EOF
chmod +x /etc/openvpn/script/config.sh

# Setting Up Socks
loc=/etc/socksproxy
mkdir -p $loc

cat << Socks > $loc/proxy.py
import socket, threading, thread, select, signal, sys, time, getopt

LISTENING_ADDR = '0.0.0.0'
LISTENING_PORT = $WsPort
PASS = ''

BUFLEN = 4096 * 4
TIMEOUT = 60
DEFAULT_HOST = "127.0.0.1:$WsConnectPort"
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
            
            if hostPort == '':
                hostPort = DEFAULT_HOST

            split = self.findHeader(self.client_buffer, 'X-Split')

            if split != '':
                self.client.recv(BUFLEN)
            
            if hostPort != '':
                passwd = self.findHeader(self.client_buffer, 'X-Pass')
				
                if len(PASS) != 0 and passwd == PASS:
                    self.method_CONNECT(hostPort)
                elif len(PASS) != 0 and passwd != PASS:
                    self.client.send('HTTP/1.1 400 WrongPass!\r\n\r\n')
                elif hostPort.startswith('127.0.0.1') or hostPort.startswith('localhost'):
                    self.method_CONNECT(hostPort)
                else:
                    self.client.send('HTTP/1.1 403 Forbidden!\r\n\r\n')
            else:
                print '- No X-Real-Host!'
                self.client.send('HTTP/1.1 400 NoXRealHost!\r\n\r\n')

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
                port = $WsPort

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
    
    print "\n:-------PythonProxy-------:\n"
    print "Listening addr: " + LISTENING_ADDR
    print "Listening port: " + str(LISTENING_PORT) + "\n"
    print ":-------------------------:\n"
    
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

cat << service > /etc/systemd/system/socksproxy.service
[Unit]
Description=Socks Proxy
Wants=network.target
After=network.target
[Service]
Type=simple
ExecStart=/usr/bin/python -O $loc/proxy.py
ExecStop=/bin/bash -c "kill -15 \`cat $loc/.pid\`"
[Install]
WantedBy=network.target
service
systemctl daemon-reload
systemctl enable socksproxy
systemctl restart socksproxy

# Setup Php 7.*

$APT update
$APT install php php-fpm php-cli php-mysql php-mcrypt libxml-parser-perl php-xml php-json php-pdo php-zip php-gd php-mbstring php-curl php-bcmath

phpl=`php --ini | grep -om 1 /etc/php/*`
phpv=`echo $phpl | cut -d/ -f4`

sed -i 's/;cgi.fix_pathinfo=1/cgi.fix_pathinfo=0/g;/display_errors =/{s/Off/On/g};/;session.save_path =/{s/;//g}' $phpl/fpm/php.ini
sed -i '/listen =/{s/= .*/= 127.0.0.1:9000/g}' $phpl/fpm/pool.d/www.conf

# Setup WebMin
echo "deb http://download.webmin.com/download/repository sarge contrib" > /etc/apt/sources.list.d/webmin.list
wget http://www.webmin.com/jcameron-key.asc -qO- | apt-key add -
$APT update
$APT install webmin
sed -i "s/ssl=1/ssl=0/g" /etc/webmin/miniserv.conf

systemctl restart {php$phpv-fpm,webmin}

# Setup Up Nginx
cat << myNginxC > /etc/nginx/conf.d/wago-config.conf
server {
 listen 0.0.0.0:$Nginx_Port;
 server_name localhost;
 root /var/www/openvpn;
 index index.html;
}
myNginxC
rm -rf /etc/nginx/sites-*/*
rm -rf /var/www/openvpn
mkdir -p /var/www/openvpn
echo "TsholoVPN Services" > /var/www/openvpn/index.html

# OpenVPN Cert
ovpnDir='/etc/openvpn'
cert="<ca>
$(cat $ovpnDir/ca.crt)
</ca>"

# Setup Menu
cd /usr/local/sbin/
cd /usr/local/sbin/
rm -rf {accounts,base-ports,base-ports-wc,base-script,bench-network,clearcache,connections,create,create_random,create_trial,delete_expired,diagnose,edit_dropbear,edit_openssh,edit_openvpn,edit_ports,edit_squid3,edit_stunnel4,locked_list,menu,options,ram,reboot_sys,reboot_sys_auto,restart_services,server,set_multilogin_autokill,set_multilogin_autokill_lib,show_ports,speedtest,user_delete,user_details,user_details_lib,user_extend,user_list,user_lock,user_unlock}
wget -q 'https://raw.githubusercontent.com/tjay13/AutoScriptDebian9/main/Tools/premiummenu.zip'
unzip -qq premiummenu.zip
rm -f premiummenu.zip
chmod +x ./*
dos2unix ./* &> /dev/null
sed -i 's|/etc/squid/squid.conf|g;s|http_port|listen-address|g' ./*

# Setup BadVPN
if [[ ! `ps -A | grep badvpn` ]]; then
if [[ ! `type -P docker` ]]; then
curl -fsSL https://download.docker.com/linux/$ID/gpg | apt-key add - 
add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/$ID $(lsb_release -cs) stable"
apt update
apt-cache policy docker-ce
apt install docker-ce -y
apt clean; fi

export sqx=n
[ `type -P dcomp` ] || wget "https://github.com/docker/compose/releases/download/1.24.0/docker-compose-$(uname -s)-$(uname -m)" -qO /sbin/dcomp
chmod +x /sbin/dcomp || return

wget -qO- https://github.com/X-DCB/Unix/raw/master/badvpn.yaml | dcomp -f - up -d; fi

docker run -d --restart always --name openvpn-monitor \
  --net host --cap-add NET_ADMIN \
  -e OPENVPNMONITOR_DEFAULT_DATETIMEFORMAT="%%d/%%m/%%Y %%H:%%M:%%S" \
  -e OPENVPNMONITOR_DEFAULT_MAPS=True \
  -e OPENVPNMONITOR_DEFAULT_MAPSHEIGHT=500 \
  -e OPENVPNMONITOR_DEFAULT_SITE="WaGo" \
  -e OPENVPNMONITOR_SITES_0_ALIAS=TCP \
  -e OPENVPNMONITOR_SITES_0_HOST=127.0.0.1 \
  -e OPENVPNMONITOR_SITES_0_NAME=TCP \
  -e OPENVPNMONITOR_SITES_0_PORT=$MGMT_TCP_PORT \
  -e OPENVPNMONITOR_SITES_0_SHOWDISCONNECT=True \
  -e OPENVPNMONITOR_SITES_1_ALIAS=UDP \
  -e OPENVPNMONITOR_SITES_1_HOST=127.0.0.1 \
  -e OPENVPNMONITOR_SITES_1_NAME=UDP \
  -e OPENVPNMONITOR_SITES_1_PORT=$MGMT_UDP_PORT \
  ruimarinho/openvpn-monitor gunicorn openvpn-monitor --bind 0.0.0.0:$Monitor_Port

# Create OpenVPN Paths
mkdir /etc/openvpn/script
chmod -R 777 /etc/openvpn/script
mkdir /var/www/html/status
chmod -R 777 /var/www/html/status

# Credentials
cat << EOF > /etc/openvpn/script/config.sh
#!/bin/bash
HOST='$DatabaseHost'
USER='$DatabaseUser'
PASS='$DatabasePass'
DB='$DatabaseName'
PORT='$DatabasePort'
EOF
chmod +x /etc/openvpn/script/config.sh

# Creating TCP OpenVPN Config
cat << TeeJay01 >/etc/openvpn/server.conf
mode server 
tls-server 
port $OpenVPN_TCP_Port
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
script-security 2
ifconfig-pool-persist ipp.txt
client-cert-not-required 
username-as-common-name 
auth-user-pass-verify "/etc/openvpn/script/auth_vpn.sh" via-file # 
tmp-dir "/etc/openvpn/" # 
server 10.200.0.0 255.255.0.0
push "redirect-gateway def1" 
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
keepalive 5 30
persist-key 
persist-tun
verb 3 
status /var/www/html/status/tcp.txt 1

TeeJay01

case $opts in
    1) cat="user.username='$username' AND user.auth_vpn=md5('$password') AND user.confirmcode='y' AND user.status='live' AND user.is_freeze=1 AND user.is_active=1 AND user.is_ban=1 AND user.is_suspend=1 AND user.is_duration > 0";;
    2) cat="user.username='$username' AND user.auth_vpn=md5('$password') AND user.confirmcode='y' AND user.status='live' AND user.is_freeze=1 AND user.is_active=1 AND user.is_ban=1 AND user.is_suspend=1 AND user.vip_duration > 0";;
    3) cat="user.username='$username' AND user.auth_vpn=md5('$password') AND user.confirmcode='y' AND user.status='live' AND user.is_freeze=1 AND user.is_active=1 AND user.is_ban=1 AND user.is_suspend=1 AND user.private_duration > 0";;
esac

# Auth Script
cat <<'TeeJay02' >/etc/openvpn/script/auth_vpn.sh
#!/bin/bash
username=`head -n1 $1 | tail -1`   
password=`head -n2 $1 | tail -1`
tm="$(date +%s)"
dt="$(date +'%Y-%m-%d %H:%M:%S')"

HOST='$DatabaseHost'
USER='$DatabaseUser'
PASS='$DatabasePass'
DB='$DatabaseName'
PORT='$DatabasePort'

AUTH=$cat
Query="SELECT user.username FROM user WHERE $AUTH"
auth_vpn=`mysql -u $USER -p$PASS -D $DB -h $HOST --skip-column-name -e "$Query"`
  
[ "$user_name" != '' ] && [ "$user_name" = "$username" ] && echo "user : $username" && echo 'authentication ok.' && exit 0 || echo 'authentication failed.'; exit 1

TeeJay02

# Setting SSH CRON Jobs
cat <<'CronPanel2' > "/etc/$Filename_alias.cron.php"
<?php
error_reporting(E_ERROR | E_PARSE);
ini_set('display_errors', '1');

$DB_host = 'DatabaseHost';
$DB_user = 'DatabaseUser';
$DB_pass = 'DatabasePass';
$DB_name = 'DatabaseName';

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
        $secret_key = md5('eugcar');
        $secret_iv = md5('sanchez');
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
        $secret_key = md5('eugcar sanchez');
        $secret_iv = md5('sanchez eugcar');

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
$vip = "is_active=1 AND vip_duration > 0";
$private = "is_active=1 AND private_duration > 0";

$query = $mysqli->query("SELECT * FROM user
WHERE ".$premium." OR ".$vip." ORDER by id_user ASC");
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
$location = '/usr/sbin/kpn/active.sh';
$fp = fopen($location, 'w');
fwrite($fp, $data) or die("Unable to open file!");
fclose($fp);

#In-Active and Invalid Accounts
$data2 = '';
$premium_deactived = "is_duration <= 0";
$vip_deactived = "vip_duration <= 0";
$private_deactived = "private_duration <= 0";
$is_activate = "is_active=0";
$freeze = "is_freeze=0";
$suspend = "is_suspend=0";

$query2 = $mysqli->query("SELECT * FROM user 
WHERE ".$suspend." OR ".$freeze." OR ".$premium_deactived ." AND ".$vip_deactived." OR ".$is_activate."
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
$location2 = '/usr/sbin/kpn/inactive.sh';
$fp = fopen($location2, 'w');
fwrite($fp, $data2) or die("Unable to open file!");
fclose($fp);

$mysqli->close();
?>
CronPanel2

sed -i "s|DatabaseHost|$DatabaseHost|g;s|DatabaseName|$DatabaseName|g;s|DatabaseUser|$DatabaseUser|g;s|DatabasePass|$DatabasePass|g" "/etc/$Filename_alias.cron.php"

chmod +x "/etc/$Filename_alias.cron.php"

# Setting Permissions
chmod +x /etc/openvpn/script/auth_vpn.sh
chmod +x /etc/openvpn/script/connect.sh
chmod +x /etc/openvpn/script/disconnect.sh

# Fixing Multilogin Script
cat <<'Multilogin' >/usr/local/sbin/set_multilogin_autokill_lib
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

systemctl enable openvpn@server
systemctl start openvpn@server

docker run -d --restart always --name v2ray --net host --cap-add NET_ADMIN \
 -v /etc/v2ray:/etc/v2ray \
 v2fly/v2fly-core
docker run -d --restart always --name v2ray-none --net host --cap-add NET_ADMIN \
 -v /etc/v2ray:/etc/v2ray \
 -v /etc/v2ray/none.json:/etc/v2ray/config.json \
 v2fly/v2fly-core
docker run -d --restart always --name v2ray-vless --net host --cap-add NET_ADMIN \
 -v /etc/v2ray:/etc/v2ray \
 -v /etc/v2ray/vless.json:/etc/v2ray/config.json \
 v2fly/v2fly-core
docker run -d --restart always --name v2ray-vnone --net host --cap-add NET_ADMIN \
 -v /etc/v2ray:/etc/v2ray \
 -v /etc/v2ray/vnone.json:/etc/v2ray/config.json \
 v2fly/v2fly-core

# Setup Apache
sed -i "s|Listen 80|Listen $Apache_Port|g" /etc/apache2/ports.conf
service apache2 restart
a2enmod proxy_fcgi setenvif
a2enconf php$phpv-fpm
systemctl reload apache2 #activate

# Set Stat Permissions
chmod 777 /var/www/html/status/tcp.txt

# Setting SSH To Work With Panel
mkdir /usr/sbin/kpn
wget -O /usr/sbin/kpn/connection.php "https://raw.githubusercontent.com/tjay13/TsholoVPN/master/Tools/Menu/connection.php"

# Cloudflare Domain
echo "$Cloudflare_Domain" >> /root/domain

# Setup Cron
cat << cron > /etc/cron.d/$Filename_alias
* * * * * root php -q /etc/$Filename_alias.cron.php
* * * * * root bash /etc/openvpn/active.sh
* * * * * root bash /etc/openvpn/inactive.sh

cron
echo -e "0 4 * * * root reboot" > /etc/cron.d/b_reboot_job
echo -e "* * * * *  root /usr/local/sbin/set_multilogin_autokill_lib 1" >> "/etc/cron.d/set_multilogin_autokill_lib"
echo -e "* * * * * root /usr/bin/php /usr/sbin/kpn/connection.php >/dev/null 2>&1" > /etc/cron.d/connection
echo -e "* * * * * root /bin/bash /usr/sbin/kpn/active.sh>/dev/null 2>&1"> /etc/cron.d/active
echo -e "* * * * * root /bin/bash /usr/sbin/kpn/inactive.sh >/dev/null 2>&1" > /etc/cron.d/inactive
systemctl restart cron
systemctl enable cron

# Script Info
clear

cat << logs | tee -a ~/log-install.txt

INSTALLATION HAS BEEN COMPLETED!!
============================-AUTOSCRIPT WAGO-G-============================

---------------------------------------------------------------------------

   >>> Service & Port
   - OpenSSH                 : $SSH_Port1, $SSH_Port2 
   - OpenVPN                 : TCP $OpenVPN_TCP_Port UDP $OpenVPN_UDP_Port
   - Stunnel/SSL             : $Stunnel_Port1, $Stunnel_Port2, $Stunnel_Port3
   - Dropbear                : $Dropbear_Port1, $Dropbear_Port2
   - Squid Proxy             : $Squid_Port1, $Squid_Port2 , $Squid_Port3
   - Badvpn                  : 7300
   - Nginx                   : $Nginx_Port
   - Apache                  : $Apache_Port
   - Socks                   : $WsPort
   - V2RAY Vmess TLS         : $V2ray_Port1
   - V2RAY Vmess None TLS    : $V2ray_Port2
   - V2RAY Vless TLS         : $V2ray_Port3
   - V2RAY Vless None TLS    : $V2ray_Port4

   >>> Server Information & Features
   - Timezone                : Africa/Johannesburg (GMT +2)
   - Fail2Ban                : [ON]
   - IPtables                : [ON]
   - Auto-Reboot             : [ON]
   - IPv6                    : [OFF]
   - Webmin Login Page       : http://$IPADDR:10000/
   - OpenVPN Monitor         : http://$IPADDR:$Monitor_Port/
---------------------------------------------------------------------------

===========================================================================

logs

# Clearing Logs
rm -rf /root/.bash_history && history -c && echo '' > /var/log/syslog
rm -f *.sh

cd
exit 0
