#!/bin/bash

#################################
# FUNC:     	           LAMP #
# DATA:              20-01-2015 #
# AUTHOR:    Rafael Andermarchi #
#################################

#InformaÃ§s do servidor
printf "\n"
cpuname=$( awk -F: '/model name/ {name=$2} END {print name}' /proc/cpuinfo )
cpucores=$( awk -F: '/model name/ {core++} END {print core}' /proc/cpuinfo )
cpufreq=$( awk -F: ' /cpu MHz/ {freq=$2} END {print freq}' /proc/cpuinfo )
svram=$( free -m | awk 'NR==2 {print $2}' )
svhdd=$( df -h | awk 'NR==2 {print $2}' )
svswap=$( free -m | awk 'NR==4 {print $2}' )

if [ -f "/proc/user_beancounters" ]; then
svip=$(ifconfig venet0:0 | grep 'inet addr:' | awk -F'inet addr:' '{ print $2}' | awk '{ print $1}')
else
svip=$(ifconfig | grep 'inet addr:' | awk -F'inet addr:' '{ print $2}' | awk '{ print $1}')
fi


printf "==========================================================================\n"
printf "ParÃ¢tros do servidor:  \n"
echo "=========================================================================="
echo "VPS Type: $(virt-what)"
echo "CPU Type: $cpuname"
echo "CPU Core: $cpucores"
echo "CPU Speed: $cpufreq MHz"
echo "Memory: $svram MB"
echo "Swap: $svswap MB"
echo "Disk: $svhdd"
echo "IP's: $svip"
printf "==========================================================================\n"
printf "\n"

#Desabilitando Selinux
if [ -s /etc/selinux/config ]; then
sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config && 
printf "==========================================================================\n"
printf "Desabilitando SELinux:                                [ \e[00;32mOK\e[00m ] \n"
echo -e "==========================================================================\n\n"
fi

# Instalando e Ajustando Repositorio

rpm -Uvh http://dl.fedoraproject.org/pub/epel/6/x86_64/epel-release-6-8.noarch.rpm --force
rpm -Uvh http://rpms.famillecollet.com/enterprise/remi-release-6.rpm
if [ -f /etc/yum.repos.d/epel.repo ]
then
sed -i "s/mirrorlist=https/mirrorlist=http/" /etc/yum.repos.d/epel.repo
fi

# Update do servidor

yum -y update

clear

# Instalando Bibliotecas padrÃµyum install -y gcc expect gcc-c++ zlib-devel lsof autoconf nc libedit-devel make openssl-devel libtool bind-utils glib2 glib2-devel openssl bzip2 bzip2-devel libcurl-devel which libxml2-devel libxslt-devel gd gd-devel libgcj gettext-devel vim-minimal nano libpng-devel freetype freetype-devel libart_lgpl-devel  GeoIP-devel aspell aspell-devel libtidy libtidy-devel libedit-devel e openldap-devel curl curl-devel diffutils libc-client libc-client-devel numactl lsof  unzip zip rar unrar rsync libtool iotop htop

clear

#Habilitando IPTABLES

rm -rf /etc/sysconfig/iptables

cat > "/etc/sysconfig/iptables" << END
# Firewall configuration written by system-config-firewall
# # Manual customization of this file is not recommended.
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
##-------------------------------------- default ----------------------------------------#
-A INPUT -s 201.20.44.2 -p icmp -j ACCEPT
-A INPUT -p icmp --icmp-type echo-request -j ACCEPT
-A INPUT -p icmp -j DROP
-A INPUT -i lo -j ACCEPT
##---------------------------------------------------------------------------------------#
#
#
##-------------------------------------- HTTP -------------------------------------------#
-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 8080 -j ACCEPT
##---------------------------------------------------------------------------------------#
#
#
##-------------------------------------- FTP --------------------------------------------#
-A INPUT -p tcp -m tcp --dport 21 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 20 -j ACCEPT
# Porta de FTP/SSL
-A INPUT -p tcp -m tcp --dport 990 -j ACCEPT
# Portas de FTP Passivo.
-A INPUT -p tcp --dport 5500:5700 -j ACCEPT

##---------------------------------------------------------------------------------------#
#
#
##-------------------------------------- MySQL ------------------------------------------#
-A INPUT -i eth0 -s 201.20.44.2 -p tcp -m tcp --dport 3306 -j ACCEPT
#-A INPUT -i eth0 -s <IP de Origem> -p tcp -m tcp --dport 3306 -j ACCEPT
# Obs.: Caso o cliente queira realizar conexões externas ao MYSQL, descomentar a segunda
# linha desta sessão e liberar a conexão para o IP de origem !!!
##---------------------------------------------------------------------------------------#
#
#
##-------------------------------------- SVN --------------------------------------------#
#-A INPUT -i eth0 -p tcp -m tcp --dport 3690 -j ACCEPT
#-A INPUT -i eth0 -p udp -m udp --dport 3690 -j ACCEPT
# Obs.: Liberar estas portas somente se o cliente possuir o serviço SVN instalado.
##---------------------------------------------------------------------------------------#
#
#
##----------------------------- Anti Syn Flood & DDoS -----------------------------------#
-A FORWARD -p tcp --syn -m limit --limit 5/s -j ACCEPT
-A FORWARD -p tcp --syn -j DROP
-A FORWARD -p tcp --tcp-flags SYN,ACK, FIN, -m limit --limit 1/s -j ACCEPT
-A INPUT -i eth0 -p tcp -m tcp --dport 80 -m state --state NEW -m recent --set --name DDOS --rsource
-A INPUT -i eth0 -p tcp -m tcp --dport 80 -m state --state NEW -m recent --update --seconds 1 --hitcount 20 --name DDOS --rsource -j DROP
# Bloqueio para o AutoSpy
-A INPUT -i eht0 -p tcp -m tcp --dport 6556 -j DROP
# Bloqueio para o LampSpy
-A INPUT -i eht0 -p tcp -m tcp --dport 6660 -j DROP
# Obs.: A primeira e a segunda regra impede o atacante de mandar muitos pacotes apenas com o flag SYN on, fazendo o servidor responder com SYN-ACK para o ip (forjado), e com isso alocar os recursos para a conexão, além de ficar aguardando pela resposta contendo o ACK, diminuindo os recursos do sistema, aumentando a demora para responder novas conexões, verdadeiras ou falsas, até que o serviço que está ouvindo na porta não consiga mais responder, ocasionando uma negação de serviço (DOS).
# Obs.: Segunda Regra visa minimizar o PortScanner

#-A INPUT -i eth0 -p tcp -m tcp --dport 54545 -j ACCEPT
# Liberando porta 54545 para script de bloqueio de IP's Mod_Security
##---------------------------------------------------------------------------------------#
#
#
##-------------------------------------- ZABBIX -----------------------------------------#
-A INPUT -i eth0 -s 177.70.96.220 -p tcp -m tcp --dport 10052 -j ACCEPT
-A INPUT -i eth0 -p tcp -m tcp --dport 10052 -j DROP
##---------------------------------------------------------------------------------------#
#
#
##-------------------------------------- SSH --------------------------------------------#
-A INPUT -s 177.70.100.5 -p tcp -m tcp --dport 22 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 22 -j DROP
##---------------------------------------------------------------------------------------#
#
#
##-------------------------------------- E-mail -----------------------------------------#
-A INPUT -p tcp -m tcp --dport 25 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 587 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 110 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 143 -j ACCEPT
##---------------------------------------------------------------------------------------#
#
#
##------------------------------------- DNS ---------------------------------------------#
-A INPUT -p tcp -m tcp --dport 53 -j ACCEPT
-A INPUT -p udp -m udp --dport 53 -j ACCEPT
##---------------------------------------------------------------------------------------#
#
#
##------------------------------------- Plesk -------------------------------------------#
#-A INPUT -p tcp -m tcp --dport 993 -j ACCEPT #imaps
#-A INPUT -p tcp -m tcp --dport 995 -j ACCEPT #pop3s
#-A INPUT -p tcp -m tcp --dport 465 -j ACCEPT #smtps
#-A INPUT -p tcp -m tcp --dport 8880 -j ACCEPT #plesk-http
#-A INPUT -p tcp -m tcp --dport 8443 -j ACCEPT #plesk-https
#-A INPUT -p tcp -m tcp --dport 8425 -j ACCEPT #Plesk webmail
#-A INPUT -p tcp -m tcp --dport 8447 -j ACCEPT #autoinstaller
#-A INPUT -p tcp -m tcp --dport 9080 -j ACCEPT #tomcat
##--------------------------------------------------------------------------------------#
#
#
##------------------------------------ CPanel ------------------------------------------#
#-A INPUT -p tcp -m tcp --dport 993 -j ACCEPT #imaps
#-A INPUT -p tcp -m tcp --dport 995 -j ACCEPT #pop3s
#-A INPUT -p tcp -m tcp --dport 2082 -j ACCEPT #cPanel TCP inbound
#-A INPUT -p tcp -m tcp --dport 2083 -j ACCEPT #cPanel SSL TCP inbound
#-A INPUT -p tcp -m tcp --dport 2086 -j ACCEPT #WHM TCP inbound
#-A INPUT -p tcp -m tcp --dport 2087 -j ACCEPT #WHM SSL TCP inbound
#-A INPUT -p tcp -m tcp --dport 2089 -j ACCEPT #cPanel license TCP outbound
#-A INPUT -p tcp -m tcp --dport 2095 -j ACCEPT #Webmail TCP inbound
#-A INPUT -p tcp -m tcp --dport 2096 -j ACCEPT #Webmail SSL TCP inbound
#-A INPUT -p tcp -m tcp --dport 6666 -j ACCEPT #Chat TCP inbound
#
##--------------------------------------------------------------------------------------#
#
#
COMMIT
END

# Instalando HTTPD

yum install -y httpd httpd-devel mod_ssl openssl openssl-devel 

rm -rf /etc/httpd/conf/httpd.conf

cat > "/etc/httpd/conf/httpd.conf" << END

ServerTokens ProductOnly
ServerSignature OFF
#
ServerRoot "/etc/httpd"
PidFile run/httpd.pid
Timeout 60
#
KeepAlive Off
MaxKeepAliveRequests 30
KeepAliveTimeout 3
#
<IfModule prefork.c>
StartServers       8
MinSpareServers    5
MaxSpareServers   20
ServerLimit      256
MaxClients       256
MaxRequestsPerChild  10
</IfModule>
#
<IfModule worker.c>
StartServers         4
MaxClients         300
MinSpareThreads     25
MaxSpareThreads     75 
ThreadsPerChild     25
MaxRequestsPerChild  0
</IfModule>
#
Listen 80
#
LoadModule auth_basic_module modules/mod_auth_basic.so
LoadModule auth_digest_module modules/mod_auth_digest.so
LoadModule authn_file_module modules/mod_authn_file.so
LoadModule authn_alias_module modules/mod_authn_alias.so
LoadModule authn_anon_module modules/mod_authn_anon.so
LoadModule authn_dbm_module modules/mod_authn_dbm.so
LoadModule authn_default_module modules/mod_authn_default.so
LoadModule authz_host_module modules/mod_authz_host.so
LoadModule authz_user_module modules/mod_authz_user.so
LoadModule authz_owner_module modules/mod_authz_owner.so
LoadModule authz_groupfile_module modules/mod_authz_groupfile.so
LoadModule authz_dbm_module modules/mod_authz_dbm.so
LoadModule authz_default_module modules/mod_authz_default.so
LoadModule ldap_module modules/mod_ldap.so
LoadModule authnz_ldap_module modules/mod_authnz_ldap.so
LoadModule include_module modules/mod_include.so
LoadModule log_config_module modules/mod_log_config.so
LoadModule logio_module modules/mod_logio.so
LoadModule env_module modules/mod_env.so
LoadModule ext_filter_module modules/mod_ext_filter.so
LoadModule mime_magic_module modules/mod_mime_magic.so
LoadModule expires_module modules/mod_expires.so
LoadModule deflate_module modules/mod_deflate.so
LoadModule headers_module modules/mod_headers.so
LoadModule usertrack_module modules/mod_usertrack.so
LoadModule setenvif_module modules/mod_setenvif.so
LoadModule mime_module modules/mod_mime.so
LoadModule dav_module modules/mod_dav.so
LoadModule status_module modules/mod_status.so
LoadModule autoindex_module modules/mod_autoindex.so
LoadModule info_module modules/mod_info.so
LoadModule dav_fs_module modules/mod_dav_fs.so
LoadModule vhost_alias_module modules/mod_vhost_alias.so
LoadModule negotiation_module modules/mod_negotiation.so
LoadModule dir_module modules/mod_dir.so
LoadModule actions_module modules/mod_actions.so
LoadModule speling_module modules/mod_speling.so
LoadModule userdir_module modules/mod_userdir.so
LoadModule alias_module modules/mod_alias.so
LoadModule substitute_module modules/mod_substitute.so
LoadModule rewrite_module modules/mod_rewrite.so
LoadModule proxy_module modules/mod_proxy.so
LoadModule proxy_balancer_module modules/mod_proxy_balancer.so
LoadModule proxy_ftp_module modules/mod_proxy_ftp.so
LoadModule proxy_http_module modules/mod_proxy_http.so
LoadModule proxy_ajp_module modules/mod_proxy_ajp.so
LoadModule proxy_connect_module modules/mod_proxy_connect.so
LoadModule cache_module modules/mod_cache.so
LoadModule suexec_module modules/mod_suexec.so
LoadModule disk_cache_module modules/mod_disk_cache.so
LoadModule cgi_module modules/mod_cgi.so
LoadModule version_module modules/mod_version.so
LoadModule ssl_module modules/mod_ssl.so

Include conf.d/*.conf

ExtendedStatus On

User apache
Group apache

ServerAdmin operacoes@mandic.net.br
ServerName www.mandic.com.br
UseCanonicalName Off

DocumentRoot "/var/www/html"

<Directory />
    Options +FollowSymLinks
    AllowOverride All
</Directory>

<Directory "/var/www/html">
    Options Indexes MultiViews FollowSymLinks
    AllowOverride all
    Order allow,deny
    Allow from all
</Directory>

<IfModule mod_userdir.c>
    UserDir disabled
    #UserDir public_html
</IfModule>

DirectoryIndex index.htm index.html index.php index.jsp index.html.var

AccessFileName .htaccess
<Files ~ "^\.ht">
    Order allow,deny
    Deny from all
    Satisfy All
</Files>

TypesConfig /etc/mime.types
DefaultType text/plain
<IfModule mod_mime_magic.c>
#   MIMEMagicFile /usr/share/magic.mime
    MIMEMagicFile conf/magic
</IfModule>

HostnameLookups Off

#EnableMMAP off
#EnableSendfile off

##############
# LOGS HTTPD #
##############

ErrorLog /var/log/httpd/error_log
LogLevel warn
LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"" combined
LogFormat "%h %l %u %t \"%r\" %>s %b" common
LogFormat "%{Referer}i -> %U" referer
LogFormat "%{User-agent}i" agent
CustomLog /var/log/httpd/access_log combined

Alias /icons/ "/var/www/icons/"

<Directory "/var/www/icons">
    Options Indexes MultiViews FollowSymLinks
    AllowOverride None
    Order allow,deny
    Allow from all
</Directory>

#
# WebDAV module configuration section.
# 
<IfModule mod_dav_fs.c>
    # Location of the WebDAV lock database.
    DAVLockDB /var/lib/dav/lockdb
</IfModule>

ScriptAlias /cgi-bin/ "/var/www/cgi-bin/"

<Directory "/var/www/cgi-bin">
    AllowOverride None
    Options None
    Order allow,deny
    Allow from all
</Directory>

# Example:
# Redirect permanent /foo http://www.example.com/bar

IndexOptions FancyIndexing VersionSort NameWidth=* HTMLTable Charset=UTF-8

AddIconByEncoding (CMP,/icons/compressed.gif) x-compress x-gzip

AddIconByType (TXT,/icons/text.gif) text/*
AddIconByType (IMG,/icons/image2.gif) image/*
AddIconByType (SND,/icons/sound2.gif) audio/*
AddIconByType (VID,/icons/movie.gif) video/*

AddIcon /icons/binary.gif .bin .exe
AddIcon /icons/binhex.gif .hqx
AddIcon /icons/tar.gif .tar
AddIcon /icons/world2.gif .wrl .wrl.gz .vrml .vrm .iv
AddIcon /icons/compressed.gif .Z .z .tgz .gz .zip
AddIcon /icons/a.gif .ps .ai .eps
AddIcon /icons/layout.gif .html .shtml .htm .pdf
AddIcon /icons/text.gif .txt
AddIcon /icons/c.gif .c
AddIcon /icons/p.gif .pl .py
AddIcon /icons/f.gif .for
AddIcon /icons/dvi.gif .dvi
AddIcon /icons/uuencoded.gif .uu
AddIcon /icons/script.gif .conf .sh .shar .csh .ksh .tcl
AddIcon /icons/tex.gif .tex
AddIcon /icons/bomb.gif core
AddIcon /icons/back.gif ..
AddIcon /icons/hand.right.gif README
AddIcon /icons/folder.gif ^^DIRECTORY^^
AddIcon /icons/blank.gif ^^BLANKICON^^

DefaultIcon /icons/unknown.gif

ReadmeName README.html
HeaderName HEADER.html

IndexIgnore .??* *~ *# HEADER* README* RCS CVS *,v *,t

AddLanguage en .en
AddLanguage es .es
AddLanguage pt .pt
AddLanguage pt-BR .pt-br


LanguagePriority pt-BR en es
ForceLanguagePriority Prefer Fallback
AddDefaultCharset UTF-8
AddType application/x-compress .Z
AddType application/x-gzip .gz .tgz
AddType application/x-x509-ca-cert .crt
AddType application/x-pkcs7-crl    .crl
AddHandler type-map var
AddType text/html .shtml
AddOutputFilter INCLUDES .shtml

Alias /error/ "/var/www/error/"

<IfModule mod_negotiation.c>
<IfModule mod_include.c>
    <Directory "/var/www/error">
        AllowOverride None
        Options IncludesNoExec
        AddOutputFilter Includes html
        AddHandler type-map var
        Order allow,deny
        Allow from all
        LanguagePriority pt-BR en es
        ForceLanguagePriority Prefer Fallback
    </Directory>

</IfModule>
</IfModule>

# COMPRESSION GZIP
#Set to gzip all output
SetOutputFilter DEFLATE
#exclude the following file types
SetEnvIfNoCase Request_URI \.(?:exe|t?gz|zip|iso|tar|bz2|sit|rar|png|jpg|gif|jpeg|flv|swf|mp3)$ no-gzip dont-vary
#set compression level
DeflateCompressionLevel 9
#Handle browser specific compression requirements
BrowserMatch ^Mozilla/4 gzip-only-text/html
BrowserMatch ^Mozilla/4.0[678] no-gzip
BrowserMatch bMSIE !no-gzip !gzip-only-text/html
SetEnvIf User-Agent ".*MSIE.*" nokeepalive ssl-unclean-shutdown downgrade-1.0 force-response-1.0



BrowserMatch "Mozilla/2" nokeepalive
BrowserMatch "MSIE 4\.0b2;" nokeepalive downgrade-1.0 force-response-1.0
BrowserMatch "RealPlayer 4\.0" force-response-1.0
BrowserMatch "Java/1\.0" force-response-1.0
BrowserMatch "JDK/1\.0" force-response-1.0

BrowserMatch "Microsoft Data Access Internet Publishing Provider" redirect-carefully
BrowserMatch "MS FrontPage" redirect-carefully
BrowserMatch "^WebDrive" redirect-carefully
BrowserMatch "^WebDAVFS/1.[0123]" redirect-carefully
BrowserMatch "^gnome-vfs/1.0" redirect-carefully
BrowserMatch "^XML Spy" redirect-carefully
BrowserMatch "^Dreamweaver-WebDAV-SCM1" redirect-carefully

<Location /server-status>
    SetHandler server-status
    Order deny,allow
    Deny from all
    Allow from 201.20.44.2
</Location>


NameVirtualHost *:80

<IfModule mod_expires.c>
  ExpiresActive On
  ExpiresDefault "access plus 1 seconds"
  ExpiresByType text/html "access plus 1 seconds"
  ExpiresByType image/gif "access plus 120 minutes"
  ExpiresByType image/jpeg "access plus 120 minutes"
  ExpiresByType image/png "access plus 120 minutes"
  ExpiresByType text/css "access plus 60 minutes"
  ExpiresByType text/javascript "access plus 60 minutes"
  ExpiresByType application/x-javascript "access plus 60 minutes"
  ExpiresByType text/xml "access plus 60 minutes"
</IfModule>

#DEFLATE
<IfModule mod_deflate.c>
   AddOutputFilterByType DEFLATE text/html text/plain text/xml text/css text/javascript application/x-javascript application/xml application/xhtml+xml "application/x-javascript \n\n" "text/html \n\n"
   DeflateCompressionLevel   9
</IfModule>
END

cat > "/var/www/html/index.php" <<END
<?php
phpinfo();
?>
END

rm -rf /etc/httpd/conf.d/ssl.conf

service httpd restart

chkconfig httpd on


# Instalando MYSQLD

yum install -y mysql mysql-server mytop mysql-utilities

service mysqld start

DATABASE_PASS=`cat /dev/urandom| tr -dc 'a-zA-Z0-9-_!@#$%^&*()_+{}|:<>?='| head -c 10`

mysqladmin -u root password "$DATABASE_PASS"
mysql -u root -p"$DATABASE_PASS" -e "UPDATE mysql.user SET Password=PASSWORD('$DATABASE_PASS') WHERE User='root'"
mysql -u root -p"$DATABASE_PASS" -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1')"
mysql -u root -p"$DATABASE_PASS" -e "DELETE FROM mysql.user WHERE User=''"
mysql -u root -p"$DATABASE_PASS" -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\_%'"
mysql -u root -p"$DATABASE_PASS" -e "FLUSH PRIVILEGES"

echo "
[client]
user=root
password='$DATABASE_PASS'
" > /root/.my.cnf



mkdir -p /mnt/mytmp
sleep 1
echo "tmpfs                  /mnt/mytmp              tmpfs   size=2G         0 0" >> /etc/fstab
sleep 3
mount -a
sleep 1
mkdir -p /var/log/mysql/
chown mysql:mysql /var/log/mysql/
mkdir -p  /var/log/mysql-bin
chown mysql:mysql /var/log/mysql-bin/
chown mysql:mysql /mnt/mytmp
 
#service mysqld restart


rm -rf /etc/my.cnf
    cat > "/etc/my.cnf" <<END
[mysqld]
datadir=/var/lib/mysql
socket=/var/lib/mysql/mysql.sock
tmpdir=/mnt/mytmp
user=mysql
symbolic-links=0
log-error=/var/log/mysql/mysqld.log
skip-external-locking

### CONFIG RECOVERY and BIN-LOG ###
myisam-recover = BACKUP
server-id = 1
log_bin = /var/log/mysql-bin/mysql-bin.log
expire_logs_days = 3
max_binlog_size = 100M
innodb_flush_log_at_trx_commit=1
sync_binlog=1

### TUNING  ###
local-infile
low-priority-updates
symbolic-links

# Log's
general_log_file = /var/log/mysql/mysql.log
general_log = 1
log-error=/var/log/mysql/error.log
slow-query-log=/var/log/mysql/slowquery.log
log_slow_queries=/var/log/mysql/slowquery.log
long_query_time=5

# Conections
connect_timeout=10
max_connections=500
max_user_connections=100
max_connect_errors=20

max_allowed_packet      = 16M
thread_stack            = 192K
thread_cache_size       = 8K
myisam_sort_buffer_size=2M
join_buffer_size=8M
sort_buffer_size=1M
table_cache=256
wait_timeout=30
tmp_table_size=4M
query_cache_size=2M
query_cache_limit=1M
key_buffer_size=2M
read_buffer_size = 1M
read_rnd_buffer_size = 2M


[safe_mysqld]
open_files_limit=65535

[mysqldump]
socket=/var/lib/mysql/mysql.sock
max_allowed_packet=64M
add-drop-table
extended-insert
quick

[mysql]
socket=/var/lib/mysql/mysql.sock
disable-auto-rehash
connect_timeout=15
local-infile
quick

[isamchk]
key_buffer = 16M
sort_buffer_size = 256M
read_buffer = 2M
write_buffer = 2M

[myisamchk]
key_buffer = 16M
sort_buffer_size = 256M
read_buffer = 2M
write_buffer = 2M


[mysqld_safe]
log-error=/var/log/mysqld.log
pid-file=/var/run/mysqld/mysqld.pid
END


mkdir -p /scripts
cd /scripts 
wget ftp://ftpcloud.mandic.com.br/Scripts/LAMP/*.sh && chmod +x *.sh

crontab -l > script_cron
echo "00 02 * * * /scripts/backup_mysql.sh" >> script_cron
crontab script_cron
rm -rf script_cron

cd ~


service mysql restart
chkconfig mysqld on

clear




# Instalando VSFTPD

yum -y install vsftpd

rm -rf /etc/vsftpd/vsftpd.conf
cat > "/etc/vsftpd/vsftpd.conf"<<END
force_dot_files=YES
background=YES
listen=YES
chown_uploads=YES
chown_username=apache
connect_from_port_20=NO
ftp_data_port=20
listen_port=21
pasv_min_port=5500
pasv_max_port=5700
pasv_promiscuous=NO
port_enable=NO
port_promiscuous=NO
connect_timeout=60
data_connection_timeout=120
idle_session_timeout=120
setproctitle_enable=YES
banner_file=/etc/banner
dirmessage_enable=YES
pasv_enable=YES
async_abor_enable=NO
guest_enable=NO
write_enable=YES
max_clients=300
max_per_ip=20
pam_service_name=vsftpd
tcp_wrappers=NO
ascii_upload_enable=NO
ascii_download_enable=NO
hide_ids=YES
ls_recurse_enable=NO
use_localtime=NO
anonymous_enable=NO
local_enable=YES
local_max_rate=0
local_umask=0022
chroot_local_user=YES
check_shell=NO
chmod_enable=YES
secure_chroot_dir=/var/empty
userlist_file=/etc/vsftpd_users
dual_log_enable=YES
log_ftp_protocol=NO
vsftpd_log_file=/var/logs/vsftpd.log
xferlog_enable=YES
xferlog_std_format=NO
xferlog_file=/var/log/xferlog
END

touch /var/log/vsftpd.log && chown vsftpd:vsftpd /var/log/vsftpd.log
service vsftpd restart
chkconfig vsftpd on

clear

# Instalando FAIL2BAN


yum -y install fail2ban 

rm -rf /etc/fail2ban/jail.conf
 
cat > "/etc/fail2ban/jail.conf"<<END
[DEFAULT]
ignoreip = 127.0.0.1 201.20.44.2 177.70.100.5
bantime  = 345600
findtime  = 300
maxretry = 5
backend = auto
usedns = warn

[pam-generic]

enabled = false
filter  = pam-generic
action  = iptables-allports[name=pam,protocol=all]
logpath = /var/log/secure

[xinetd-fail]

enabled = false
filter  = xinetd-fail
action  = iptables-allports[name=xinetd,protocol=all]
logpath = /var/log/daemon*log

[ssh-iptables]

enabled  = true
filter   = sshd
action   = iptables[name=SSH, port=ssh, protocol=tcp]
           sendmail-whois[name=SSH, dest=you@example.com, sender=fail2ban@example.com, sendername="Fail2Ban"]
logpath  = /var/log/secure
maxretry = 5

[ssh-ddos]

enabled  = false
filter   = sshd-ddos
action   = iptables[name=SSHDDOS, port=ssh, protocol=tcp]
logpath  = /var/log/sshd.log
maxretry = 2

[dropbear]

enabled  = false
filter   = dropbear
action   = iptables[name=dropbear, port=ssh, protocol=tcp]
logpath  = /var/log/messages
maxretry = 5

[proftpd-iptables]

enabled  = false
filter   = proftpd
action   = iptables[name=ProFTPD, port=ftp, protocol=tcp]
           sendmail-whois[name=ProFTPD, dest=you@example.com]
logpath  = /var/log/proftpd/proftpd.log
maxretry = 6

[gssftpd-iptables]

enabled  = false
filter   = gssftpd
action   = iptables[name=GSSFTPd, port=ftp, protocol=tcp]
           sendmail-whois[name=GSSFTPd, dest=you@example.com]
logpath  = /var/log/daemon.log
maxretry = 6

[pure-ftpd]

enabled  = false
filter   = pure-ftpd
action   = iptables[name=pureftpd, port=ftp, protocol=tcp]
logpath  = /var/log/pureftpd.log
maxretry = 6

[wuftpd]

enabled  = false
filter   = wuftpd
action   = iptables[name=wuftpd, port=ftp, protocol=tcp]
logpath  = /var/log/daemon.log
maxretry = 6

[sendmail-auth]

enabled  = false
filter   = sendmail-auth
action   = iptables-multiport[name=sendmail-auth, port="submission,465,smtp", protocol=tcp]
logpath  = /var/log/mail.log

[sendmail-reject]

enabled  = false
filter   = sendmail-reject
action   = iptables-multiport[name=sendmail-auth, port="submission,465,smtp", protocol=tcp]
logpath  = /var/log/mail.log

[sasl-iptables]

enabled  = false
filter   = postfix-sasl
backend  = polling
action   = iptables[name=sasl, port=smtp, protocol=tcp]
           sendmail-whois[name=sasl, dest=you@example.com]
logpath  = /var/log/mail.log

[assp]

enabled = false
filter  = assp
action  = iptables-multiport[name=assp,port="25,465,587"]
logpath = /root/path/to/assp/logs/maillog.txt

[ssh-tcpwrapper]

enabled     = false
filter      = sshd
action      = hostsdeny[daemon_list=sshd]
              sendmail-whois[name=SSH, dest=you@example.com]
ignoreregex = for myuser from
logpath     = /var/log/sshd.log

[ssh-route]

enabled  = false
filter   = sshd
action   = route
logpath  = /var/log/sshd.log
maxretry = 5

[ssh-iptables-ipset4]

enabled  = false
filter   = sshd
action   = iptables-ipset-proto4[name=SSH, port=ssh, protocol=tcp]
logpath  = /var/log/sshd.log
maxretry = 5

[ssh-iptables-ipset6]

enabled  = false
filter   = sshd
action   = iptables-ipset-proto6[name=SSH, port=ssh, protocol=tcp, bantime=600]
logpath  = /var/log/sshd.log
maxretry = 5

[ssh-bsd-ipfw]

enabled  = false
filter   = sshd
action   = bsd-ipfw[port=ssh,table=1]
logpath  = /var/log/auth.log
maxretry = 5

[apache-tcpwrapper]

enabled  = false
filter	 = apache-auth
action   = hostsdeny
logpath  = /var/log/apache*/*error.log
           /home/www/myhomepage/error.log
maxretry = 6

[apache-modsecurity]

enabled  = false
filter	 = apache-modsecurity
action   = iptables-multiport[name=apache-modsecurity,port="80,443"]
logpath  = /var/log/apache*/*error.log
           /home/www/myhomepage/error.log
maxretry = 2

[apache-overflows]

enabled  = false
filter	 = apache-overflows
action   = iptables-multiport[name=apache-overflows,port="80,443"]
logpath  = /var/log/apache*/*error.log
           /home/www/myhomepage/error.log
maxretry = 2

[apache-nohome]

enabled  = false
filter	 = apache-nohome
action   = iptables-multiport[name=apache-nohome,port="80,443"]
logpath  = /var/log/apache*/*error.log
           /home/www/myhomepage/error.log
maxretry = 2

[nginx-http-auth]

enabled = false
filter  = nginx-http-auth
action  = iptables-multiport[name=nginx-http-auth,port="80,443"]
logpath = /var/log/nginx/error.log

[squid]

enabled = false
filter  = squid
action  = iptables-multiport[name=squid,port="80,443,8080"]
logpath = /var/log/squid/access.log

[postfix-tcpwrapper]

enabled  = false
filter   = postfix
action   = hostsdeny[file=/not/a/standard/path/hosts.deny]
           sendmail[name=Postfix, dest=you@example.com]
logpath  = /var/log/postfix.log
bantime  = 300

[cyrus-imap]

enabled = false
filter  = cyrus-imap
action  = iptables-multiport[name=cyrus-imap,port="143,993"]
logpath = /var/log/mail*log

[courierlogin]

enabled = false
filter  = courierlogin
action  = iptables-multiport[name=courierlogin,port="25,110,143,465,587,993,995"]
logpath = /var/log/mail*log

[couriersmtp]

enabled = false
filter  = couriersmtp
action  = iptables-multiport[name=couriersmtp,port="25,465,587"]
logpath = /var/log/mail*log

[qmail-rbl]

enabled = false
filter  = qmail
action  = iptables-multiport[name=qmail-rbl,port="25,465,587"]
logpath = /service/qmail/log/main/current

[sieve]

enabled = false
filter  = sieve
action  = iptables-multiport[name=sieve,port="25,465,587"]
logpath = /var/log/mail*log

[vsftpd-notification]

enabled  = false
filter   = vsftpd
action   = sendmail-whois[name=VSFTPD, dest=shared@mandic.net.br]
logpath  = /var/log/vsftpd.log
maxretry = 5
bantime  = 1800

[vsftpd-iptables]

enabled  = false
filter   = vsftpd
action   = iptables[name=VSFTPD, port=ftp, protocol=tcp]
           sendmail-whois[name=VSFTPD, dest=shared@mandic.net.br]
logpath  = /var/log/vsftpd.log
maxretry = 5
bantime  = 1800

[apache-badbots]

enabled  = false
filter   = apache-badbots
action   = iptables-multiport[name=BadBots, port="http,https"]
           sendmail-buffered[name=BadBots, lines=5, dest=you@example.com]
logpath  = /var/www/*/logs/access_log
bantime  = 172800
maxretry = 1

[apache-shorewall]

enabled  = false
filter   = apache-noscript
action   = shorewall
           sendmail[name=Postfix, dest=you@example.com]
logpath  = /var/log/apache2/error_log

[roundcube-iptables]

enabled  = false
filter   = roundcube-auth
action   = iptables-multiport[name=RoundCube, port="http,https"]
logpath  = /var/log/roundcube/userlogins

[sogo-iptables]

enabled  = false
filter   = sogo-auth
action   = iptables-multiport[name=SOGo, port="http,https"]
logpath  = /var/log/sogo/sogo.log

[groupoffice]

enabled  = false
filter   = groupoffice
action   = iptables-multiport[name=groupoffice, port="http,https"]
logpath  = /home/groupoffice/log/info.log 

[openwebmail]

enabled  = false
filter   = openwebmail
logpath  = /var/log/openwebmail.log
action   = ipfw
           sendmail-whois[name=openwebmail, dest=you@example.com]
maxretry = 5

[horde]

enabled  = false
filter   = horde
logpath  = /var/log/horde/horde.log
action   = iptables-multiport[name=horde, port="http,https"]
maxretry = 5

[php-url-fopen]

enabled  = false
action   = iptables-multiport[name=php-url-open, port="http,https"]
filter   = php-url-fopen
logpath  = /var/www/*/logs/access_log
maxretry = 1

[suhosin]

enabled  = false
filter   = suhosin
action   = iptables-multiport[name=suhosin, port="http,https"]
logpath  = /var/log/lighttpd/error.log
maxretry = 2

[lighttpd-auth]

enabled  = false
filter   = lighttpd-auth
action   = iptables-multiport[name=lighttpd-auth, port="http,https"]
logpath  = /var/log/lighttpd/error.log
maxretry = 2

[ssh-ipfw]

enabled  = false
filter   = sshd
action   = ipfw[localhost=192.168.0.1]
           sendmail-whois[name="SSH,IPFW", dest=you@example.com]
logpath  = /var/log/auth.log
ignoreip = 168.192.0.1


[named-refused-tcp]

enabled  = false
filter   = named-refused
action   = iptables-multiport[name=Named, port="domain,953", protocol=tcp]
           sendmail-whois[name=Named, dest=you@example.com]
logpath  = /var/log/named/security.log
ignoreip = 168.192.0.1

[nsd]

enabled = false
filter  = nsd
action  = iptables-multiport[name=nsd-tcp, port="domain", protocol=tcp]
          iptables-multiport[name=nsd-udp, port="domain", protocol=udp]
logpath = /var/log/nsd.log

[asterisk]

enabled  = false
filter   = asterisk
action   = iptables-multiport[name=asterisk-tcp, port="5060,5061", protocol=tcp]
           iptables-multiport[name=asterisk-udp, port="5060,5061", protocol=udp]
           sendmail-whois[name=Asterisk, dest=you@example.com, sender=fail2ban@example.com]
logpath  = /var/log/asterisk/messages
maxretry = 10

[freeswitch]

enabled  = false
filter   = freeswitch
logpath  = /var/log/freeswitch.log
maxretry = 10
action   = iptables-multiport[name=freeswitch-tcp, port="5060,5061,5080,5081", protocol=tcp]
           iptables-multiport[name=freeswitch-udp, port="5060,5061,5080,5081", protocol=udp]

[ejabberd-auth]

enabled = false
filter = ejabberd-auth
logpath = /var/log/ejabberd/ejabberd.log
action   = iptables[name=ejabberd, port=xmpp-client, protocol=tcp]

[asterisk-tcp]

enabled  = false
filter   = asterisk
action   = iptables-multiport[name=asterisk-tcp, port="5060,5061", protocol=tcp]
           sendmail-whois[name=Asterisk, dest=you@example.com, sender=fail2ban@example.com]
logpath  = /var/log/asterisk/messages
maxretry = 10

[asterisk-udp]

enabled  = false
filter	 = asterisk
action   = iptables-multiport[name=asterisk-udp, port="5060,5061", protocol=udp]
           sendmail-whois[name=Asterisk, dest=you@example.com, sender=fail2ban@example.com]
logpath  = /var/log/asterisk/messages
maxretry = 10

[mysqld-iptables]

enabled  = false
filter   = mysqld-auth
action   = iptables[name=mysql, port=3306, protocol=tcp]
           sendmail-whois[name=MySQL, dest=root, sender=fail2ban@example.com]
logpath  = /var/log/mysqld.log
maxretry = 5

[mysqld-syslog]

enabled  = false
filter   = mysqld-auth
action   = iptables[name=mysql, port=3306, protocol=tcp]
logpath  = /var/log/daemon.log
maxretry = 5

[recidive]

enabled  = false
filter   = recidive
logpath  = /var/log/fail2ban.log
action   = iptables-allports[name=recidive,protocol=all]
           sendmail-whois-lines[name=recidive, logpath=/var/log/fail2ban.log]
bantime  = 604800  ; 1 week
findtime = 86400   ; 1 day
maxretry = 5

[ssh-pf]

enabled  = false
filter   = sshd
action   = pf
logpath  = /var/log/sshd.log
maxretry = 5

[3proxy]

enabled = false
filter  = 3proxy
action  = iptables[name=3proxy, port=3128, protocol=tcp]
logpath = /var/log/3proxy.log

[exim]

enabled = false
filter  = exim
action  = iptables-multiport[name=exim,port="25,465,587"]
logpath = /var/log/exim/mainlog

[exim-spam]

enabled = false
filter  = exim-spam
action  = iptables-multiport[name=exim-spam,port="25,465,587"]
logpath = /var/log/exim/mainlog

[perdition]

enabled = false
filter  = perdition
action  = iptables-multiport[name=perdition,port="110,143,993,995"]
logpath = /var/log/maillog

[uwimap-auth]

enabled = false
filter  = uwimap-auth
action  = iptables-multiport[name=uwimap-auth,port="110,143,993,995"]
logpath = /var/log/maillog

[osx-ssh-ipfw]

enabled  = false
filter   = sshd
action   = osx-ipfw
logpath  = /var/log/secure.log
maxretry = 5

[ssh-apf]

enabled = false
filter  = sshd
action  = apf[name=SSH]
logpath = /var/log/secure
maxretry = 5

[osx-ssh-afctl]

enabled  = false
filter   = sshd
action   = osx-afctl[bantime=600]
logpath  = /var/log/secure.log
maxretry = 5

[webmin-auth]

enabled = false
filter  = webmin-auth
action  = iptables-multiport[name=webmin,port="10000"]
logpath = /var/log/auth.log

[dovecot]

enabled = false
filter  = dovecot
action  = iptables-multiport[name=dovecot, port="pop3,pop3s,imap,imaps,submission,465,sieve", protocol=tcp]
logpath = /var/log/mail.log

[dovecot-auth]

enabled = false
filter  = dovecot
action  = iptables-multiport[name=dovecot-auth, port="pop3,pop3s,imap,imaps,submission,465,sieve", protocol=tcp]
logpath = /var/log/secure

[solid-pop3d]

enabled = false
filter  = solid-pop3d
action  = iptables-multiport[name=solid-pop3, port="pop3,pop3s", protocol=tcp]
logpath = /var/log/mail.log

[selinux-ssh]
enabled  = false
filter   = selinux-ssh
action   = iptables[name=SELINUX-SSH, port=ssh, protocol=tcp]
logpath  = /var/log/audit/audit.log
maxretry = 5

[ssh-blocklist]

enabled  = false
filter   = sshd
action   = iptables[name=SSH, port=ssh, protocol=tcp]
           sendmail-whois[name=SSH, dest=you@example.com, sender=fail2ban@example.com, sendername="Fail2Ban"]
           blocklist_de[email="fail2ban@example.com", apikey="xxxxxx", service=%(filter)s]
logpath  = /var/log/sshd.log
maxretry = 20

[nagios]
enabled  = false
filter   = nagios
action   = iptables[name=Nagios, port=5666, protocol=tcp]
           sendmail-whois[name=Nagios, dest=you@example.com, sender=fail2ban@example.com, sendername="Fail2Ban"]
logpath  = /var/log/messages     ; nrpe.cfg may define a different log_facility
maxretry = 1

[my-vsftpd-iptables]
 
enabled  = true
filter   = vsftpd
action   = iptables[name=VSFTPD, port=ftp, protocol=tcp]
           sendmail-whois[name=VSFTPD, dest=shared@mandic.net.br]
logpath  = /var/log/vsftpd.log
END

service fail2ban start
chkconfig fail2ban on

# Inslanado versÃ£do PHP
prompt="Qual versÃ£de PHP deseja instalar:"
options=( "PHP 5.6" "PHP 5.5" "PHP 5.4" "PHP 5.3" "Exit" )
echo "========================================================================="
echo "                      Selecione a VersÃ£do PHP           "
echo "========================================================================="

PS3="$prompt"
select opt in "${options[@]}" ; do

    case "$REPLY" in
    1) yum -y --enablerepo=remi,remi-php56 install php php-opcache php-cli php-common php-mysql php-bcmath php-dba php-devel php-embedded php-imap php-ldap php-mbstring php-mcrypt php-pdo php-soap && clear && exit 1;;
    2) yum -y --enablerepo=remi,remi-php55 install php php-opcache php-cli php-common php-mysql php-bcmath php-dba php-devel php-embedded php-imap php-ldap php-mbstring php-mcrypt php-pdo php-soap && clear && exit 1;;
    3) yum -y --enablerepo=remi,remi-php54 install php php-cli php-common php-mysql php-bcmath php-dba php-devel php-embedded php-imap php-ldap php-mbstring php-mcrypt php-pdo php-soap && clear && exit 1 ;;
    4) yum -y install php php-cli php-common php-php-mysql php-bcmath php-dba php-devel php-embedded php-imap php-ldap php-mbstring php-mcrypt php-pdo php-soap && clear && exit 1 ;;
    5) clear && echo "Cancelando..." && exit;;
    *) echo "por favor selecione uma das opÃ§s";continue;;

    esac

clear 
rm -r -f /etc/php.d/*opcache*
    cat > "/etc/php.ini" <<END
[PHP]
engine = On
short_open_tag = On
asp_tags = Off
precision = 14
output_buffering = 4096
zlib.output_compression = Off
implicit_flush = Off
unserialize_callback_func =
serialize_precision = 17
disable_functions = 
disable_classes =
zend.enable_gc = On
expose_php = Off
max_execution_time = 120
max_input_time = 600
memory_limit = $memory_limit
max_input_vars = 2000
realpath_cache_size = 4096k
realpath_cache_ttl = 360
error_reporting = E_ALL & ~E_DEPRECATED & ~E_STRICT
display_errors = Off
display_startup_errors = Off
log_errors = On
log_errors_max_len = 1024
ignore_repeated_errors = Off
ignore_repeated_source = Off
report_memleaks = On
track_errors = Off
html_errors = On
variables_order = "GPCS"
request_order = "GP"
register_argc_argv = Off
auto_globals_jit = On
post_max_size = 100M
auto_prepend_file =
auto_append_file =
default_mimetype = "text/html"
default_charset = "UTF-8"
doc_root =
user_dir =
enable_dl = Off
cgi.fix_pathinfo=0
file_uploads = On
upload_max_filesize = 120M
max_file_uploads = 20
allow_url_fopen = On
allow_url_include = Off
default_socket_timeout = 60
cli_server.color = On

[Date]
date.timezone = Asia/Bangkok

[filter]

[iconv]

[intl]

[sqlite]

[sqlite3]

[Pcre]

[Pdo]

[Pdo_mysql]
pdo_mysql.cache_size = 2000
pdo_mysql.default_socket=

[Phar]

[mail function]
SMTP = localhost
smtp_port = 25
sendmail_path = /usr/sbin/sendmail -t -i
mail.add_x_header = On

[SQL]
sql.safe_mode = Off

[ODBC]
odbc.allow_persistent = On
odbc.check_persistent = On
odbc.max_persistent = -1
odbc.max_links = -1
odbc.defaultlrl = 4096
odbc.defaultbinmode = 1

[Interbase]
ibase.allow_persistent = 1
ibase.max_persistent = -1
ibase.max_links = -1
ibase.timestampformat = "%Y-%m-%d %H:%M:%S"
ibase.dateformat = "%Y-%m-%d"
ibase.timeformat = "%H:%M:%S"

[MySQL]
mysql.allow_local_infile = On
mysql.allow_persistent = On
mysql.cache_size = 2000
mysql.max_persistent = -1
mysql.max_links = -1
mysql.default_port =
mysql.default_socket =
mysql.default_host =
mysql.default_user =
mysql.default_password =
mysql.connect_timeout = 60
mysql.trace_mode = Off

[MySQLi]
mysqli.max_persistent = -1
mysqli.allow_persistent = On
mysqli.max_links = -1
mysqli.cache_size = 2000
mysqli.default_port = 3306
mysqli.default_socket =
mysqli.default_host =
mysqli.default_user =
mysqli.default_pw =
mysqli.reconnect = Off

[mysqlnd]
mysqlnd.collect_statistics = On
mysqlnd.collect_memory_statistics = Off

[OCI8]

[PostgreSQL]
pgsql.allow_persistent = On
pgsql.auto_reset_persistent = Off
pgsql.max_persistent = -1
pgsql.max_links = -1
pgsql.ignore_notice = 0
pgsql.log_notice = 0

[Sybase-CT]
sybct.allow_persistent = On
sybct.max_persistent = -1
sybct.max_links = -1
sybct.min_server_severity = 10
sybct.min_client_severity = 10

[bcmath]
bcmath.scale = 0

[browscap]

[Session]
session.save_handler = files
session.use_cookies = 1
session.use_only_cookies = 1
session.name = PHPSESSID
session.auto_start = 0
session.cookie_lifetime = 0
session.cookie_path = /
session.cookie_domain =
session.cookie_httponly =
session.serialize_handler = php
session.gc_probability = 1
session.gc_divisor = 1000
session.gc_maxlifetime = 1440
session.bug_compat_42 = Off
session.bug_compat_warn = Off
session.referer_check =
session.cache_limiter = nocache
session.cache_expire = 180
session.use_trans_sid = 0
session.hash_function = 0
session.hash_bits_per_character = 5
url_rewriter.tags = "a=href,area=href,frame=src,input=src,form=fakeentry"

[MSSQL]
mssql.allow_persistent = On
mssql.max_persistent = -1
mssql.max_links = -1
mssql.min_error_severity = 10
mssql.min_message_severity = 10
mssql.compatability_mode = Off

[Assertion]

[mbstring]

[gd]

[exif]

[Tidy]
tidy.clean_output = Off

[soap]
soap.wsdl_cache_enabled=1
soap.wsdl_cache_dir="/tmp"
soap.wsdl_cache_ttl=86400
soap.wsdl_cache_limit = 5

[sysvshm]

[ldap]
ldap.max_links = -1

[mcrypt]

[dba]

END

rm -f /etc/php.d/*opcache*
cat > "/etc/php.d/opcache.ini" <<END
zend_extension=opcache.so
opcache.enable=1
opcache.enable_cli=1
opcache.memory_consumption=40
opcache.interned_strings_buffer=16
opcache.max_accelerated_files=3000
opcache.max_wasted_percentage=5
opcache.use_cwd=1
opcache.validate_timestamps=1
opcache.revalidate_freq=5
opcache.fast_shutdown=1
END

service iptables restart

clear
done


