#!/bin/bash
DOMAIN=$1
DATA="<VirtualHost *:80>
        ServerName $DOMAIN.com.br
        ServerAlias $DOMAIN.com.br www.$DOMAIN.com.br $DOMAIN.mandictemp.com.br
        DocumentRoot /var/www/html/$DOMAIN.com.br
        <Directory /var/www/html/$DOMAIN.com.br>
                Options -Indexes FollowSymLinks MultiViews
                AllowOverride All
        </Directory>
        CustomLog /var/log/httpd/$DOMAIN-access.log combined
        ErrorLog /var/log/httpd/$DOMAIN-error.log
        LogLevel warn
</VirtualHost>"
mkdir -p /var/www/html/$DOMAIN.com.br && chown deepftp:apache /var/www/html/$DOMAIN.com.br && echo "$DATA" > /etc/httpd/conf.d/$DOMAIN.com.br.conf && apachectl restart
