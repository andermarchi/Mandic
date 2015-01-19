#!/bin/bash

while [ x$username = "x" ]; do

read -p "Informe o Usuario : " username

if id -u $username >/dev/null 2>&1; then

echo "User already exists"

username=""

fi

done

while [ x$group = "x" ]; do

read -p "Informe o Grupo do Usuario : " group

if id -g $group >/dev/null 2>&1; then

echo "Grupo ja Existe"

else

groupadd $group

fi

done

read -p "Informe o bash [Somente se Necessario] : " bash

if [ x"$bash" = "x" ]; then

bash="/sbin/nologin"

fi

read -p "Informe o Home Directory [/home/$username] : " homedir

if [ x"$homedir" = "x" ]; then

homedir="/var/www/html/$username"

fi

read -p "As informacoes estao corretas [s/n]" confirm

if [ "$confirm" = "s" ]; then

useradd -g $group -s $bash -d $homedir -M $username

fi
