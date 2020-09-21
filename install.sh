#!/bin/sh

# Dependencias
sudo apt-get update
sudo apt-get -y install iptables
sudo cpan -i -f Apache::Log::Parser

# Instalacion del servicio
sudo mkdir /opt/apache_eq2
sudo mv apache_eq2.service /etc/systemd/system/
sudo systemctl --system daemon-reload
sudo mv * /opt/apache_eq2/
chmod 0755 /opt/apache_eq2/*
sudo systemctl start apache_eq2.service
