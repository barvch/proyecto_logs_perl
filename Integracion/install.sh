#!/bin/sh

sudo mkdir /opt/apache_eq2
sudo mv apache_eq2.service /etc/systemd/system/
sudo systemctl --system daemon-reload
sudo mv * /opt/apache_eq2/
chmod 0755 /opt/apache_eq2/*
