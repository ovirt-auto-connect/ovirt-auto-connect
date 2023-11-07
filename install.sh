#!/bin/bash

pip install -r requirements.txt
sudo install -m 755 "ovirt-auto-connect.py" /usr/local/bin/ovirt-auto-connect
sudo mkdir -p /usr/share/applications
sudo install -m 644 "ovirt-auto-connect.desktop" /usr/share/applications/
echo "Initial set credentials"
./ovirt-auto-connect.py -s
