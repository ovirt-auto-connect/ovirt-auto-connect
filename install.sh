#!/bin/bash

if which python > /dev/null 2>&1 || which python3 > /dev/null 2>&1; then
	python_version=`python --version 2>&1 | awk '{print $2}'`
	echo "Python version $python_version is installed"
else
	echo "No Python executable is found"
	exit 1
fi

if which pip > /dev/null 2>&1; then
	pip_version=`pip --version 2>&1 | awk '{print $2}'`
	echo "pip version $python_version is installed"
else
	echo "No pip executable is found"
	exit 1
fi

sudo pip install -r requirements.txt
sudo install -m 755 "ovirt-auto-connect.py" /usr/local/bin/ovirt-auto-connect
sudo mkdir -p /usr/share/applications
sudo install -m 644 "ovirt-auto-connect.desktop" /usr/share/applications/
sudo install -m 644 "EltexRootCA.pem" /etc/ssl/certs/
echo "Initial set credentials"
./ovirt-auto-connect.py -s
