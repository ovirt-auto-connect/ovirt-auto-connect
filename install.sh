#!/bin/bash

set -e

OS="$(uname -s)"

if which python > /dev/null 2>&1 || which python3 > /dev/null 2>&1; then
	if which python3 > /dev/null 2>&1; then
		PY=python3
	else
		PY=python
	fi
	python_version=`$PY --version 2>&1 | awk '{print $2}'`
	echo "Python version $python_version is installed"
else
	echo "No Python executable is found"
	exit 1
fi

PIP="$PY -m pip"

if ! $PIP --version > /dev/null 2>&1; then
	echo "No pip executable is found"
	exit 1
fi

pip_version=`$PIP --version 2>&1 | awk '{print $2}'`
echo "pip version $pip_version is installed"

if [ "$OS" = "Darwin" ]; then
	BREW_PY=/opt/homebrew/bin/python3
	if [ ! -x "$BREW_PY" ]; then
		BREW_PY=/usr/local/bin/python3
	fi
	if [ ! -x "$BREW_PY" ]; then
		echo "Homebrew python3 not found"
		exit 1
	fi

	python_version=`$BREW_PY --version 2>&1 | awk '{print $2}'`
	echo "Python version $python_version is installed"

	sudo mkdir -p /usr/local/lib/ovirt-auto-connect
	sudo install -m 644 "ovirt-auto-connect.py" /usr/local/lib/ovirt-auto-connect/ovirt-auto-connect.py

	if [ ! -x /usr/local/lib/ovirt-auto-connect/venv/bin/python ]; then
		sudo "$BREW_PY" -m venv /usr/local/lib/ovirt-auto-connect/venv
	fi

	sudo /usr/local/lib/ovirt-auto-connect/venv/bin/python -m pip install -U pip
	sudo /usr/local/lib/ovirt-auto-connect/venv/bin/python -m pip install -r requirements.txt

	sudo install -m 755 "macos/ovirt-auto-connect" /usr/local/bin/ovirt-auto-connect

	sudo mkdir -p /usr/local/etc/ssl/certs
	sudo install -m 644 "EltexRootCA.pem" /usr/local/etc/ssl/certs/EltexRootCA.pem
	sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "EltexRootCA.pem" || true

	APP_NAME="ovirt-auto-connect"
	APP_DIR="/Applications/${APP_NAME}.app"
	CONTENTS="$APP_DIR/Contents"
	MACOS_DIR="$CONTENTS/MacOS"

	sudo rm -rf "$APP_DIR"
	sudo mkdir -p "$MACOS_DIR"

	sudo install -m 644 "macos/Info.plist" "$CONTENTS/Info.plist"
	sudo install -m 755 "macos/run" "$MACOS_DIR/run"

	echo "Initial set credentials"
	/usr/local/bin/ovirt-auto-connect -s
else
	if ! sudo pip install -r requirements.txt ; then
		sudo pip install --break-system-packages -r requirements.txt
	fi
	sudo install -m 755 "ovirt-auto-connect.py" /usr/local/bin/ovirt-auto-connect
	sudo mkdir -p /usr/share/applications
	sudo install -m 644 "ovirt-auto-connect.desktop" /usr/share/applications/
	sudo install -m 644 "EltexRootCA.pem" /etc/ssl/certs/
	echo "Initial set credentials"
	$PY ./ovirt-auto-connect.py -s
fi
