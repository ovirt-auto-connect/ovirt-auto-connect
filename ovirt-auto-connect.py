#!/usr/bin/env python3

import ovirtsdk4 as sdk
import ovirtsdk4.types as types

import argparse
import getpass
import time
import subprocess
import keyring
import os
import sys

REMOTE_VIEWER_PATH='/usr/bin/remote-viewer'
VV_PATH='/tmp/srw.vv'

def get_vv_file(user, password, profile, vm=None):
	ca_file='/etc/ssl/certs/EltexRootCA.pem'
	if not os.path.exists(ca_file):
		ca_file='/usr/local/etc/ssl/certs/EltexRootCA.pem'

	with sdk.Connection(
		url='https://ovirt.eltex.loc/ovirt-engine/api',
		username=f'{user}@{profile}',
		password=password,
		ca_file=ca_file,
	) as connection:
		system_service = connection.system_service()
		vms_service = system_service.vms_service()
		if vm:
			vms = vms_service.list(search=f'name={vm}')
		else:
			vms = vms_service.list()

		if not vms:
			print('VM not found')
			raise RuntimeError

		vm = vms[0]

		vm_service = vms_service.vm_service(vm.id)

		if vm.status == types.VmStatus.DOWN:
			vm_service.start()

		while True:
			vm = vm_service.get()
			if vm.status == types.VmStatus.UP:
				break
			time.sleep(2)

		consoles_service = vm_service.graphics_consoles_service()
		consoles = consoles_service.list()
		console = next(
			(c for c in consoles if c.protocol == types.GraphicsType.SPICE),
			None
		)

		if not console:
			print('No SPICE console available')
			raise RuntimeError

		console_service = consoles_service.console_service(console.id)
		return console_service.remote_viewer_connection_file()

backend = keyring.core.load_keyring('keyrings.alt.file.PlaintextKeyring')
if not backend:
	print("Required keyring not installed")
	exit(1)

keyring.set_keyring(backend)

parser = argparse.ArgumentParser()
parser.add_argument('-u', '--user', help='LDAP username', dest='user')
parser.add_argument('-p', '--profile', help='oVirt profile', dest='profile')
parser.add_argument('-v', '--vm', help='VM name', dest='vm', nargs='?')
parser.add_argument('-s', '--setup', help='Initial setup', action='store_true')
args = parser.parse_args()

if args.setup:
	user = input('Enter username for oVirt\n')
	keyring.set_password("ovirt-no-pass", "user", user)

	print('Enter password for oVirt user', user)
	password = getpass.getpass()
	keyring.set_password("ovirt-no-pass", "password", password)

	profile = input(f'Enter profile for oVirt {user}\n')
	keyring.set_password("ovirt-no-pass", "profile", profile)
	print('Setup successful')
	exit(0)

if args.user:
	keyring.set_password("ovirt-no-pass", "user", args.user)
	print('Enter password for oVirt user', args.user)
	password = getpass.getpass()
	keyring.set_password("ovirt-no-pass", "password", password)

if args.profile:
	keyring.set_password("ovirt-no-pass", "profile", args.profile)

if args.vm:
	keyring.set_password("ovirt-no-pass", "vm", args.vm)
	print('Set default vm successful', args.vm)

if args.user or args.profile:
	print('Set credentials successful')
	exit(0)

user = keyring.get_password("ovirt-no-pass", "user")
password = keyring.get_password("ovirt-no-pass", "password")
profile = keyring.get_password("ovirt-no-pass", "profile")
vm = keyring.get_password("ovirt-no-pass", "vm")

if not user:
	print("Not found saved users")
	exit(1)

if not password:
	print("Not found saved password for user", user)
	exit(1)

if not profile:
	print("Not found saved profile for user", user)
	exit(1)

file = get_vv_file(user, password, profile, vm)

with open(VV_PATH, "w") as f:
	f.write(file)

if sys.platform == 'darwin':
	subprocess.Popen(['open', '-a', 'aSPICE', VV_PATH], start_new_session=True)
else:
	subprocess.Popen([REMOTE_VIEWER_PATH, VV_PATH], start_new_session=True)
