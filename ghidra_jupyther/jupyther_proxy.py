#Shit
#@author Sen
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 

import socket
import threading
import struct
import traceback
import ast
import atexit
import sys
from cStringIO import StringIO
from random import randrange

PWD = 'LOLOLOLOLPWDPWD'

def read_byte(sock):
	return ord(sock.recv(1))

def write_byte(sock, b):
	return sock.send(chr(b))

def read_packet(sock):
	print 'read_packet'
	toread = struct.unpack('<l', sock.recv(4))[0]
	print 'packet_len:', toread
	buf = bytearray()
	while len(buf) < toread:
		bb = sock.recv(toread)
		buf.extend(bb)
	# jython is retarded
	'''buf = bytearray(toread)
	view = memoryview(buf)
	while toread:
		nbytes = sock.recv_into(view, toread)
		view = view[nbytes:]
		toread -= nbytes'''
	return buf

def write_packet(sock, msg):
	sock.sendall(struct.pack('<l', len(msg)))
	return sock.sendall(msg)

def crypt_pwd(pwd, x):
	return ''.join(chr(b ^ x) for b in bytearray(pwd))

def fancy_eval(code, globals, locals):
	code_ast = ast.parse(code)
	last_expr = None
	print code_ast, code_ast.body
	if type(code_ast.body[-1]) == ast.Expr:
		# jython is retarded and pop() doesn't work
		# code_ast.body.pop()
		last_expr = code_ast.body[-1]
		del code_ast.body[-1]
	print code_ast, code_ast.body, last_expr
	custom_stdout = StringIO()
	out = ''
	try:
		old_stdout = sys.stdout
		old_stderr = sys.stderr
		sys.stdout = custom_stdout
		sys.stderr = custom_stdout
		exec(compile(code_ast, '<string>', 'exec'), globals, locals)
		if last_expr:
			last_expr.lineno = 0
			last_expr.col_offset = 0
			out = eval(compile(ast.Expression(last_expr.value), '<string>', 'eval'), globals, locals)
	except:
		out = traceback.format_exc()
	finally:
		sys.stdout = old_stdout
		sys.stderr = old_stderr
	return out, custom_stdout.getvalue()

#class Server(threading.Thread):
class Server:
	def __init__(self, a):
		#threading.Thread.__init__(self)
		self.sock, self.address = a

	def run(self):
		print '%s:%d connected' % self.address
		sock = self.sock
		r = randrange(0, 256)
		print 'rand'
		write_byte(sock, r)
		pwd = read_packet(sock)
		print 'pwd', pwd
		if crypt_pwd(pwd, r) != PWD:
			print 'NOPE!'
			return

		print 'loop'
		locals_dict = {}
		while True:
			msg = str(read_packet(sock))
			print 'received:'
			print msg
			ret, stdout = fancy_eval(msg, globals(), locals_dict)
			final_out = stdout + str(ret)
			write_packet(sock, final_out)
			print final_out

	def start(self):
		self.run()
		

def client(sock):
	b = read_byte(sock)
	write_packet(sock, crypt_pwd(PWD, b))
	write_packet(sock, 'a=1\nprint "test"\nfor i in range(10): a+=2\na+666')
	out = read_packet(sock)
	print out

if 'ghidra' in locals():
	mode = 'server'
else:
	mode = sys.argv[1]
server_address = ('localhost', 6666)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
atexit.register(lambda: sock.close())
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

if mode == 'client':
	sock.connect(server_address)
	client(sock)
elif mode == 'server':
	sock.bind(server_address)
	sock.listen(1)
	while True:
		try:
			Server(sock.accept()).start()
		except:
			pass
else:
	print 'NOPE'
