#!/usr/bin/python

import sys, os, argparse, curses, xml, locale, math, subprocess

from time import sleep
from multiprocessing import Process

from net_scan_structs import Display_Types
from net_scan_host import Host, DSHost

import xml.etree.ElementTree as ET

file_available = False
need_clear = False
filter_state = "OFF"

target_file_name = "targets"
spec_res_dir = "specific_results/"

log_buffer = []

cmd_buffer = []
cmd_index = len(cmd_buffer)

def _print(string,log_only=False):
	global mainscr
	global log_buffer
	if not log_only:
		if args.display_option  == Display_Types.CLI:
			print string
		elif args.display_option  == Display_Types.NCURSES:
			mainscr.addstr(mainscr.getmaxyx()[0]-1,mainscr.getmaxyx()[1]/2," "*((mainscr.getmaxyx()[1]/2)-1))
			mainscr.addstr(mainscr.getmaxyx()[0]-1,mainscr.getmaxyx()[1]/2,">"+str(string))
			refresh_all()
		elif args.display_option == Display_Types.GRAPHIC:
			pass
	log_buffer.append(str(string))

def dump_log(to_file=True):
	global log_buffer
	if to_file:
		with open("scan_log.txt",'w') as f:
			for l in log_buffer:
				f.write(l+'\n')
	for l in log_buffer:
		print l

def refresh_all():
	global mainscr
	global dscanscr
	if args.display_option  == Display_Types.NCURSES:
		mainscr.refresh()
		mainscr.redrawwin()
		if dscanscr != None:
			dscanscr.redrawwin()
			dscanscr.overwrite(mainscr)
			dscanscr.refresh()

hosts_res = []
ip_width = 24
def scan(hosts):
	global need_clear
	global filter_state
	global ip_width
	global file_available
	global old_amnt_of_hosts
	if file_available:
		try:
			res = ET.parse('res.xml')
			#_print("File parsed.")
			root = res.getroot()
			global hosts_res
			hosts_res = []
			for child in filter(lambda c: c.tag == 'host', root):
				hosts_res.append(Host(child))
			if args.display_option == Display_Types.CLI:
				for c in hosts_res:
					print c.summary
			redraw_hosts()
			if len(hosts_res) != old_amnt_of_hosts:
				on_hosts_amnt_change()
			old_amnt_of_hosts = len(hosts_res)
		except xml.etree.ElementTree.ParseError:
			#_print("Waiting for file.")
			pass
	else:
		#_print("File not available.")
		pass

old_amnt_of_hosts = len(hosts_res)
def on_hosts_amnt_change():
	global need_clear
	need_clear = True

def redraw_hosts():
	global ip_width
	global need_clear
	global filter_state
	global hosts_res
	if args.display_option  == Display_Types.NCURSES:
		count = 0
		inc = 0
		max_in_x = (mainscr.getmaxyx()[1]/ip_width)
		max_in_y = (mainscr.getmaxyx()[0] - 3)
		if need_clear:
			mainscr.clear()
			need_clear = False
		for c in hosts_res:
			if count/max_in_x < max_in_y:
				index_str = "("+("%3d"%count).replace(" ","0")+")"
				if filter_state == "UP":
					if c.state == 'up':
						mainscr.addstr(inc/max_in_x,(inc%max_in_x)*ip_width,(index_str+" "+c.summary).encode('utf-8'))
						inc += 1
				elif filter_state == "DOWN":
					if c.state != 'up':
						mainscr.addstr(inc/max_in_x,(inc%max_in_x)*ip_width,(index_str+" "+c.summary).encode('utf-8'))
						inc += 1
				else:
					mainscr.addstr(count/max_in_x,(count%max_in_x)*ip_width,(index_str+" "+c.summary).encode('utf-8'))
			else:
				break
			count += 1
		mainscr.addstr(mainscr.getmaxyx()[0]-1,0,":"+input_str)
		refresh_all()

dscanscr = None
def dscan(host,rescan=False):
	global dscanscr
	dscanscr = curses.newwin(mainscr.getmaxyx()[0]/2,mainscr.getmaxyx()[1]/2,mainscr.getmaxyx()[0]/4,mainscr.getmaxyx()[1]/4)
	dscanscr.border()
	dscanscr.addstr(0,(dscanscr.getmaxyx()[1]/2)-(len(host.addr)/2),host.addr)
	dscanscr.addstr(1,1,"MAC: "+host.mac)
	dscanscr.addstr(2,1,"Vendor: "+host.vendor)
	dscanscr.addstr(3,1,"Loading more info...")
	dscanscr.refresh()
	if not os.path.isfile(spec_res_dir+host.addr+".xml") or rescan:
		subprocess.call("sudo nmap -v "+host.addr+" -oX "+spec_res_dir+host.addr+".xml",shell=True,stdout=devnull)
	res = ET.parse(spec_res_dir+host.addr+".xml")
	root = res.getroot()
	host_res = DSHost(filter(lambda c: c.tag == 'host', root)[0])
	dscanscr.addstr(3,1," "*(dscanscr.getmaxyx()[1]-2))
	dscanscr.addstr(3,1,"Number of open ports: "+str(host_res.num_of_ports))
	if host_res.num_of_ports > 0:
		i = 0
		while i < host_res.num_of_ports and i < (dscanscr.getmaxyx()[1]-5):
			dscanscr.addstr(4+i,1,"Port "+host_res.ports[i].number+": "+host_res.ports[i].protocol)
			i += 1

def cmd_proc(commands):
	global bg_proc
	global dscanscr
	global need_clear
	global filter_state
	commands_list = commands.split(" ")
	if commands.upper() == "QUIT" or commands.upper() == "EXIT":
		curses.endwin()
		bg_proc.terminate()
		exit()
	elif commands.upper() == "FLASH":
		curses.flash()
	elif commands_list[0].upper() == "DSCAN" and len(commands_list) > 1:
		if len(commands_list) == 2:
			dscan(hosts_res[int(commands_list[1])])
		else:
			cmd_args = commands_list[1:len(commands_list)-1:]
			if '-r' in cmd_args:
				dscan(hosts_res[int(commands_list[-1])],True)
	elif commands.upper() == "CLEAR":
		dscanscr = None
		need_clear = True
		refresh_all()
	elif commands_list[0].upper() == "FILTER" and len(commands_list) > 1:
		need_clear = True
		if commands_list[1].upper() == "UP":
			filter_state = "UP"
		elif commands_list[1].upper() == "DOWN":
			filter_state = "DOWN"
		elif commands_list[1].upper() == "NONE" or commands_list[1].upper() == "OFF":
			filter_state = "OFF"
		redraw_hosts()
	elif commands_list[0].upper() == "CHGRP" and len(commands_list) > 2:
		hosts_res[int(commands_list[1])].group = commands_list[2]
	elif commands.upper() == "REDRAW":
		redraw_hosts()
	elif commands_list[0].upper() == "RM" and len(commands_list) > 1:
		del hosts_res[int(commands_list[1])]
		with open(target_file_name,'w') as t:
			for e in hosts_res:
				t.write(e.addr+"\n")
		refresh_all()
	elif commands_list[0].upper() == "ADD" and len(commands_list) > 1:
		need_clear = True
		with open(target_file_name,"a") as t:
			t.write("\n"+commands_list[1]+"\n")
		_print("Wrote to target list.")
		refresh_all()


devnull = open('/dev/null', 'w')
def nmap_loop():
	global file_available
	global target_file_name
	while 1:
		file_available = False
		subprocess.call("nmap -n -v -sn -iL "+target_file_name+" -oX res.xml",shell=True,stdout=devnull)
		file_available = True
		sleep(1)

input_str = ""
def on_key_down(key):
	global input_str
	global cmd_buffer
	global cmd_index
	global need_clear
	def refresh():
		global input_str
		mainscr.addstr(mainscr.getmaxyx()[0]-1,0," "*(mainscr.getmaxyx()[1]/2))
		mainscr.addstr(mainscr.getmaxyx()[0]-1,0,":"+input_str)
		refresh_all()
	if key == ord('Q'):
		curses.endwin()
		bg_proc.terminate()
		exit()
	elif key > 0 and key < 256:
		if key != 10: #Enter
			input_str += chr(key)
		else:
			cmd_proc(input_str)
			cmd_buffer.append(input_str)
			cmd_index = len(cmd_buffer)
			input_str = ""
		refresh()
	elif key == 259: #Up arrow
		if (cmd_index - 1) in xrange(len(cmd_buffer)): cmd_index -= 1
		try: input_str = cmd_buffer[cmd_index]
		except IndexError: pass
		refresh()
	elif key == 258: #Down arrow
		if (cmd_index + 1) in xrange(len(cmd_buffer)): cmd_index += 1
		try: input_str = cmd_buffer[cmd_index]
		except IndexError: pass
		refresh()
	elif key == curses.KEY_BACKSPACE:
		input_str = input_str[:-1]
		refresh()
	elif key == curses.KEY_RESIZE: #On screen resize
		mainscr.clear()
		redraw_hosts()
		refresh()

parser = argparse.ArgumentParser(description='Network scanner.')
mainscr = None
bg_proc = Process(target=nmap_loop)

parser.add_argument('-d','--display', nargs='?', dest='display_option',help='How the output should be displayed')
parser.add_argument('-t','--target', nargs='?', dest='target',help='Target network',required=True)

args = parser.parse_args()

try:
	if __name__ == "__main__":
		if os.geteuid() != 0:
			print "Need root for deep scans."
			exit()
		if args.display_option == Display_Types.NCURSES:
			#global hosts_res
			locale.setlocale(locale.LC_ALL,"")
			mainscr = curses.initscr()
			mainscr.nodelay(True)
			mainscr.keypad(1)
			curses.noecho()
			curses.cbreak()
			curses.curs_set(0)
			_print("Loading...")
			if not os.path.exists(spec_res_dir):
				os.makedirs(spec_res_dir)
			file_available = False
			subprocess.call("nmap -n -v -sn "+args.target+" -oX res.xml",shell=True,stdout=devnull)
			file_available = True
			scan(args.target)
			with open(target_file_name,'w') as t:
				for h in hosts_res:
					t.write(h.addr+"\n")

		elif args.display_option == Display_Types.CLI:
			print 'Output will be display in CLI'
		else:
			print 'No display type specified. Will use CLI'
			args.display_option = Display_Types.CLI
		try:
			if args.display_option == Display_Types.NCURSES:
				bg_proc.start()
				while 1:
					scan(args.target)
					on_key_down(mainscr.getch())
			elif args.display_option == Display_Types.CLI:
				_print("Scanning...")
				subprocess.call("nmap -n -v -sn "+args.target+" -oX res.xml",shell=True,stdout=devnull)
				file_available = True
				scan(args.target)
		except KeyboardInterrupt:
			curses.endwin()
			bg_proc.terminate()
			exit()
except Exception as e:
	curses.endwin()
	bg_proc.terminate()
	dump_log()
	raise