#!/usr/bin/env python3

import auparse
import sys
import os
import signal
from pathlib import Path

LOG = "/var/log/custom_audit.log"
interpret_fields = True
live = False

AT_FDCWD = 0xffffff9c
SKIP_EVENT_TYPES = [ 'DAEMON_CONFIG', 'USER_END', 'CRED_DISP', 'CRED_ACQ', 'LOGIN', 'USER_START', 'USER_ACCT', 'CONFIG_CHANGE', 'CRED_REFR', 'SERVICE_START', 'SERVICE_STOP' ]

# Gracefully handle daemon termination signals from auditd/audispd
def signal_handler(sig, frame):
	with open(LOG, "a") as log:
		log.write("exiting?\n")
	sys.exit(0)

signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGHUP, signal_handler)

process_map = {}

# returns the link target of /proc/<pid>/fd/<fd>, if runing live
# else return a contrived string
def get_pid_fd_name(pid, fd):
	if live:
		try:
			return Path(f"/proc/{pid}/fd/{fd}").readlink()
		except:
			pass
	path = f"<pid {pid} fd {fd}>"

def get_pid_exe(pid):
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except Exception as e:
        return "???"


def set_pid_info(pid, info):
	global process_map

	if not pid in process_map:
		process_map[pid] = {}

	for key in [ 'ppid', 'ses', 'proctitle', 'cmdline', 'exe' ]:
		if key in info:
			val = info[key]
		else:
			val = None

		if not key in process_map[pid] or process_map[pid][key] == None:
			process_map[pid][key] = val
#	process_map[pid]['ses'] = info['ses']
def exit_pid(pid):
	global process_map

	try:
		del process_map[pid]
	except:
		pass

def get_pid_field(pid, field):
	if pid in process_map and field in process_map[pid]:
		return process_map[pid][field]
	return None

def get_pid_name(pid):
	return get_pid_field(pid, 'exe')
def get_ppid(pid):
	return get_pid_field(pid, 'ppid')
	
def pid_ancestry(pid):
	if pid in process_map:
		exe = get_pid_name(pid)
		ret = f"{exe} ({pid})"
	else:
		ret = f"pid {pid}"

	pid = get_ppid(pid)
#	try:
#		print("ppid is {}".format(pid))
#	except:
#		pass
	while pid is not None:
#		try:
#			print(" pid is {}".format(pid))
#		except:
#			pass
#		print("parent: {}".format(pid))
		exe = get_pid_name(pid)
		if exe is None:
			exe = get_pid_exe(pid)

		ret = f"{exe} ({pid}) -> " + ret

		pid = get_ppid(pid)

	return ret






# get the field from the current record
# interpret_as: 'none', 'true', 'realpath', 'int', 'str'
# 'sock_family', 'sock_port', 'sock_address'
def extract_field(au, needle, interpret = False, interpret_as = 'none'):
	au.first_field()
	while True:
		if au.get_field_name() == needle:
			if interpret_as == 'none' or interpret_as == 'str':
				return au.get_field_str()
			elif interpret_as == 'true':
				return au.interpret_field()
			elif interpret_as == 'int':
				return au.get_field_int()
			elif interpret_as == 'realpath':
				return au.interpret_realpath()
			return au.get_field_str()
		if not au.next_field():
			break
	return None

def dump_event(au):
	au.first_record()
	au.first_field()
	while True:
		while True:
			au.first_field()

			print("  type: {} ({})".format(au.get_type(), au.get_type_name()))
			while True:

				field_name = au.get_field_name()
				field_value = au.get_field_str()
				print("    {} = {} ({})".format(field_name, field_value, au.interpret_field()))

				if not au.next_field():
					break

			if not au.next_record():
				break
		if not au.next_record():
			break

def process_syscall_clone(au):
	au.first_record()
	au.first_field()
	info = {}
	pid = extract_field(au, 'exit')
	ppid = extract_field(au, 'pid')
	pppid = extract_field(au, 'ppid')
	ses= extract_field(au, 'ses')
	exe = get_pid_name(ppid)

	if not au.next_record():
		proctitle = 'unknown'
	else:
		proctitle = extract_field(au, 'proctitle', 'true')


	set_pid_info(ppid, {
		'ppid': pppid,
		'ses' : ses,
		'proctitle' : proctitle,
		'exe' : exe
		})
		
	set_pid_info(pid, {
		'ppid': ppid,
		'ses' : ses,
		'proctitle' : proctitle,
		'exe' : exe
		})

	print(f"pid {ppid} (child of {pppid}) cloned {pid}")

	print("  ancestry: {}".format(pid_ancestry(pid)))
	print("dump: ")
	dump_event(au)



def process_syscall_execve(au):
	au.first_record()
	au.first_field()
	info = {}
	pid = extract_field(au, 'pid')
	ppid = extract_field(au, 'ppid')
	ses = extract_field(au, 'ses')
	exe = extract_field(au, 'exe')

	if not au.get_type_name() == 'SYSCALL':
		print("malformed event")
		return

	success = extract_field(au, 'success')
	if success == 'yes':
		if au.next_record() and au.get_type_name() == 'EXECVE':
			cwd = extract_field(au, 'cwd')

			argc = extract_field(au, 'argc', interpret_as='int')
			arg0 = extract_field(au, 'a0')
			cmdline = arg0 
			for i in range(1, argc):
				key = f"a{i}"
				arg = extract_field(au, key)
				cmdline = cmdline + ' ' + arg

			set_pid_info(pid, {
				'ses' : ses,
				'ppid' : ppid,
				'cmdline' : cmdline,
				'exe' : exe
				})

			print(f"pid {pid} called execve: {cmdline}")
			return

	else:
		exit_val = extract_field(au, 'exit')

		if au.next_record() and au.get_type_name() == 'CWD':
			if au.next_record() and au.get_type_name() == 'PATH':
				name = extract_field(au, 'name')

				print(f"pid {pid} called execve({name}) = {exit_val}")
				return

	print("dumping execve event")
	au.first_record()
	dump_event(au)

def process_syscall_fchmod(au, interpret=False):
	au.first_record()
	au.first_field()

	if not au.get_type_name() == 'SYSCALL':
		print("malformed event")
		return

	pid = extract_field(au, 'pid')
	ppid = extract_field(au, 'ppid')
	ses = extract_field(au, 'ses')
	comm = extract_field(au, 'comm')
	exe = extract_field(au, 'exe')
	fd = extract_field(au, 'a0', interpret_as = 'int')
	new_mode = extract_field(au, 'a1', interpret_as = 'true')

	if au.next_record() and au.get_type_name() == 'CWD':
		cwd = extract_field(au, 'cwd')

		if au.next_record() and au.get_type_name() == 'PATH':
#			path = extract_field(au, 'name')
#			if not path[0:1] == '/': # relative
#				path = f"{cwd}/{path}"
			path = get_pid_fd_name(pid, fd)

			orig_mode = extract_field(au, 'mode')
			ouid = extract_field(au, 'ouid', interpret)
			ogid = extract_field(au, 'ogid', interpret)

			if au.next_record() and au.get_type_name() == 'PROCTITLE':
				proctitle = extract_field(au, 'proctitle', True)

			else: # no PROCTITLE
				proctitle = 'unknown'

			ppexe = 'TODO'

		else: # no PATH
			path = 'unknown'
			proctitle = 'unknown'
			ppexe = 'TODO'

	else: # no CWD
		cwd = 'unknown'
		path = 'unknown'
		proctitle = 'unknown'
		ppexe = 'TODO'

	print(f"{pid} - {exe} (ppid {ppid} - {ppexe}) - fchmod({fd} - {path}, {new_mode})")

	# potentially update process_map


def process_syscall_fchmodat(au):
#	dump_event(au)

	au.first_record()
	au.first_field()

	if not au.get_type_name() == 'SYSCALL':
		print("malformed event")
		return

	pid = extract_field(au, 'pid')
	ppid = extract_field(au, 'ppid')
	ses = extract_field(au, 'ses')
	comm = extract_field(au, 'comm')
	exe = extract_field(au, 'exe')
	fd = extract_field(au, 'a0', interpret_as = 'int')
	new_mode = extract_field(au, 'a2', interpret_as = 'true')

	if au.next_record() and au.get_type_name() == "CWD":
		cwd = extract_field(au, 'cwd')

		if fd == AT_FDCWD:
			fd_path = cwd
			fd_str = 'AT_FDCWD'
		else:
			fd_str = get_pid_fd_name(pid, fd)
			if fd_str[0:1] == '/':
				fd_str = f"<{fd}>{fd_str}"

		if au.next_record() and au.get_type_name() == 'PATH':
			name = extract_field(au, 'name')

			if not name[0:1] == '/': # relative
				path = f"{fd_str}/{name}"
		else:
			path = "unknown"
	else:
		path = "unknown"

	ppexe = 'TODO'

	print(f"{pid} - {exe} (ppid {ppid} - {ppexe}) - fchmodat({fd_str}, \"{name}\", {new_mode}, ...)")

#	set_pid_info(pid, {
#		'ppid': ppid,
#		'ses' : ses,
#		'proctitle' : proctitle
#		})


def process_syscall_exit(au):
	au.first_record()
	au.first_field()

	pid = extract_field(au, 'pid')
	a0 = extract_field(au, 'a0', interpret_as='int')

	print(f"pid {pid} exited with code {a0}")
	exit_pid(pid)

def process_audit_event(au, cb_event_type, user_data):
	if not cb_event_type == auparse.AUPARSE_CB_EVENT_READY:
		return

	message = "=====================\n"
#	message = message + "event has {} records\n".format(au.get_num_records())
	au.first_record()

	event = {}
#	event['num_records'] = au.get_num_records()
#	record_num = 0

	type_name = au.get_type_name()

	if type_name in SKIP_EVENT_TYPES:
		return

	if type_name == "SYSCALL":
		scname = extract_field(au, 'syscall', interpret_as='true')
		add = f" (syscall {scname})"
	else:
		add = ""

	ts = au.get_timestamp()
	# get_sec
	# get_millis
	# get_serial
	# get_host

	print("{}.{} ({} - type: {} ({}) {}".format(ts.sec, ts.milli, ts.serial, au.get_type(), au.get_type_name(), add))

	if type_name == "SYSCALL":
		scname = extract_field(au, 'syscall', interpret_as='true')
#			print("syscall name: {} ({})".format(scname, event['syscall_name']))
#		event['syscall_name'] = scname

		if scname == 'clone':
			process_syscall_clone(au)
			return
		if scname == 'fchmod':
			process_syscall_fchmod(au)
			return
		if scname == 'fchmodat':
			process_syscall_fchmodat(au)
			return
		if scname == 'execve':
			process_syscall_execve(au)
			return
		if scname == 'exit':
			process_syscall_exit(au)
			return

		if scname in [ 'exit_group' ]:
			return

		if scname in [ 'write' ]:
			return


	elif type_name in [ 'DAEMON_CONFIG', 'USER_END', 'CRED_DISP', 'CRED_ACQ', 'LOGIN', 'USER_START', 'USER_ACCT', 'CONFIG_CHANGE', 'CRED_REFR', 'SERVICE_START', 'SERVICE_STOP' ]:
		return


#	elif type_name == "DAEMON_CONFIG":
#		event['type'] = "daemon_config"
	else:
		event['type'] = "unknown"



	while True:
#		rectype = au.get_type()
#		num_fields = au.get_num_fields()
#		message = message + "record type: {} ({}) - {} fields\n".format(rectype, au.get_type_name(), num_fields)

		while True:
#			message = message + "new record ({} - {}) has {} fields\n".format(
#				au.get_type(), au.get_type_name(), au.get_num_fields())



			message = message + "auparse.AUPARSE_TYPE_SYSCALL: {}, type: {}".format(auparse.AUPARSE_TYPE_SYSCALL, au.get_type())
#			print("auparse.AUPARSE_TYPE_PROCTITLE: {}\n".format(auparse.AUPARSE_TYPE_PROCTITLE))
			message = message + "auparse.AUPARSE_TYPE_PROCTITLE: {}".format(auparse.AUPARSE_TYPE_PROCTITLE)

			if au.get_type() == auparse.AUPARSE_TYPE_SYSCALL:
				syscall_name = au.find_field("syscall")
#				message = message + "syscall {} {}\n".format(syscall_name, au.interpret_field())
				print("syscall {} {}".format(syscall_name, au.interpret_field()))
#				message = message + "syscall {}".format(syscall_name)
#				message = message + "syscall ...\n"



#			event[messages].append(au.get_type_name())

			au.first_field()

			print("  type: {} ({})".format(au.get_type(), au.get_type_name()))
			while True:

				field_name = au.get_field_name()
				field_value = au.get_field_str()
#				message = message + "    {} = {} ({})\n".format(field_name, field_value, au.interpret_field())
				print("    {} = {} ({})".format(field_name, field_value, au.interpret_field()))

				if not au.next_field():
					break

			if not au.next_record():
				break

#        with open(LOG, "a") as log:
#            log.write(f"message: {s}\n")

		if not au.next_record():
			break


	if event['type'] == "syscall" and event['syscall_name'] == "clone":
		print("clone")


#  type: 1309 (EXECVE)
#    type = EXECVE (EXECVE)
#    argc = 4 (4)
#    a0 = "ausearch" (ausearch)
#    a1 = "--start" (--start)
#    a2 = "recent" (recent)
#    a3 = "--raw" (--raw)



#	with open(LOG, "a") as log:
#		log.write(f"{message}\n")

def main():
	au = auparse.AuParser(auparse.AUSOURCE_FEED)
	au.add_callback(process_audit_event, None)

	try:
		for line in sys.stdin:
#			with open(LOG, "a") as log:
#				log.write("here\n")
			if not line:
				break
			au.feed(line)
	except KeyboardInterrupt:
		pass
	finally:
		with open(LOG, "a") as log:
			log.write("error?\n")
		au.flush_feed()


def check_live():
	global live

	ppid = os.getppid()
	print("ppid: {}".format(ppid))

	try:
		ppexe = os.readlink(f"/proc/{ppid}/exe")
	except Exception as e:
		ppexe = "UNKNOWN"

	if ppexe == "/usr/sbin/auditd":
		live = True

	if live:
		print("executing live")
	else:
		print("not executing live")

if __name__ == "__main__":
	check_live()
	main()





# vim: autoindent noexpandtab tabstop=4 shiftwidth=4
