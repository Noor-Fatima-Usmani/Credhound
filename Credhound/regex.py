import os
import re
import glob
import json
import stat
import time
import sqlite3
import gzip, zipfile, tarfile
from report import generate_report
from browser_parser import parse_browser_artifacts

# COLORS
R  = "\033[91m"
G  = "\033[92m"
Y  = "\033[93m"
B  = "\033[94m"
M  = "\033[95m"
C  = "\033[96m"
W  = "\033[97m"
RESET = "\033[0m"

# GLOBAL
MAX_AGE_SECONDS = 60 * 60 * 24 * 7

# REGEX
email = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
linux_hash = re.compile(r'\$(1|2[aby]|5|6|7|y|gy)\$(?:rounds=\d+\$)?[a-zA-Z0-9./]+\$[a-zA-Z0-9./]+')
user_pass = re.compile(r'(?i)(user|username|pass|password|passwd|pwd|psk)\s*[:=]\s*(\S+)')
conn_strings = re.compile(r'[a-zA-Z]+://[^:]+:[^@]+@[^/]+')
private_key = re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----')
generic_secret = re.compile(r'(?i)(token|secret|api_key|apikey|auth)\s*[:=]\s*([A-Za-z0-9_\-]{16,})')
jwt = re.compile(r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+')
aws_key = re.compile(r'(?:AKIA|AIPA|ASIA)[A-Z0-9]{16}')
aws_secret = re.compile(r'(?i)aws.{0,20}secret.{0,20}[=:]\s*([A-Za-z0-9/+=]{40})')

# LIST OF ALL REGEX
scanners = [email, linux_hash, user_pass, conn_strings, private_key, generic_secret, jwt, aws_key, aws_secret]

# MEMORY STORAGE
findings = {1: [], 2: [], 3: [], 4: []}

# UTILITY FUNCTION
def history():
	patterns = [
		os.path.expanduser("~") + "/.*_history",
		"/root/.*_history",
		"/home/*/.*_history",
		"/*_history"
	]

	all_files = []
	for pattern in patterns:
		all_files.extend(glob.glob(pattern))

	return list(set(all_files))

# LIST OF ALL DIRS AND FILES TO CONSIDER
TARGETS = {
	1: {
		"label": "Temp Files",
		"dirs":  ["/tmp", "/var/tmp"],
		"files": [],
	},
	2: {
		"label": "Cache & Config Files",
		"dirs":  ["/var/lib/sss/db", "/var/lib/samba", "/etc/NetworkManager/system-connections"],
		"files": [
			"/etc/shadow",
			"/var/log/auth.log",
			"/etc/ssh/sshd_config",
			"/etc/mysql/my.cnf",
			"/etc/postgresql/*/main/pg_hba.conf",
		],
	},
	3: {
		"label": "History Files",
		"dirs":  [],
		"files": history(),
	},
	4: {
		"label": "FIrefox Artifacts",
	},
}

# HELPER
def read_logical_lines(f):
	buffer = ""
	for i, line in enumerate(f, 1):
		line = line.rstrip()
		if line.endswith("\\"):
			buffer += line[:-1] + " "
		else:
			buffer += line
			yield i, buffer
			buffer = ""
	if buffer.strip():
		yield i, buffer

def strings(path, min_len=8):
	with open(path, "rb") as f:
		data = f.read()
	pattern = re.compile(rb'[ -~]{%d,}' % min_len)
	return [s.decode("ascii") for s in pattern.findall(data)]

def decompress(path):
	lines = []
	try:
		if path.endswith(".gz"):
			with gzip.open(path, "rt", errors="ignore") as f:
				lines = f.readlines()
		elif zipfile.is_zipfile(path):
			with zipfile.ZipFile(path) as z:
				for name in z.namelist():
					with z.open(name) as f:
						lines += f.read().decode("utf-8", errors="ignore").splitlines()
		elif tarfile.is_tarfile(path):
			with tarfile.open(path) as t:
				for m in t.getmembers():
					if m.isfile():
						f = t.extractfile(m)
						if f:
							lines += f.read().decode("utf-8", errors="ignore").splitlines()
	except Exception:
		pass
	return lines

def scan_sqlite(path, category):
	try:
		conn = sqlite3.connect(path)
		for table in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall():
			for row in conn.execute(f"SELECT * FROM {table[0]}"):
				text = " ".join(str(c) for c in row)
				for pattern in scanners:
					if pattern.search(text):
						findings[category].append((path, text))
						print(f"  {Y}[+]{RESET} {C}SQLITE{RESET} {W}{text}{RESET}\n")
						break
		conn.close()
	except Exception:
		pass
		
def scan_nmconnection(path, category):
	try:
		with open(path, "r", errors="ignore") as f:
			content = f.read()

		name = ""
		psk  = ""

		for line in content.splitlines():
			line = line.strip()
			if line.lower().startswith("id="):
				name = line.split("=", 1)[1]
			elif line.lower().startswith("ssid="):
				name = line.split("=", 1)[1]
			elif line.lower().startswith("psk="):
				psk = line.split("=", 1)[1]

		if psk:
			value = f"WIFI: {name!r}  PSK: {psk}" if name else f"PSK: {psk}"
			findings[category].append((path, value))
			print(f"  {Y}[+]{RESET} {C}WIFI{RESET} {W}{value}{RESET}\n")

	except PermissionError:
		pass

# PARSER
def parser(path, category):   
	if os.path.isfile(path):
		scan_file(path, category)
	elif os.path.isdir(path):
		for root, dirs, files in os.walk(path):
			for file in files:
				filepath = os.path.join(root, file)
				
				# SKIP PYINSTALLER CACHE 
				if "/_MEI" in filepath:
					continue
                    
				if not os.path.isfile(filepath) or os.path.islink(filepath):
					print(f"  {Y}[~]{RESET} Skipping symlink: {filepath}\n")
					continue
				scan_file(filepath, category)

def scan_file(path, category):
	is_history = "_history" in path
	ext = path.lower()

	if ext.endswith(".db") or ext.endswith(".sqlite") or ext.endswith(".sqlite3"):
		scan_sqlite(path, category)
		return
		
	if path.endswith(".nmconnection"):
		scan_nmconnection(path, category)
		return

	if ext.endswith((".gz", ".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2")):
		lines = decompress(path)
		for i, line in enumerate(lines, 1):
			for pattern in scanners:
				match = pattern.search(line)
				if match:
					val = match.group(0).strip()
					findings[category].append((path, val))
					print(f"  {Y}[+]{RESET} {M}ARCHIVE{RESET} (Line {i}) {W}{val}{RESET}\n")
					break
		return

	try:
		with open(path, "rb") as f:
			header = f.read(512)
		is_binary = b'\x00' in header
	except Exception:
		is_binary = False

	if is_binary:
		extracted = strings(path)
		for i, line in enumerate(extracted, 1):
			for pattern in scanners:
				match = pattern.search(line)
				if match:
					val = match.group(0).strip()
					findings[category].append((path, val))
					print(f"  {Y}[+]{RESET} {M}BINARY{RESET} (String {i}) {W}{val}{RESET}\n")
					break
		try:
			st = os.stat(path)
			if st.st_mode & stat.S_IWOTH:
				findings[category].append((path, "WORLD-WRITABLE"))
				print(f"  {R}[!]{RESET} {R}WORLD-WRITABLE{RESET}: {path}\n")
		except Exception:
			pass
		return

	try:
		with open(path, "r", errors="ignore") as f:
			iterator = read_logical_lines(f) if is_history else enumerate(f, 1)
			for i, line in iterator:
				line = line.rstrip()
				if is_history:
					for pattern in scanners:
						match = pattern.search(line)
						if match:
							findings[category].append((path, line))
							print(f"  {Y}[+]{RESET} {G}CMD{RESET} (Line {i}) {W}{line}{RESET}\n")
							break
					continue
				for pattern in scanners:
					match = pattern.search(line)
					if match:
						val = match.group(0).strip()
						findings[category].append((path, val))
						print(f"  {Y}[+]{RESET} {C}HIT{RESET} (Line {i}) {W}{val}{RESET}\n")
						break
	except PermissionError:
		pass

def scan_shadow(path="/etc/shadow", category=2):
	path = os.path.expanduser(path)
	try:
		with open(path, "r", errors="ignore") as f:
			for i, line in enumerate(f, 1):
				parts = line.strip().split(":")
				if len(parts) >= 2 and linux_hash.search(parts[1]):
					value = f"{parts[0]}:{parts[1]}"
					findings[category].append((path, value))
					print(f"  {Y}[+]{RESET} {R}SHADOW{RESET} {W}{value}{RESET}\n")
	except PermissionError:
		pass

# HELPER
def run_scan(option):
	if option == 4:
		results = parse_browser_artifacts()
		for path, val in results:
			findings[4].append((path, val))
			print(f"  {Y}[+]{RESET} {C}BROWSER{RESET} {W}{val}{RESET}\n")
		return
		
	targets = TARGETS[option]["dirs"] + TARGETS[option]["files"]
	for loc in targets:
		loc = os.path.expanduser(loc)
		expanded = glob.glob(loc) or [loc]
		for path in expanded:
			if option == 1:
				try:
					age = time.time() - os.path.getmtime(path)
					if age > MAX_AGE_SECONDS:
						continue
				except Exception:
					continue
			print(f"{B}[*]{RESET} ---------- Scanning: {path} ----------\n")
			if path == "/etc/shadow":
				scan_shadow(path, category=option)
			else:
				parser(path, option)
			print()

"""
R  = "\033[91m"
G  = "\033[92m"
Y  = "\033[93m"
B  = "\033[94m"
M  = "\033[95m"
C  = "\033[96m"
W  = "\033[97m"
"""

# MAIN
if __name__ == "__main__":
	print(f"\033[1m{R}", end="")
	print(r"""
 _______  _______  _______  ______            _______           _        ______ 
(  ____ \(  ____ )(  ____ \(  __  \ |\     /|(  ___  )|\     /|( (    /|(  __  \ 
| (    \/| (    )|| (    \/| (  \  )| )   ( || (   ) || )   ( ||  \  ( || (  \  )
| |      | (____)|| (__    | |   ) || (___) || |   | || |   | ||   \ | || |   ) |
| |      |     __)|  __)   | |   | ||  ___  || |   | || |   | || (\ \) || |   | |
| |      | (\ (   | (      | |   ) || (   ) || |   | || |   | || | \   || |   ) |
| (____/\| ) \ \__| (____/\| (__/  )| )   ( || (___) || (___) || )  \  || (__/  )
(_______/|/   \__/(_______/(______/ |/     \|(_______)(_______)|/    )_)(______/ 
	""")
	print(f"{RESET}", end="")

	while (True):
		print(f"""
	{B}[1]{RESET} Temp Files
	{B}[2]{RESET} Cache & Config Files
	{B}[3]{RESET} History Files
	{B}[4]{RESET} Browser Artifacts
	{B}[9]{RESET} Generate Report
		""")

		choice = input(f"{G}[?] Select option: {RESET}").strip()
		print()

		if choice in ("1", "2", "3", "4"):
			run_scan(int(choice))
		elif choice == "9":
			print(f"{Y}[*] Generating report{RESET}\n")
			target = input(f"{G}[?] Target (IP/HOSTNAME): {RESET}").strip() or "N/A"
			generate_report(findings, target=target, out_path="report.pdf")
			break
		else:
			print(f"{R}[-] Invalid option{RESET}")
