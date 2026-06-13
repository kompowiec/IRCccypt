import weechat
import subprocess
import base64
import os
import hashlib

SCRIPT_NAME = "pragmatic_crypto"
SCRIPT_AUTHOR = "Pragmatic Linux Developer"
SCRIPT_VERSION = "1.5"
SCRIPT_LICENSE = "GPL3"
SCRIPT_DESC = "Szyfrowanie komendą /s dla pełnego bezpieczeństwa - Poprawka Targetu"

PRIV_KEY_PATH = "/tmp/wc_priv.pem"
SHARED_SECRET = None

if weechat.register(SCRIPT_NAME, SCRIPT_AUTHOR, SCRIPT_VERSION, SCRIPT_LICENSE, SCRIPT_DESC, "", ""):
    weechat.hook_command("crypto_init", "Generuje parę kluczy ECDH w klamrach zabezpieczających", "", "", "", "init_dh_cb", "")
    weechat.hook_command("crypto_derive", "Generuje wspólny sekret na podstawie bezpiecznego bloku klucza", "<blok_klucza>", "", "", "derive_dh_cb", "")
    weechat.hook_command("s", "Wysyła bezpieczną wiadomość", "<tekst>", "", "", "secure_send_cb", "")
    weechat.hook_modifier("irc_in2_privmsg", "decrypt_cb", "")
    weechat.prnt("", "Załadowano Pragmatic E2EE v1.5. Szyfruj komendą: /s <tekst>")

def run_cmd(cmd, stdin_data=None):
    try:
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate(input=stdin_data)
        if proc.returncode != 0:
            return None
        return stdout
    except Exception:
        return None

def init_dh_cb(data, buffer, args):
    run_cmd(["openssl", "genpkey", "-algorithm", "X25519", "-out", PRIV_KEY_PATH])
    pub_der = run_cmd(["openssl", "pkey", "-in", PRIV_KEY_PATH, "-pubout", "-outform", "DER"])
    if pub_der:
        pub_b64 = base64.b64encode(pub_der).decode('utf-8')
        weechat.prnt(buffer, "=== GENEROWANIE KLUCZA ===")
        weechat.prnt(buffer, f"---BEGIN PKE KEY--- {pub_b64} ---END PKE KEY---")
    return weechat.WEECHAT_RC_OK

def derive_dh_cb(data, buffer, args):
    global SHARED_SECRET
    if not args or "---BEGIN PKE KEY---" not in args:
        weechat.prnt(buffer, "BŁĄD: Niepoprawny format klucza.")
        return weechat.WEECHAT_RC_OK
    try:
        peer_b64 = args.split("---BEGIN PKE KEY---")[1].split("---END PKE KEY---")[0].strip()
        peer_der = base64.b64decode(peer_b64)
    except Exception:
        return weechat.WEECHAT_RC_OK

    peer_path = "/tmp/wc_peer_pub.pem"
    with open(peer_path, "wb") as f: f.write(peer_der)
    secret_raw = run_cmd(["openssl", "pkeyutl", "-derive", "-inkey", PRIV_KEY_PATH, "-peerkey", peer_path, "-peerform", "DER"])
    if secret_raw:
        SHARED_SECRET = base64.b64encode(secret_raw.strip()).decode('utf-8')[:32]
        fingerprint = hashlib.sha256(SHARED_SECRET.encode()).hexdigest()[:4].upper()
        weechat.prnt(buffer, f"=== SUKCES === Suma kontrolna: [{fingerprint}]")
    if os.path.exists(peer_path): os.remove(peer_path)
    return weechat.WEECHAT_RC_OK

def secure_send_cb(data, buffer, args):
    """Obsługa komendy /s <tekst> w WeeChat"""
    global SHARED_SECRET
    if not args:
        return weechat.WEECHAT_RC_OK
    if not SHARED_SECRET:
        weechat.prnt(buffer, "BŁĄD: Brak uzgodnionego klucza.")
        return weechat.WEECHAT_RC_OK

    enc_raw = run_cmd(["openssl", "enc", "-aes-256-cbc", "-salt", "-k", SHARED_SECRET, "-a"], stdin_data=args.encode('utf-8'))
    if enc_raw:
        cipher_clean = enc_raw.decode('utf-8').replace('\\n', '').strip()
        
        # POPRAWKA: Używamy localvar_channel zamiast localvar_name, aby uzyskać czysty cel (np. #kanal lub nick)
        current_target = weechat.buffer_get_string(buffer, "localvar_channel")
        
        # Jeśli localvar_channel jest puste (np. okno statusu), spróbuj pobrać nazwę bufora
        if not current_target:
            current_target = weechat.buffer_get_string(buffer, "name")

        weechat.command(buffer, f"/quote PRIVMSG {current_target} :[E2EE]:{cipher_clean}")
        
        my_nick = weechat.buffer_get_string(buffer, "localvar_nick")
        weechat.prnt(buffer, f"\t🔒\t{my_nick}\t{args}")
    return weechat.WEECHAT_RC_OK

def decrypt_cb(data, modifier, modifier_data, string):
    global SHARED_SECRET
    if "[E2EE]:" not in string:
        return string
    try:
        cipher_text = string.split("[E2EE]:", 1)[1].strip()
        if " " in cipher_text: cipher_text = cipher_text.split()[0]
        
        if not SHARED_SECRET:
            decrypted = "[Zaszyfrowane - brak klucza]"
        else:
            cipher_bytes = cipher_text.encode('ascii', errors='ignore')
            dec_raw = run_cmd(["openssl", "enc", "-aes-256-cbc", "-d", "-salt", "-k", SHARED_SECRET, "-a"], stdin_data=cipher_bytes)
            decrypted = dec_raw.decode('utf-8', errors='ignore').strip() if dec_raw else "[Błąd deszyfrowania]"

        raw_to_replace = string.split(" :", 1)[1] if " :" in string else string
        return string.replace(raw_to_replace, f"🔒 {decrypted}")
    except Exception:
        return string
