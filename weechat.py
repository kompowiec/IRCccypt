import weechat
import subprocess
import base64
import os
import hashlib

SCRIPT_NAME = "E2E"
SCRIPT_AUTHOR = "Gemini"
SCRIPT_VERSION = "1.9"
SCRIPT_LICENSE = "GPL3"
SCRIPT_DESC = "E2EE przez OpenSSL z czyszczeniem śmieci i jawnym stderr"

PRIV_KEY_PATH = "/tmp/wc_priv.pem"
SHARED_SECRET = None

if weechat.register(SCRIPT_NAME, SCRIPT_AUTHOR, SCRIPT_VERSION, SCRIPT_LICENSE, SCRIPT_DESC, "", ""):
    weechat.hook_command("crypto_init", "Generuje parę kluczy ECDH v1.9", "", "", "", "init_dh_cb", "")
    weechat.hook_command("crypto_derive", "Generuje wspólny sekret v1.9", "<blok_klucza>", "", "", "derive_dh_cb", "")
    weechat.hook_command("s", "Wysyła bezpieczną wiadomość E2EE", "<tekst>", "", "", "secure_send_cb", "")
    weechat.hook_modifier("irc_in2_privmsg", "decrypt_cb", "")
    weechat.prnt("", "Załadowano Pragmatic E2EE v1.9. Użyj /s aby wysłać.")

def run_cmd(cmd, stdin_data=None):
    try:
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate(input=stdin_data)
        if proc.returncode != 0:
            if stderr:
                weechat.prnt("", f"❌ OpenSSL Err (WeeChat): {stderr.decode('utf-8', errors='ignore').strip()}")
            return None
        return stdout
    except Exception as e:
        weechat.prnt("", f"❌ Subprocess Exception: {str(e)}")
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
        # POPRAWKA: Pełny klucz bez sztucznego obcinania do [:32]
        SHARED_SECRET = base64.b64encode(secret_raw.strip()).decode('utf-8').strip()
        fingerprint = hashlib.sha256(SHARED_SECRET.encode()).hexdigest()[:4].upper()

        target_buf = buffer if buffer else weechat.current_buffer()
        weechat.prnt(target_buf, f"=== SUKCES === Suma kontrolna: [{fingerprint}]")
    if os.path.exists(peer_path): os.remove(peer_path)
    return weechat.WEECHAT_RC_OK

def secure_send_cb(data, buffer, args):
    global SHARED_SECRET
    if not args or not SHARED_SECRET:
        return weechat.WEECHAT_RC_OK

    # Szyfrujemy do czystych bajtów binarnych (brak flagi -a)
    enc_raw = run_cmd(["openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-md", "sha256", "-salt", "-k", SHARED_SECRET], stdin_data=args.strip().encode('utf-8'))
    if enc_raw:
        # Bezpieczne kodowanie w Pythonie do jednej linii base64
        cipher_clean = base64.b64encode(enc_raw).decode('utf-8').strip()
        current_target = weechat.buffer_get_string(buffer, "localvar_channel") or weechat.buffer_get_string(buffer, "name")

        weechat.command(buffer, f"/quote PRIVMSG {current_target} :[E2EE]:{cipher_clean}")
        my_nick = weechat.buffer_get_string(buffer, "localvar_nick")
        weechat.prnt(buffer, f"\t🔒\t{my_nick}\t{args}")
    return weechat.WEECHAT_RC_OK

def decrypt_cb(data, modifier, modifier_data, string):
    global SHARED_SECRET
    if "[E2EE]:" not in string:
        return string
    try:
        parsed = weechat.info_get_hashtable("irc_message_parse", {"message": string})
        msg_text = parsed.get("arguments", "")

        if "[E2EE]:" not in msg_text:
            return string

        cipher_b64 = msg_text.split("[E2EE]:", 1)[1].strip()
        cipher_b64 = cipher_b64.replace('\r', '').replace('\n', '').strip()
        if " " in cipher_b64: 
            cipher_b64 = cipher_b64.split()[0]
        cipher_b64 = cipher_b64.rstrip('\x01')

        if not SHARED_SECRET:
            decrypted = "[Zaszyfrowane - brak klucza]"
        else:
            try:
                # Dekodujemy Base64 w Pythonie
                cipher_bytes = base64.b64decode(cipher_b64)
                # Deszyfrujemy binarne dane wejściowe (brak flagi -a)
                dec_raw = run_cmd(["openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-md", "sha256", "-d", "-salt", "-k", SHARED_SECRET], stdin_data=cipher_bytes)
                decrypted = dec_raw.decode('utf-8', errors='ignore').strip() if dec_raw else "[Błąd deszyfrowania]"
            except Exception:
                decrypted = "[Błąd struktury pakietu Base64]"

        start_idx = string.find("[E2EE]:")
        if start_idx != -1:
            base_part = string[:start_idx]
            return f"{base_part}🔒 {decrypted}"

        return string
    except Exception:
        return string
