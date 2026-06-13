import hexchat
import subprocess
import base64
import os
import hashlib

__module_name__ = "Pragmatic Linux E2EE"
__module_version__ = "1.4"
__module_description__ = "Szyfrowanie komendą /s dla pełnego bezpieczeństwa"

PRIV_KEY_PATH = "/tmp/hc_priv.pem"
SHARED_SECRET = None

def run_cmd(cmd, stdin_data=None):
    try:
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate(input=stdin_data)
        if proc.returncode != 0:
            return None
        return stdout
    except Exception:
        return None

def init_dh(word, word_eol, userdata):
    run_cmd(["openssl", "genpkey", "-algorithm", "X25519", "-out", PRIV_KEY_PATH])
    pub_der = run_cmd(["openssl", "pkey", "-in", PRIV_KEY_PATH, "-pubout", "-outform", "DER"])
    if pub_der:
        pub_b64 = base64.b64encode(pub_der).decode('utf-8')
        hexchat.prnt("=== GENEROWANIE KLUCZA ===")
        hexchat.prnt("Wyślij poniższy blok do rozmówcy:")
        hexchat.prnt(f"---BEGIN PKE KEY--- {pub_b64} ---END PKE KEY---")
    return hexchat.EAT_ALL

def derive_dh(word, word_eol, userdata):
    global SHARED_SECRET
    if len(word) < 2:
        hexchat.prnt("Użycie: /crypto_derive <cały_blok_z_kreskami>")
        return hexchat.EAT_ALL
    
    raw_input = word_eol[1]
    if "---BEGIN PKE KEY---" not in raw_input or "---END PKE KEY---" not in raw_input:
        hexchat.prnt("BŁĄD: Brak delimiterów BEGIN/END!")
        return hexchat.EAT_ALL
        
    try:
        peer_b64 = raw_input.split("---BEGIN PKE KEY---")[1].split("---END PKE KEY---")[0].strip()
        peer_der = base64.b64decode(peer_b64)
    except Exception:
        hexchat.prnt("BŁĄD: Dekodowanie Base64 nie powiodło się.")
        return hexchat.EAT_ALL

    peer_path = "/tmp/hc_peer_pub.pem"
    with open(peer_path, "wb") as f:
        f.write(peer_der)

    secret_raw = run_cmd(["openssl", "pkeyutl", "-derive", "-inkey", PRIV_KEY_PATH, "-peerkey", peer_path, "-peerform", "DER"])
    if secret_raw:
        SHARED_SECRET = base64.b64encode(secret_raw.strip()).decode('utf-8')[:32]
        fingerprint = hashlib.sha256(SHARED_SECRET.encode()).hexdigest()[:4].upper()
        hexchat.prnt(f"=== SUKCES === Suma kontrolna: [{fingerprint}]")
    else:
        hexchat.prnt("Błąd obliczania sekretu OpenSSL.")
    if os.path.exists(peer_path): os.remove(peer_path)
    return hexchat.EAT_ALL

def secure_send_cb(word, word_eol, userdata):
    """Obsługa komendy /s <tekst>"""
    global SHARED_SECRET
    if len(word) < 2:
        hexchat.prnt("Użycie: /s <bezpieczna wiadomość>")
        return hexchat.EAT_ALL

    if not SHARED_SECRET:
        hexchat.prnt("BŁĄD: Najpierw uzgodnij klucz przez /crypto_init i /crypto_derive!")
        return hexchat.EAT_ALL

    message = word_eol[1]
    enc_raw = run_cmd(["openssl", "enc", "-aes-256-cbc", "-salt", "-k", SHARED_SECRET, "-a"], stdin_data=message.encode('utf-8'))
    if enc_raw:
        encrypted = f"[E2EE]:{enc_raw.decode('utf-8').replace('\\n', '').strip()}"
        channel = hexchat.get_info("channel")
        # Pchamy w sieć TYLKO i wyłącznie komendę z zaszyfrowanym ciągiem
        hexchat.command(f"PRIVMSG {channel} :{encrypted}")
        # Drukujemy u siebie ładną kłódkę
        hexchat.prnt(f"\\t🔒\\t{hexchat.get_info('nick')}\\t{message}")
    return hexchat.EAT_ALL

def message_in_hook(word, word_eol, userdata):
    message = word[1]
    if message.startswith("[E2EE]:"):
        sender = word[0]
        if not SHARED_SECRET:
            hexchat.prnt(f"\\t🔒\\t{sender}\\t[Zaszyfrowane - brak klucza]")
            return hexchat.EAT_ALL
        clean_cipher = message.replace("[E2EE]:", "").strip()
        dec_raw = run_cmd(["openssl", "enc", "-aes-256-cbc", "-d", "-salt", "-k", SHARED_SECRET, "-a"], stdin_data=clean_cipher.encode('ascii', errors='ignore'))
        decrypted = dec_raw.decode('utf-8', errors='ignore').strip() if dec_raw else "[Błąd deszyfrowania]"
        hexchat.prnt(f"\\t🔒\\t{sender}\\t{decrypted}")
        return hexchat.EAT_ALL
    return hexchat.EAT_NONE

hexchat.hook_command("crypto_init", init_dh)
hexchat.hook_command("crypto_derive", derive_dh)
hexchat.hook_command("s", secure_send_cb, help="/s <wiadomość> wysyła zaszyfrowany pakiet E2EE")
hexchat.hook_server("PRIVMSG", message_in_hook)
hexchat.prnt("Załadowano Pragmatic E2EE v1.4. Szyfruj komendą: /s <tekst>")
