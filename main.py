import network
import socket
import time
import hashlib
import gc # Für Garbage Collection

# --- WLAN Daten ---
WLAN_SSID = "Deine_WLAN_SSID"
WLAN_PASS = "Dein_WLAN_Passwort"

# --- Fritz!Box Daten ---
FRITZBOX_HOST = "fritz.box"
FRITZBOX_USER = "Dein_Fritzbox_User"
FRITZBOX_PASS = "Dein_Fritzbox_Passwort"

# --- SOAP Service Details für TR-064 (WICHTIG: Hier bleibt die Anpassung auf X_VoIP:1 Service!) ---
FRITZBOX_PORT_TR064 = 49000 # Für TR-064 ist Port 49000 üblich
uri_tr064 = '/upnp/control/x_voip' # Angepasst an den Arduino-Code
soap_action_tr064 = "urn:dslforum-org:service:X_VoIP:1#X_AVM-DE_DialNumber" # Angepasst
soap_body_tr064 = ( # Angepasst an den Arduino-Code
    '<?xml version="1.0" encoding="utf-8"?>'
    '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
    's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
    '<s:Body>'
    '<u:X_AVM-DE_DialNumber xmlns:u="urn:dslforum-org:service:X_VoIP:1">'
    '<NewX_AVM-DE_PhoneNumber>**9</NewX_AVM-DE_PhoneNumber>'
    '</u:X_AVM-DE_DialNumber>'
    '</s:Body>'
    '</s:Envelope>'
)

# --- Globale Variablen für Digest Authentication ---
# Diese Variablen müssen persistieren, da nc bei jedem Request inkrementiert wird
# Initialisiere sie beim Start oder speichere sie, falls der ESP schlafen geht.
# Für diesen Test initialisieren wir sie hier:
digest_nonce = ""
digest_realm = ""
digest_qop = ""
digest_nc = 0 # Nonce Count

# --- HILFSFUNKTIONEN ---

def md5_hash(data):
    # Erwartet Bytes für den Hash
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.md5(data).digest().hex()

def md5_fritz_response(challenge, password):
    print(f"[DBG] md5_fritz_response: Challenge: {challenge}, Password: (hidden)")
    combined = challenge + "-" + password
    print(f"[DBG] md5_fritz_response: Combined string: {combined}")

    # Konvertierung zu UTF-16LE Bytes (wichtig für Fritz!Box Challenge-Response)
    # Jedes Zeichen wird zu 2 Bytes: Zeichen-Byte, dann Null-Byte
    utf16le_bytes = bytearray()
    for char in combined:
        utf16le_bytes.append(ord(char))
        utf16le_bytes.append(0x00) # Null-Byte für UTF-16LE

    print(f"[DBG] md5_fritz_response: UTF-16LE Bytes (Hex): {utf16le_bytes.hex()}")

    result_hash = hashlib.md5(utf16le_bytes).hexdigest()
    print(f"[DBG] md5_fritz_response: Calculated Hash: {result_hash}")
    return result_hash

def parse_sid_login_response(payload):
    # Sucht nach <Challenge> und <SID> im XML-Payload
    challenge = ""
    sid = ""

    # Challenge extrahieren
    challenge_start = payload.find("<Challenge>")
    if challenge_start != -1:
        challenge_end = payload.find("</Challenge>", challenge_start)
        if challenge_end != -1:
            challenge = payload[challenge_start + len("<Challenge>"):challenge_end]
    
    # SID extrahieren
    sid_start = payload.find("<SID>")
    if sid_start != -1:
        sid_end = payload.find("</SID>", sid_start)
        if sid_end != -1:
            sid = payload[sid_start + len("<SID>"):sid_end]
            
    return challenge, sid

def connect_wifi(ssid, password):
    wlan = network.WLAN(network.STA_IF)
    wlan.active(True)
    if not wlan.isconnected():
        print('[*] WLAN: Verbinde...')
        wlan.connect(ssid, password)
        while not wlan.isconnected():
            print('.')
            time.sleep(1)
    print(f'[+] WLAN: Verbunden! IP: {wlan.ifconfig()[0]}')
    return wlan

# --- NEUE FUNKTIONEN FÜR DIGEST AUTHENTIFIZIERUNG (ADAPTIERT AUS C++) ---

def parse_www_authenticate_header(header_line):
    # Globales nonce, realm, qop aktualisieren
    global digest_nonce, digest_realm, digest_qop

    print(f"[DBG] parse_www_authenticate_header: Parsing header: '{header_line}'")
    # Der Header beginnt mit 'WWW-Authenticate: Digest '
    # Wir brauchen den Teil danach, z.B. realm="users@fritz.box", nonce="..."
    header_content = header_line.replace("WWW-Authenticate: Digest ", "")
    
    # Funktionen zum Extrahieren einzelner Schlüssel-Wert-Paare
    def extract_value(content, key):
        start_key = f'{key}="'
        start_index = content.find(start_key)
        if start_index == -1:
            # Fallback für Schlüssel ohne Anführungszeichen (z.B. qop=auth)
            start_key = f'{key}='
            start_index = content.find(start_key)
            if start_index == -1:
                return ""
            value_start = start_index + len(start_key)
            end_index = content.find(",", value_start)
            if end_index == -1:
                end_index = len(content)
            return content[value_start:end_index].strip()
        
        value_start = start_index + len(start_key)
        value_end = content.find('"', value_start)
        if value_end == -1:
            return ""
        return content[value_start:value_end]

    digest_realm = extract_value(header_content, "realm")
    digest_nonce = extract_value(header_content, "nonce")
    digest_qop = extract_value(header_content, "qop") # Normalerweise 'auth'

    print(f"[DBG] Parsed Realm: {digest_realm}, Nonce: {digest_nonce}, QOP: {digest_qop}")
    return digest_realm != "" and digest_nonce != "" and digest_qop != ""

def build_digest_header():
    global digest_nc
    digest_nc += 1 # Nonce Count inkrementieren
    
    # cnonce: Client Nonce (zufällige Zeichenfolge)
    # Hier verwenden wir einfach die aktuelle Zeit als Hex-String
    cnonce = hex(int(time.time() * 1000000))[2:] # Entferne "0x" Präfix

    # nc_str: Nonce Count als 8-stelliger Hex-String
    # KORRIGIERTE ZEILE FÜR MICROPYTHON:
    nc_str = "{:0>8x}".format(digest_nc) # Formatiert digest_nc als 8-stelligen Hex-String mit führenden Nullen

    print(f"[DBG] build_digest_header: Nonce Count (nc): {digest_nc} (Hex: {nc_str})")
    print(f"[DBG] build_digest_header: Client Nonce (cnonce): {cnonce}")

    # HA1 = MD5(username:realm:password)
    ha1_input = f"{FRITZBOX_USER}:{digest_realm}:{FRITZBOX_PASS}"
    ha1 = md5_hash(ha1_input.encode('utf-8')) # Bytes für MD5-Hash
    print(f"[DBG] build_digest_header: HA1 input: '{FRITZBOX_USER}:{digest_realm}:(hidden_pass)' -> HA1: {ha1}")

    # HA2 = MD5(HTTP-Methode:digestURI)
    ha2_input = f"POST:{uri_tr064}" # uri_tr064 ist hier der Pfad auf der Fritzbox
    ha2 = md5_hash(ha2_input.encode('utf-8')) # Bytes für MD5-Hash
    print(f"[DBG] build_digest_header: HA2 input: 'POST:{uri_tr064}' -> HA2: {ha2}")

    # Response = MD5(HA1:nonce:nc:cnonce:qop:HA2)
    response_input = f"{ha1}:{digest_nonce}:{nc_str}:{cnonce}:{digest_qop}:{ha2}"
    response = md5_hash(response_input.encode('utf-8')) # Bytes für MD5-Hash
    print(f"[DBG] build_digest_header: Response input: '{ha1}:{digest_nonce}:{nc_str}:{cnonce}:{digest_qop}:{ha2}' -> Response: {response}")

    auth_header = (
        f'Digest username="{FRITZBOX_USER}", '
        f'realm="{digest_realm}", '
        f'nonce="{digest_nonce}", '
        f'uri="{uri_tr064}", '
        f'qop={digest_qop}, '
        f'nc={nc_str}, '
        f'cnonce="{cnonce}", '
        f'response="{response}", '
        'algorithm=MD5'
    )
    
    return auth_header

# --- HAUPTPROGRAMM LOGIK ---

def sid_login():
    print("[*] Starte Fritz!Box SID-Login.")
    addr = socket.getaddrinfo(FRITZBOX_HOST, 80)[0][-1] # Port 80 für SID-Login
    s = socket.socket()
    s.settimeout(5.0) # Timeout für Socket-Operationen

    try:
        s.connect(addr)
        gc.collect()

        # Erster Request für Challenge
        request_line = f"GET http://{FRITZBOX_HOST}/login_sid.lua HTTP/1.1\r\n"
        headers = f"Host: {FRITZBOX_HOST}\r\n"
        headers += "Connection: close\r\n\r\n"
        full_request = request_line + headers
        s.sendall(full_request.encode('utf-8'))
        
        response_data = b""
        start_time = time.time()
        while time.time() - start_time < 15.0: # 15 Sekunden Timeout für Response
            try:
                chunk = s.recv(128)
                if chunk:
                    response_data += chunk
                else:
                    break
            except OSError as e:
                if e.args[0] == 110: # errno 110 is ETIMEDOUT
                    print("[DBG] Timeout beim Lesen der SID-Challenge-Antwort.")
                    break
                else:
                    raise e
        
        payload = response_data.decode('utf-8', 'ignore') # 'ignore' um Fehler bei unvollständigen Bytes zu vermeiden
        gc.collect()
        
        challenge, current_sid = parse_sid_login_response(payload)
        
        if not challenge:
            print("[ERR] Keine Challenge erhalten, SID-Login fehlgeschlagen!")
            return False

        print(f"[INF] Challenge für SID-Login: {challenge}")
        
        response_hash = md5_fritz_response(challenge, FRITZBOX_PASS)
        response_str = f"{challenge}-{response_hash}"
        print(f"[DBG] Login: SID Response Hash: {response_hash}")
        print(f"[DBG] Login: SID Response String: {response_str}")
        
        # Zweiter Request mit Response für SID
        request_line = f"GET http://{FRITZBOX_HOST}/login_sid.lua?username={FRITZBOX_USER}&response={response_str} HTTP/1.1\r\n"
        headers = f"Host: {FRITZBOX_HOST}\r\n"
        headers += "Connection: close\r\n\r\n"
        full_request = request_line + headers
        s.sendall(full_request.encode('utf-8'))
        
        response_data = b""
        start_time = time.time()
        while time.time() - start_time < 15.0:
            try:
                chunk = s.recv(128)
                if chunk:
                    response_data += chunk
                else:
                    break
            except OSError as e:
                if e.args[0] == 110: # errno 110 is ETIMEDOUT
                    print("[DBG] Timeout beim Lesen der SID-Response.")
                    break
                else:
                    raise e

        payload = response_data.decode('utf-8', 'ignore')
        gc.collect()
        
        _, final_sid = parse_sid_login_response(payload)
        
        if final_sid and final_sid != "0000000000000000":
            print(f"[INF] SID: {final_sid}")
            print("[+] SID-Login erfolgreich abgeschlossen.")
            return True
        else:
            print("[ERR] SID-Login fehlgeschlagen oder ungültige SID erhalten.")
            return False

    except Exception as e:
        print(f"[ERR] Fehler im SID-Login: {e}")
        return False
    finally:
        s.close()
        print("[DBG] Login: Socket closed.")
        gc.collect()

def start_rundruf():
    print("[*] Versuche, den Rundruf (Klingel) über manuelle Digest-Authentifizierung (TR-064) zu starten...")
    
    # --- ERSTER VERSUCH: Manueller Request ohne Authorization-Header, um die Challenge zu erhalten (HTTP 401) ---
    addr = socket.getaddrinfo(FRITZBOX_HOST, FRITZBOX_PORT_TR064)[0][-1]
    s = socket.socket()
    s.settimeout(10.0) # Timeout auf 10 Sekunden setzen (kann auch 15 sein)
    
    try:
        print(f"[DBG] Manueller Request (TR-064): Verbinde mit {FRITZBOX_HOST}:{FRITZBOX_PORT_TR064}...")
        s.connect(addr)
        gc.collect()

        http_request = (
            f"POST {uri_tr064} HTTP/1.1\r\n"
            f"Host: {FRITZBOX_HOST}:{FRITZBOX_PORT_TR064}\r\n"
            f"Content-Type: text/xml; charset=\"utf-8\"\r\n"
            f"SOAPACTION: \"{soap_action_tr064}\"\r\n"
            f"Content-Length: {len(soap_body_tr064)}\r\n"
            f"Connection: close\r\n"
            f"\r\n" # Leere Zeile trennt Header vom Body
            f"{soap_body_tr064}"
        )
        
        print("[DBG] Sende manuellen HTTP-POST Request (TR-064):")
        print(http_request)
        s.sendall(http_request.encode('utf-8'))
        
        response_data = b""
        start_time = time.time()
        http_response_code = 0
        www_authenticate_header = ""
        headers_finished = False

        while time.time() - start_time < 20.0: # 20 Sekunden Timeout für die gesamte Header-Lesung
            try:
                line_bytes = s.readline() # Liest bis zum nächsten '\n'
                if not line_bytes: # Verbindung geschlossen oder Timeout
                    if not s.connected(): # Überprüfen, ob die Verbindung wirklich getrennt wurde
                        print("[DBG] *** Socket NICHT mehr verbunden! SCHLEIFE WIRD ABGEBROCHEN. ***")
                    break
                
                response_line = line_bytes.decode('utf-8', 'ignore').strip()
                print(f"[DBG] Gelesene Zeile: '{response_line}'")

                if not response_line: # Leere Zeile bedeutet Ende der Header
                    headers_finished = True
                    print("[DBG] Ende der HTTP-Header erreicht. (TR-064)")
                    break
                
                if response_line.startswith("HTTP/1."):
                    parts = response_line.split(' ')
                    if len(parts) > 1:
                        http_response_code = int(parts[1])
                        print(f"[*] Manuelle HTTP Antwort Code (TR-064): {http_response_code}")
                        # Wir lesen die Header weiter, bis wir eine leere Zeile finden
                elif response_line.lower().startswith("www-authenticate:"):
                    www_authenticate_header = response_line
                    print("[*] WWW-Authenticate Header manuell gefunden! (wird weitergelesen bis Ende Header)")

            except OSError as e:
                if e.args[0] == 110: # ETIMEDOUT
                    print("[DBG] Timeout beim Lesen der TR-064-Antwort-Header.")
                    break
                else:
                    raise e
            except Exception as e:
                print(f"[ERR] Fehler beim Lesen der TR-064-Antwort-Header: {e}")
                break

        s.close() # Erste Verbindung schließen
        print("[DBG] Erste HTTP-Verbindung geschlossen. (TR-064)")
        gc.collect()

        if http_response_code != 401:
            print(f"[!] Unerwarteter HTTP Code beim ersten Request (TR-064): {http_response_code}")
            return False

        if not www_authenticate_header:
            print("[!] ❌ WWW-Authenticate Header NICHT gefunden nach manuellem Parsen (trotz 401)!")
            print("[!] ❌ Rundruf fehlgeschlagen oder Authentifizierungsproblem über TR-064!")
            return False

        print("[*] WWW-Authenticate Header gefunden! Starte Digest-Berechnung...")
        
        if not parse_www_authenticate_header(www_authenticate_header):
            print("[!] ❌ Fehler beim Parsen von realm, nonce oder qop aus WWW-Authenticate Header!")
            return False

        # Digest Authorization Header erstellen
        auth_header_value = build_digest_header()
        print(f"[DBG] Erstellter Digest Auth Header: {auth_header_value}")

        # --- ZWEITER VERSUCH: Mit Authorization-Header ---
        print("[*] Sende zweiten SOAP POST (mit Auth) für TR-064...")
        s2 = socket.socket()
        s2.settimeout(10.0) # Timeout für zweiten Socket
        s2.connect(addr) # Erneut verbinden
        gc.collect()

        http_request_2 = (
            f"POST {uri_tr064} HTTP/1.1\r\n"
            f"Host: {FRITZBOX_HOST}:{FRITZBOX_PORT_TR064}\r\n"
            f"Content-Type: text/xml; charset=\"utf-8\"\r\n"
            f"SOAPACTION: \"{soap_action_tr064}\"\r\n"
            f"Content-Length: {len(soap_body_tr064)}\r\n"
            f"Authorization: {auth_header_value}\r\n" # HIER kommt der Auth-Header rein!
            f"Connection: close\r\n"
            f"\r\n" # Leere Zeile trennt Header vom Body
            f"{soap_body_tr064}"
        )
        
        print(f"[DBG] Zweiter Request SOAP Body:\n{soap_body_tr064}")
        s2.sendall(http_request_2.encode('utf-8'))
        
        response_data_2 = b""
        start_time_2 = time.time()
        final_http_code = 0

        while time.time() - start_time_2 < 20.0: # Timeout für zweite Antwort
            try:
                line_bytes = s2.readline()
                if not line_bytes:
                    break
                response_line = line_bytes.decode('utf-8', 'ignore').strip()
                print(f"[DBG] Gelesene Zeile (2. Request): '{response_line}'")
                
                if response_line.startswith("HTTP/1."):
                    parts = response_line.split(' ')
                    if len(parts) > 1:
                        final_http_code = int(parts[1])
                        print(f"[*] Zweiter HTTP Antwort Code (TR-064): {final_http_code}")
                        # Wir lesen die Header weiter, bis wir eine leere Zeile finden
                elif not response_line and response_data_2 == b"":
                    # Leere Zeile nach den Headern, Body beginnt
                    pass # Brechen hier nicht ab, da wir den Body noch lesen müssen
                
                # Hier könntest du den Body lesen, falls es einen gibt und du ihn brauchst
                # Für den Rundruf ist der Body meistens leer oder unwichtig
                if not response_line and final_http_code == 200: # Leere Zeile NACH Headern und Code 200
                     # Hier wäre die Logik, um den Body zu lesen (falls Content-Length bekannt)
                     pass

            except OSError as e:
                if e.args[0] == 110: # ETIMEDOUT
                    print("[DBG] Timeout beim Lesen der TR-064-Antwort (2. Request).")
                    break
                else:
                    raise e
            except Exception as e:
                print(f"[ERR] Fehler beim Lesen der TR-064-Antwort (2. Request): {e}")
                break

        if final_http_code == 200: # HTTP 200 ist der Erfolgscode
            print("[+] Zweiter Request erfolgreich! Rundruf gesendet.")
            return True
        else:
            print(f"[!] Zweiter Request fehlgeschlagen, Code: {final_http_code}")
            return False

    except Exception as e:
        print(f"[ERR] Fehler im TR-064-Rundruf: {e}")
        return False
    finally:
        s.close()
        if 's2' in locals() and s2: # Sicherstellen, dass s2 existiert und geschlossen wird
            s2.close()
        print("[DBG] TR-064: Sockets geschlossen.")
        gc.collect()


# --- Haupt-Programmablauf ---
def main():
    gc.collect()
    print(f"MPY: soft reboot. Freier Speicher: {gc.mem_free()} Bytes")

    wlan_connected = connect_wifi(WLAN_SSID, WLAN_PASS)
    if not wlan_connected:
        print("[ERR] WLAN-Verbindung fehlgeschlagen. Abbruch.")
        return

    # SID-Login (immer noch hilfreich, um generelle Netzwerk- und Authentifizierungsbasis zu testen)
    
    if sid_login():
        print("----------------------------------------")
        if start_rundruf():
            print("----------------------------------------")
            print("[+] ✅ Rundruf erfolgreich initiiert!")
        else:
            print("----------------------------------------")
            print("[!] ❌ Rundruf fehlgeschlagen oder Authentifizierungsproblem über TR-064!")
    else:
        print("[!] SID-Login fehlgeschlagen. Der TR-064-Rundruf wird möglicherweise auch Probleme haben.")
        print("----------------------------------------")
        # Trotzdem versuchen, falls SID-Login nur ein Test war oder temporäre Probleme hatte
        if start_rundruf(): 
            print("----------------------------------------")
            print("[+] ✅ Rundruf erfolgreich initiiert!")
        else:
            print("----------------------------------------")
            print("[!] ❌ Rundruf fehlgeschlagen oder Authentifizierungsproblem über TR-064!")

    print(f"Script finished. Free memory: {gc.mem_free()} Bytes")

if __name__ == '__main__':
    main()
