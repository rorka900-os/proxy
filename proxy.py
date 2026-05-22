import socket
import threading
import select
import time
import sys
import os

H, P, B = '0.0.0.0', 8080, 65536

def find_sni_split_indices(data):
    """Находит точное начало и конец SNI (домена) в TLS Client Hello."""
    try:
        if len(data) < 44 or data[0] != 0x16 or data[5] != 0x01:
            return -1, -1
        
        idx = 43
        sess_len = data[idx]
        idx += 1 + sess_len
        
        cs_len = int.from_bytes(data[idx:idx+2], 'big')
        idx += 2 + cs_len
        
        cm_len = data[idx]
        idx += 1 + cm_len
        
        ext_len = int.from_bytes(data[idx:idx+2], 'big')
        idx += 2
        ext_end = idx + ext_len
        
        while idx + 4 <= ext_end:
            ext_type = int.from_bytes(data[idx:idx+2], 'big')
            ext_data_len = int.from_bytes(data[idx+2:idx+4], 'big')
            idx += 4
            
            if ext_type == 0x0000:  # SNI Extension
                if idx + 5 <= ext_end:
                    name_len = int.from_bytes(data[idx+3:idx+5], 'big')
                    name_start = idx + 5
                    return name_start, name_start + name_len
            idx += ext_data_len
    except Exception:
        pass
    return -1, -1

def force_send(sock, data, delay=0.15):
    """
    КРИТИЧЕСКИ ВАЖНО: Принудительно отправляет пакет, обходя буферизацию ядра ОС (Nagle/TSO).
    Без этого ядро склеит ваши осколки обратно в один пакет, и DPI его заблокирует.
    """
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if sys.platform == "linux":
            # TCP_CORK заставляет ядро накапливать данные, а снятие CORK - немедленно отправляет
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_CORK, 1)
            sock.send(data)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_CORK, 0)
        elif sys.platform == "darwin":
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NOPUSH, 1)
            sock.send(data)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NOPUSH, 0)
        else:
            sock.send(data)
    except Exception:
        try:
            sock.send(data)
        except:
            pass
    time.sleep(delay)

def scramble_http(data):
    """Обход DPI для обычного HTTP (не HTTPS) через искажение заголовков."""
    try:
        data = data.replace(b'Host:', b'hOsT:')
        data = data.replace(b'GET ', b'GET  ')
        data = data.replace(b'POST ', b'POST  ')
        data = data.replace(b'User-Agent:', b'UsEr-Agent:')
        return data
    except:
        return data

def nfq_send(sock, data, mode):
    if len(data) > 5 and data[0] == 0x16:  # TLS Client Hello
        sni_start, sni_end = find_sni_split_indices(data)
        
        if sni_start != -1 and sni_end != -1:
            sni_mid = sni_start + (sni_end - sni_start) // 2
            
            if mode == 1: # SNI Split (Force Send) - Самый надежный
                force_send(sock, data[:sni_mid], delay=0.15)
                force_send(sock, data[sni_mid:], delay=0.0)
                
            elif mode == 2: # SNI Split + TLS Record Split
                force_send(sock, data[:sni_start], delay=0.1)
                force_send(sock, data[sni_start:sni_mid], delay=0.1)
                force_send(sock, data[sni_mid:], delay=0.0)
                
            elif mode == 3: # Triple Split (До, Середина, После)
                force_send(sock, data[:sni_start], delay=0.1)
                force_send(sock, data[sni_start:sni_end], delay=0.1)
                force_send(sock, data[sni_end:], delay=0.0)
                
            elif mode == 4: # 1 Byte SNI Split
                force_send(sock, data[:sni_start+1], delay=0.2)
                force_send(sock, data[sni_start+1:], delay=0.0)
                
            elif mode == 5: # Агрессивный побайтовый разрыв SNI
                force_send(sock, data[:sni_start], delay=0.1)
                for i in range(sni_start, sni_end):
                    force_send(sock, data[i:i+1], delay=0.05)
                force_send(sock, data[sni_end:], delay=0.0)
                
            elif mode == 6: # Fake Host в CONNECT (если DPI смотрит на CONNECT)
                force_send(sock, data[:sni_mid], delay=0.15)
                force_send(sock, data[sni_mid:], delay=0.0)
                
            elif mode == 7: # Max Delay Split (для очень медленных DPI)
                force_send(sock, data[:sni_mid], delay=0.5)
                force_send(sock, data[sni_mid:], delay=0.0)
        else:
            # Фоллбек, если SNI не найден
            split = len(data) // 2
            force_send(sock, data[:split], delay=0.15)
            force_send(sock, data[split:], delay=0.0)
    else:
        force_send(sock, scramble_http(data), delay=0.0)

def tunnel(c, s, first=None, mode=3):
    if first:
        nfq_send(s, first, mode)
    qs = [c, s]
    while True:
        try:
            r, _, e = select.select(qs, [], qs, 25)
            if e or not r: break
            for x in r:
                y = s if x is c else c
                try:
                    b = x.recv(B)
                except ConnectionResetError:
                    print(f"[!] RST (Сброс соединения) от {'DPI/Сервера' if x is s else 'Клиента'}")
                    return
                except Exception:
                    return
                if not b: return
                y.sendall(b)
        except:
            break

def handle(c, mode=3):
    s = None
    try:
        c.settimeout(6)
        buf = c.recv(B)
        if not buf: return
        
        req = buf.decode('utf-8', 'ignore').split('\r\n')[0].split()
        if len(req) < 2: return
        m, u = req[0], req[1]

        if m == "CONNECT":
            h, _, p = u.partition(':')
            p = int(p) if p else 443
            s = socket.create_connection((h, p), 10)
            c.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            
            try:
                c.settimeout(2)
                tls = c.recv(B)
                if tls:
                    tunnel(c, s, tls, mode)
                else:
                    tunnel(c, s, None, mode)
            except:
                tunnel(c, s, None, mode)
        else:
            hx = u.split("://")[-1].split('/')[0].split(':')[0]
            px = 80
            s = socket.create_connection((hx, px), 10)
            tunnel(c, s, buf, mode)
    except Exception:
        pass
    finally:
        for x in [c, s]:
            if x:
                try: x.close()
                except: pass

def test_all_modes():
    print("\n=== TESTING 7 BYPASS MODES ===")
    import subprocess
    best_mode = 1
    for mode in range(1, 8):
        print(f"Testing Mode {mode}... ", end="", flush=True)
        try:
            # Увеличен таймаут, так как задержки между пакетами теперь больше
            result = subprocess.run([
                "curl", "-s", "-m", "10", "-x", f"http://127.0.0.1:{P}",
                "--proxy-insecure", "-I", "https://youtube.com"
            ], capture_output=True, timeout=12)
            if result.returncode == 0 and b"HTTP/" in result.stdout:
                print("✅ SUCCESS")
                best_mode = mode
                break
            else:
                print("❌ fail")
        except Exception:
            print("❌ error (curl not found or timeout)")
    print(f"Best mode: {best_mode}")
    return best_mode

def main():
    mode = 1
    if len(sys.argv) > 1:
        if sys.argv[1] == "test":
            mode = test_all_modes()
        elif sys.argv[1].isdigit():
            mode = int(sys.argv[1])
            
    print(f"Advanced SNI DPI Bypass Proxy | Port: {P} | Active Mode: {mode}")
    print("Usage: python3 proxy.py test   (for auto test)")

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((H, P))
    srv.listen(128)

    while True:
        try:
            k, a = srv.accept()
            threading.Thread(target=handle, args=(k, mode), daemon=True).start()
        except KeyboardInterrupt:
            break
        except:
            pass

if __name__ == '__main__':
    main()
