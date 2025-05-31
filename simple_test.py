import socket
import time

def simple_udp_listener():
    """Listener UDP sederhana untuk port 5056"""
    print("🎮 Simple Albion Online Packet Listener")
    print("=" * 40)
    
    try:
        # Buat UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Bind ke semua interface di port 5056
        sock.bind(('0.0.0.0', 5056))
        sock.settimeout(1.0)  # Timeout 1 detik
        
        print("👂 Listening on port 5056...")
        print("📝 PENTING: Port 5056 harus bebas (tutup Albion dulu jika perlu)")
        print("⏱️ Akan berhenti otomatis setelah 30 detik atau tekan Ctrl+C")
        
        start_time = time.time()
        packet_count = 0
        
        while time.time() - start_time < 30:  # 30 detik timeout
            try:
                data, addr = sock.recvfrom(4096)
                packet_count += 1
                
                print(f"📦 Packet #{packet_count} from {addr[0]}:{addr[1]}")
                print(f"   Size: {len(data)} bytes")
                print(f"   First 20 bytes: {data[:20].hex()}")
                print()
                
                if packet_count >= 5:
                    print("✅ Berhasil menangkap 5 paket!")
                    break
                    
            except socket.timeout:
                continue  # Lanjut loop
                
        if packet_count == 0:
            print("❌ Tidak ada paket diterima")
            print("💡 Tips:")
            print("   - Pastikan tidak ada aplikasi lain di port 5056")
            print("   - Coba jalankan sebagai Administrator")
            print("   - Firewall mungkin memblokir")
        
    except PermissionError:
        print("❌ Permission denied - jalankan sebagai Administrator")
    except OSError as e:
        if e.errno == 10048:  # Port already in use
            print("❌ Port 5056 sudah digunakan aplikasi lain")
            print("💡 Tutup Albion Online atau aplikasi lain yang menggunakan port ini")
        else:
            print(f"❌ OS Error: {e}")
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        try:
            sock.close()
        except:
            pass

def port_scanner():
    """Scan port yang sedang digunakan"""
    print("\n🔍 Scanning common game ports...")
    
    common_ports = [5056, 5055, 5054, 80, 443, 8080]
    
    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        
        try:
            result = sock.connect_ex(('127.0.0.1', port))
            if result == 0:
                print(f"✅ Port {port} is OPEN")
            else:
                print(f"❌ Port {port} is CLOSED")
        except Exception:
            print(f"❓ Port {port} - unknown")
        finally:
            sock.close()

if __name__ == "__main__":
    try:
        simple_udp_listener()
        port_scanner()
    except KeyboardInterrupt:
        print("\n\n⏹️ Stopped by user")
    
    print("\n" + "="*50)
    print("Jika ini tidak berhasil, lanjut ke pyshark troubleshooting")