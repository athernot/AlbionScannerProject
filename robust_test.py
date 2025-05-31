import pyshark
import psutil
import time
import sys

def get_available_interfaces():
    """Dapatkan daftar interface yang tersedia"""
    try:
        interfaces = psutil.net_if_addrs()
        return list(interfaces.keys())
    except Exception as e:
        print(f"Error mendapatkan interface: {e}")
        return []

def test_interface(interface_name, timeout=10):
    """Test satu interface dengan timeout"""
    print(f"\n=== Testing Interface: '{interface_name}' ===")
    
    try:
        # Buat capture object
        capture = pyshark.LiveCapture(interface=interface_name)
        
        print(f"✅ LiveCapture object berhasil dibuat untuk '{interface_name}'")
        
        # Test capture dengan timeout
        print("🔄 Mencoba capture paket (timeout 10 detik)...")
        
        packet_found = False
        start_time = time.time()
        
        try:
            # Gunakan sniff_continuously dengan timeout
            for packet in capture.sniff_continuously():
                print(f"✅ BERHASIL! Paket tertangkap: {packet.summary()}")
                packet_found = True
                break
                
                # Check timeout
                if time.time() - start_time > timeout:
                    print("⏱️ Timeout - tidak ada paket dalam 10 detik")
                    break
                    
        except Exception as capture_error:
            print(f"❌ Error saat capture: {capture_error}")
            
        finally:
            try:
                capture.close()
            except:
                pass
        
        return packet_found
        
    except Exception as e:
        print(f"❌ Error membuat LiveCapture: {e}")
        return False

def test_albion_capture(interface_name):
    """Test capture khusus untuk Albion Online"""
    print(f"\n=== Testing Albion Capture pada '{interface_name}' ===")
    
    try:
        # Test dengan filter UDP port 5056
        capture = pyshark.LiveCapture(
            interface=interface_name, 
            display_filter="udp port 5056"
        )
        
        print("🎮 Menunggu paket Albion Online (UDP port 5056)...")
        print("   Pastikan Albion Online sedang berjalan dan aktif!")
        print("   Akan timeout dalam 30 detik jika tidak ada paket...")
        
        packet_count = 0
        start_time = time.time()
        
        for packet in capture.sniff_continuously():
            packet_count += 1
            print(f"🎯 Albion packet #{packet_count}: {packet.summary()}")
            
            if packet_count >= 3:  # Tangkap 3 paket saja
                print("✅ Berhasil menangkap paket Albion!")
                break
                
            # Timeout setelah 30 detik
            if time.time() - start_time > 30:
                print("⏱️ Timeout - tidak ada paket Albion dalam 30 detik")
                break
        
        capture.close()
        return packet_count > 0
        
    except Exception as e:
        print(f"❌ Error Albion capture: {e}")
        return False

def main():
    print("🔍 ALBION PACKET CAPTURE TROUBLESHOOTER")
    print("=" * 50)
    
    # Step 1: Dapatkan daftar interface
    interfaces = get_available_interfaces()
    
    if not interfaces:
        print("❌ Tidak bisa mendapatkan daftar interface!")
        return
    
    print(f"📡 Ditemukan {len(interfaces)} interface:")
    for i, interface in enumerate(interfaces, 1):
        print(f"  {i}. '{interface}'")
    
    # Step 2: Test setiap interface
    working_interfaces = []
    
    for interface in interfaces:
        if test_interface(interface):
            working_interfaces.append(interface)
    
    if not working_interfaces:
        print("\n❌ TIDAK ADA INTERFACE YANG BEKERJA!")
        print("\nSolusi yang bisa dicoba:")
        print("1. Install/reinstall Wireshark dengan Npcap")
        print("2. Jalankan script sebagai Administrator")
        print("3. Periksa firewall dan antivirus")
        return
    
    print(f"\n✅ Interface yang bekerja: {working_interfaces}")
    
    # Step 3: Test Albion capture pada interface yang bekerja
    print(f"\n🎮 TESTING ALBION CAPTURE")
    print("=" * 30)
    
    for interface in working_interfaces:
        print(f"\n🔄 Testing Albion pada '{interface}'...")
        
        if test_albion_capture(interface):
            print(f"🎉 SUKSES! Interface '{interface}' bisa menangkap paket Albion!")
            print(f"\n📝 Gunakan interface ini di script utama:")
            print(f"INTERFACE_NAME = '{interface}'")
            break
    else:
        print("\n⚠️ Tidak ada paket Albion tertangkap.")
        print("Pastikan:")
        print("- Albion Online sedang berjalan")
        print("- Anda sedang bermain (tidak idle)")
        print("- Game menggunakan koneksi yang benar")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⏹️ Dibatalkan oleh user")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        print("Coba jalankan sebagai Administrator")