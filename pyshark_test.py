import pyshark
import subprocess
import os
import time
import threading

def get_tshark_interfaces():
    """Dapatkan daftar interface dari TShark langsung"""
    try:
        # Cari TShark
        tshark_paths = [
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe"
        ]
        
        tshark_path = None
        for path in tshark_paths:
            if os.path.exists(path):
                tshark_path = path
                break
        
        if not tshark_path:
            print("❌ TShark tidak ditemukan")
            return []
        
        # Jalankan tshark -D
        result = subprocess.run([tshark_path, '-D'], 
                              capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            interfaces = []
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    interfaces.append(line.strip())
            return interfaces
        else:
            print(f"❌ TShark error: {result.stderr}")
            return []
            
    except Exception as e:
        print(f"❌ Error getting interfaces: {e}")
        return []

def test_pyshark_interface(interface_spec, timeout=10):
    """Test pyshark dengan interface tertentu"""
    print(f"\n🧪 Testing PyShark dengan interface: '{interface_spec}'")
    print("-" * 60)
    
    try:
        # Buat LiveCapture object
        capture = pyshark.LiveCapture(interface=interface_spec)
        print(f"✅ LiveCapture object berhasil dibuat")
        
        # Setup timeout menggunakan threading
        result = {'success': False, 'error': None, 'packet': None}
        
        def capture_thread():
            try:
                for packet in capture.sniff_continuously():
                    result['packet'] = packet
                    result['success'] = True
                    break
            except Exception as e:
                result['error'] = e
        
        # Start capture dalam thread terpisah
        thread = threading.Thread(target=capture_thread)
        thread.daemon = True
        thread.start()
        
        # Wait dengan timeout
        thread.join(timeout)
        
        if thread.is_alive():
            print(f"⏱️ Timeout {timeout}s - tidak ada paket (tapi interface valid)")
            success = True  # Interface valid meski tidak ada paket
        elif result['success']:
            print(f"✅ BERHASIL! Paket tertangkap: {result['packet'].summary()}")
            success = True
        elif result['error']:
            print(f"❌ Error saat capture: {result['error']}")
            success = False
        else:
            print(f"❓ Status tidak jelas")
            success = False
        
        # Tutup capture
        try:
            capture.close()
        except:
            pass
            
        return success
        
    except Exception as e:
        print(f"❌ Error membuat LiveCapture: {e}")
        
        # Analisis error lebih detail
        error_str = str(e).lower()
        if 'retcode: 4' in error_str:
            print("💡 Error code 4 biasanya karena masalah interface name")
        elif 'permission' in error_str:
            print("💡 Masalah permission - coba jalankan sebagai Administrator")
        elif 'tshark' in error_str:
            print("💡 Masalah dengan TShark - periksa instalasi Wireshark")
        
        return False

def test_albion_specific(working_interfaces):
    """Test khusus untuk Albion Online"""
    if not working_interfaces:
        print("\n❌ Tidak ada interface yang bekerja untuk test Albion")
        return
    
    print(f"\n🎮 TESTING ALBION ONLINE CAPTURE")
    print("=" * 50)
    
    for interface in working_interfaces[:2]:  # Test 2 interface terbaik
        print(f"\n🎯 Testing Albion pada interface: {interface}")
        
        try:
            # Gunakan filter UDP port 5056
            capture = pyshark.LiveCapture(
                interface=interface,
                display_filter="udp port 5056",
                use_json=True,  # Coba dengan JSON mode
                include_raw=True  # Include raw data
            )
            
            print("🔍 Filter: UDP port 5056")
            print("⏱️ Menunggu 15 detik untuk paket Albion...")
            print("📱 Pastikan Albion Online berjalan dan ada aktivitas!")
            
            packet_count = 0
            start_time = time.time()
            
            for packet in capture.sniff_continuously():
                packet_count += 1
                
                print(f"\n🎯 ALBION PACKET #{packet_count}:")
                print(f"   Time: {packet.sniff_time}")
                print(f"   Length: {packet.length}")
                
                # Info UDP
                if hasattr(packet, 'udp'):
                    print(f"   UDP: {packet.udp.srcport} → {packet.udp.dstport}")
                
                # Info IP
                if hasattr(packet, 'ip'):
                    print(f"   IP: {packet.ip.src} → {packet.ip.dst}")
                
                if packet_count >= 3:
                    print(f"✅ Berhasil capture {packet_count} paket Albion!")
                    break
                
                # Timeout check
                if time.time() - start_time > 15:
                    print("⏱️ Timeout 15 detik")
                    break
            
            capture.close()
            
            if packet_count > 0:
                print(f"\n🎉 SUCCESS! Interface '{interface}' bisa capture Albion!")
                print(f"📝 Gunakan ini di script utama:")
                print(f"INTERFACE_NAME = '{interface}'")
                return interface
            else:
                print(f"❌ Tidak ada paket Albion di interface '{interface}'")
                
        except Exception as e:
            print(f"❌ Error Albion test: {e}")
    
    print(f"\n⚠️ Tidak berhasil capture paket Albion")
    print(f"💡 Kemungkinan:")
    print(f"   - Albion tidak berjalan")
    print(f"   - Tidak ada aktivitas network")
    print(f"   - Game menggunakan port/protocol lain")

def main():
    print("🔬 PYSHARK COMPREHENSIVE TEST")
    print("=" * 50)
    
    # Step 1: Dapatkan daftar interface dari TShark
    print("📡 Getting interface list from TShark...")
    interfaces = get_tshark_interfaces()
    
    if not interfaces:
        print("❌ Tidak bisa mendapatkan daftar interface")
        print("💡 Pastikan Wireshark terinstall dan jalankan sebagai Administrator")
        return
    
    print(f"✅ Ditemukan {len(interfaces)} interfaces:")
    for i, interface in enumerate(interfaces, 1):
        print(f"  {i}. {interface}")
    
    # Step 2: Test setiap interface dengan PyShark
    print(f"\n🧪 TESTING PYSHARK INTERFACES")
    print("=" * 40)
    
    working_interfaces = []
    
    for interface in interfaces:
        # Extract interface ID/name untuk test
        # Format: "1. \Device\NPF_{GUID} (Interface Name)"
        if '. ' in interface:
            interface_id = interface.split('.')[0].strip()
            interface_name = interface.split('(')[-1].replace(')', '').strip() if '(' in interface else ""
            
            # Test dengan ID numerik
            if test_pyshark_interface(interface_id):
                working_interfaces.append(interface_id)
                print(f"✅ Interface ID '{interface_id}' BEKERJA!")
            
            # Jika ada nama interface, test juga
            if interface_name and interface_name not in working_interfaces:
                if test_pyshark_interface(interface_name):
                    working_interfaces.append(interface_name)
                    print(f"✅ Interface name '{interface_name}' BEKERJA!")
    
    # Step 3: Summary
    print(f"\n📋 TEST SUMMARY")
    print("=" * 30)
    
    if working_interfaces:
        print(f"✅ {len(working_interfaces)} interface(s) bekerja:")
        for interface in working_interfaces:
            print(f"   - '{interface}'")
        
        # Step 4: Test Albion khusus
        test_albion_specific(working_interfaces)
        
    else:
        print("❌ TIDAK ADA INTERFACE YANG BEKERJA!")
        print("\n🔧 TROUBLESHOOTING:")
        print("1. Jalankan sebagai Administrator")
        print("2. Reinstall Wireshark + Npcap")
        print("3. Periksa Windows Firewall")
        print("4. Restart komputer setelah install Npcap")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⏹️ Test dibatalkan oleh user")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()