import pyshark
import time

def test_numeric_interfaces():
    """Test interface dengan ID numerik (dari hasil diagnostic)"""
    # Dari hasil diagnostic: interface 1, 4, 5, 6 yang paling mungkin
    test_interfaces = ['4', '5', '6']
    interface_names = {
        '1': 'Local Area Connection* 8',
        '4': 'Ethernet', 
        '5': 'USB Tethering',
        '6': 'vEthernet (Default Switch)'
    }
    
    working_interfaces = []
    
    for interface_id in test_interfaces:
        try:
            print(f"\n=== Testing Interface {interface_id} ({interface_names.get(interface_id, 'Unknown')}) ===")
            
            capture = pyshark.LiveCapture(interface=interface_id)
            print(f"✅ LiveCapture object berhasil dibuat untuk interface {interface_id}")
            
            # Test capture dengan timeout
            print("🔄 Testing packet capture (timeout 5 detik)...")
            packet_count = 0
            start_time = time.time()
            
            try:
                for packet in capture.sniff_continuously():
                    packet_count += 1
                    print(f"📦 Packet #{packet_count}: {packet.summary()}")
                    
                    if packet_count >= 2:  # Capture 2 paket
                        break
                    
                    if time.time() - start_time > 5:  # 5 detik timeout
                        print("⏱️ Timeout 5 detik")
                        break
                        
            except Exception as capture_error:
                print(f"Info capture: {capture_error}")
            finally:
                capture.close()
            
            if packet_count > 0:
                print(f"✅ SUCCESS! Interface {interface_id} berhasil capture {packet_count} paket")
                working_interfaces.append(interface_id)
            else:
                print(f"⚠️ Interface {interface_id} valid tapi tidak ada traffic")
                working_interfaces.append(interface_id)  # Tetap dianggap working
                
        except Exception as e:
            print(f"❌ FAILED Interface {interface_id}: {e}")
    
    return working_interfaces

def test_albion_on_interfaces(working_interfaces):
    """Test capture Albion pada interface yang bekerja"""
    if not working_interfaces:
        print("❌ Tidak ada interface yang bekerja")
        return None
    
    print(f"\n🎮 TESTING ALBION CAPTURE")
    print("=" * 40)
    
    for interface_id in working_interfaces:
        try:
            print(f"\n🎯 Testing Albion pada interface {interface_id}...")
            
            capture = pyshark.LiveCapture(
                interface=interface_id,
                display_filter="udp port 5056"
            )
            
            print("🔍 Filter: UDP port 5056")
            print("⏱️ Menunggu 15 detik untuk paket Albion...")
            print("📱 Pastikan Albion Online berjalan dan ada aktivitas!")
            
            packet_count = 0
            start_time = time.time()
            
            for packet in capture.sniff_continuously():
                packet_count += 1
                print(f"🎯 ALBION PACKET #{packet_count}: {packet.summary()}")
                
                if packet_count >= 3:
                    break
                
                if time.time() - start_time > 15:
                    print("⏱️ Timeout 15 detik")
                    break
            
            capture.close()
            
            if packet_count > 0:
                print(f"🎉 SUKSES! Interface {interface_id} berhasil capture Albion!")
                return interface_id
            else:
                print(f"❌ Tidak ada paket Albion di interface {interface_id}")
                
        except Exception as e:
            print(f"❌ Error testing Albion pada interface {interface_id}: {e}")
    
    return None

if __name__ == "__main__":
    print("🧪 PYSHARK INTERFACE TESTING")
    print("=" * 50)
    
    # Test interface numerik
    working_interfaces = test_numeric_interfaces()
    
    if working_interfaces:
        print(f"\n✅ Interface yang bekerja: {working_interfaces}")
        
        # Test Albion khusus
        albion_interface = test_albion_on_interfaces(working_interfaces)
        
        if albion_interface:
            print(f"\n🎉 FINAL RESULT:")
            print(f"Interface untuk Albion: {albion_interface}")
            print(f"\n📝 Update test.py dengan:")
            print(f"INTERFACE_NAME = '{albion_interface}'")
        else:
            print(f"\n⚠️ Tidak ada paket Albion tertangkap")
            print(f"💡 Gunakan interface: {working_interfaces[0]} (yang pertama)")
            print(f"\n📝 Update test.py dengan:")
            print(f"INTERFACE_NAME = '{working_interfaces[0]}'")
    else:
        print(f"\n❌ Tidak ada interface yang bekerja")
        print(f"💡 Coba jalankan sebagai Administrator")