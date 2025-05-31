import pyshark
import time
import threading

def capture_all_packets_and_filter(interface_id, duration=30):
    """Capture semua paket lalu filter secara manual"""
    print(f"🎯 Capturing ALL packets pada interface {interface_id} untuk {duration} detik...")
    print("📱 Pastikan Albion Online berjalan dan ada aktivitas!")
    
    albion_packets = []
    packet_count = 0
    
    try:
        # Capture TANPA filter dulu
        capture = pyshark.LiveCapture(interface=interface_id)
        
        start_time = time.time()
        
        for packet in capture.sniff_continuously():
            packet_count += 1
            
            try:
                # Manual filtering untuk UDP port 5056
                if hasattr(packet, 'udp'):
                    src_port = int(packet.udp.srcport)
                    dst_port = int(packet.udp.dstport)
                    
                    if src_port == 5056 or dst_port == 5056:
                        albion_packets.append(packet)
                        print(f"🎯 ALBION PACKET #{len(albion_packets)}:")
                        print(f"   UDP: {packet.ip.src}:{src_port} → {packet.ip.dst}:{dst_port}")
                        print(f"   Length: {packet.length}")
                        print(f"   Time: {packet.sniff_time}")
                        
                        if len(albion_packets) >= 5:  # Stop setelah 5 paket Albion
                            print("✅ Berhasil capture 5 paket Albion!")
                            break
                
                # Progress indicator
                if packet_count % 100 == 0:
                    elapsed = time.time() - start_time
                    print(f"📊 {packet_count} paket total, {len(albion_packets)} Albion, {elapsed:.1f}s elapsed")
                
                # Timeout check
                if time.time() - start_time > duration:
                    print(f"⏱️ Timeout {duration} detik")
                    break
                    
            except AttributeError:
                # Skip paket yang tidak punya UDP layer
                continue
            except Exception as e:
                print(f"Error processing packet: {e}")
                continue
        
        capture.close()
        
        # Summary
        print(f"\n📋 HASIL CAPTURE:")
        print(f"Total paket: {packet_count}")
        print(f"Paket Albion: {len(albion_packets)}")
        
        if len(albion_packets) > 0:
            print(f"🎉 SUKSES! Ditemukan {len(albion_packets)} paket Albion Online!")
            return True, interface_id
        else:
            print(f"❌ Tidak ada paket Albion ditemukan")
            return False, interface_id
            
    except Exception as e:
        print(f"❌ Error capture: {e}")
        return False, interface_id

def test_capture_without_filter(interface_id, duration=10):
    """Test capture basic tanpa filter sama sekali"""
    print(f"\n🧪 Testing basic capture pada interface {interface_id}...")
    
    try:
        capture = pyshark.LiveCapture(interface=interface_id)
        
        packet_count = 0
        start_time = time.time()
        
        for packet in capture.sniff_continuously():
            packet_count += 1
            
            # Analisis packet secara manual
            try:
                protocols = []
                if hasattr(packet, 'ip'):
                    protocols.append('IP')
                if hasattr(packet, 'tcp'):
                    protocols.append(f"TCP:{packet.tcp.srcport}→{packet.tcp.dstport}")
                if hasattr(packet, 'udp'):
                    protocols.append(f"UDP:{packet.udp.srcport}→{packet.udp.dstport}")
                if hasattr(packet, 'http'):
                    protocols.append('HTTP')
                
                print(f"📦 Packet #{packet_count}: {' | '.join(protocols) if protocols else 'Unknown'}")
                
                # Check jika ini paket game (port range yang umum untuk game)
                if hasattr(packet, 'udp'):
                    port = int(packet.udp.dstport)
                    if 5000 <= port <= 6000:  # Range port game
                        print(f"   🎮 GAME PORT DETECTED: {port}")
                
            except Exception as e:
                print(f"📦 Packet #{packet_count}: [Error parsing: {e}]")
            
            if packet_count >= 20:  # Limit untuk test
                break
                
            if time.time() - start_time > duration:
                print("⏱️ Timeout")
                break
        
        capture.close()
        print(f"✅ Basic capture berhasil: {packet_count} paket")
        return True
        
    except Exception as e:
        print(f"❌ Basic capture gagal: {e}")
        return False

def alternative_filter_method(interface_id):
    """Coba metode filter alternatif"""
    print(f"\n🔧 Testing alternative filter methods pada interface {interface_id}...")
    
    # Method 1: Capture filter (bukan display filter)
    try:
        print("Method 1: Capture filter...")
        capture = pyshark.LiveCapture(
            interface=interface_id,
            bpf_filter="udp port 5056"  # Berkeley Packet Filter
        )
        
        packet_count = 0
        start_time = time.time()
        
        for packet in capture.sniff_continuously():
            packet_count += 1
            print(f"🎯 Filtered packet #{packet_count}: UDP {packet.ip.src}:{packet.udp.srcport} → {packet.ip.dst}:{packet.udp.dstport}")
            
            if packet_count >= 3:
                break
                
            if time.time() - start_time > 15:
                print("⏱️ Timeout 15s")
                break
        
        capture.close()
        
        if packet_count > 0:
            print(f"✅ Capture filter BERHASIL! {packet_count} paket")
            return True, "bpf_filter"
        else:
            print("❌ Capture filter: tidak ada paket")
            
    except Exception as e:
        print(f"❌ Capture filter error: {e}")
    
    # Method 2: Use tshark_path parameter
    try:
        print("\nMethod 2: Explicit tshark path...")
        capture = pyshark.LiveCapture(
            interface=interface_id,
            tshark_path=r"C:\Program Files\Wireshark\tshark.exe",
            display_filter="udp.port == 5056"  # Alternative syntax
        )
        
        packet_count = 0
        start_time = time.time()
        
        for packet in capture.sniff_continuously():
            packet_count += 1
            print(f"🎯 Alt filter packet #{packet_count}")
            
            if packet_count >= 3:
                break
                
            if time.time() - start_time > 15:
                break
        
        capture.close()
        
        if packet_count > 0:
            print(f"✅ Alt display filter BERHASIL! {packet_count} paket")
            return True, "alt_display_filter"
        else:
            print("❌ Alt display filter: tidak ada paket")
            
    except Exception as e:
        print(f"❌ Alt display filter error: {e}")
    
    return False, None

def main():
    print("🔧 ALBION CAPTURE TROUBLESHOOTING")
    print("=" * 50)
    
    # Interface yang bekerja dari test sebelumnya
    working_interfaces = ['4', '5', '6']
    
    for interface_id in working_interfaces:
        print(f"\n🎯 TESTING INTERFACE {interface_id}")
        print("=" * 30)
        
        # Test 1: Basic capture
        if not test_capture_without_filter(interface_id, duration=5):
            print(f"❌ Interface {interface_id} basic capture gagal, skip...")
            continue
        
        # Test 2: Alternative filter methods
        success, method = alternative_filter_method(interface_id)
        if success:
            print(f"🎉 SUKSES dengan method: {method}")
            print(f"📝 Konfigurasi yang bekerja:")
            if method == "bpf_filter":
                print(f"capture = pyshark.LiveCapture(interface='{interface_id}', bpf_filter='udp port 5056')")
            else:
                print(f"capture = pyshark.LiveCapture(interface='{interface_id}', tshark_path=r'C:\\Program Files\\Wireshark\\tshark.exe', display_filter='udp.port == 5056')")
            break
        
        # Test 3: Manual filtering (fallback)
        print(f"\n🔄 Trying manual filtering method...")
        success, _ = capture_all_packets_and_filter(interface_id, duration=15)
        if success:
            print(f"🎉 SUKSES dengan manual filtering!")
            print(f"📝 Gunakan interface {interface_id} dengan manual filtering")
            break
    
    else:
        print(f"\n❌ Semua method gagal pada semua interface")
        print(f"💡 Kemungkinan:")
        print(f"   - Albion Online tidak berjalan")
        print(f"   - Port 5056 tidak digunakan oleh Albion")
        print(f"   - Game menggunakan TCP bukan UDP")
        print(f"   - Perlu troubleshooting lebih lanjut")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⏹️ Dibatalkan oleh user")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()