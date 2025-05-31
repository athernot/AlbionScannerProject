import pyshark
import time
from collections import Counter

def analyze_game_traffic(interface_id, duration=30):
    """Analisis traffic untuk menemukan port yang digunakan game"""
    print(f"🕵️ ANALYZING NETWORK TRAFFIC untuk menemukan game ports...")
    print(f"Interface: {interface_id}, Duration: {duration} detik")
    print("📱 Pastikan Albion Online berjalan dan ada aktivitas!")
    
    udp_ports = Counter()
    tcp_ports = Counter()
    game_candidates = []
    
    try:
        capture = pyshark.LiveCapture(interface=interface_id)
        
        packet_count = 0
        start_time = time.time()
        
        for packet in capture.sniff_continuously():
            packet_count += 1
            
            try:
                # Analisis UDP traffic
                if hasattr(packet, 'udp'):
                    src_port = int(packet.udp.srcport)
                    dst_port = int(packet.udp.dstport)
                    
                    # Count port usage
                    udp_ports[dst_port] += 1
                    udp_ports[src_port] += 1
                    
                    # Look for game-like ports (non-standard ports)
                    for port in [src_port, dst_port]:
                        if 1024 <= port <= 65535 and port not in [53, 123, 137, 138, 139]:  # Skip DNS, NTP, NetBIOS
                            game_candidates.append(('UDP', port, packet.ip.src, packet.ip.dst))
                
                # Analisis TCP traffic  
                if hasattr(packet, 'tcp'):
                    src_port = int(packet.tcp.srcport)
                    dst_port = int(packet.tcp.dstport)
                    
                    tcp_ports[dst_port] += 1
                    tcp_ports[src_port] += 1
                    
                    # Look for game-like ports
                    for port in [src_port, dst_port]:
                        if 1024 <= port <= 65535 and port not in [80, 443, 22, 21, 25]:  # Skip common web/service ports
                            game_candidates.append(('TCP', port, packet.ip.src, packet.ip.dst))
                
                # Progress
                if packet_count % 200 == 0:
                    elapsed = time.time() - start_time
                    print(f"📊 {packet_count} packets analyzed, {elapsed:.1f}s elapsed")
                
                # Stop conditions
                if time.time() - start_time > duration:
                    print(f"⏱️ Analysis complete after {duration} seconds")
                    break
                    
            except Exception as e:
                continue
        
        capture.close()
        
        # Analysis results
        print(f"\n📋 TRAFFIC ANALYSIS RESULTS:")
        print(f"Total packets analyzed: {packet_count}")
        
        # Top UDP ports
        print(f"\n🔵 TOP UDP PORTS:")
        for port, count in udp_ports.most_common(10):
            status = "🎮 GAME CANDIDATE" if 1024 <= port <= 65535 and port not in [53, 123] else ""
            print(f"  Port {port}: {count} packets {status}")
        
        # Top TCP ports  
        print(f"\n🔴 TOP TCP PORTS:")
        for port, count in tcp_ports.most_common(10):
            status = "🎮 GAME CANDIDATE" if 1024 <= port <= 65535 and port not in [80, 443, 22] else ""
            print(f"  Port {port}: {count} packets {status}")
        
        # Game port candidates
        if game_candidates:
            print(f"\n🎯 POTENTIAL GAME PORTS:")
            game_port_summary = Counter()
            for protocol, port, src, dst in game_candidates[-50:]:  # Last 50 game packets
                game_port_summary[(protocol, port)] += 1
            
            for (protocol, port), count in game_port_summary.most_common(15):
                print(f"  {protocol} port {port}: {count} packets")
                
                # Specific recommendations
                if port == 5056:
                    print(f"    ✅ This matches expected Albion port!")
                elif 5000 <= port <= 6000:
                    print(f"    🎮 This looks like a game port - try filtering this!")
        
        # Recommendations
        print(f"\n💡 RECOMMENDATIONS:")
        
        # Check if 5056 was found
        if udp_ports.get(5056, 0) > 0:
            print(f"✅ UDP port 5056 found! ({udp_ports[5056]} packets)")
            print(f"   Original filter should work - ada masalah dengan syntax filter")
        else:
            print(f"❌ UDP port 5056 not found")
            
            # Suggest alternative ports
            top_game_ports = []
            for port, count in udp_ports.most_common(5):
                if 1024 <= port <= 65535 and port not in [53, 123]:
                    top_game_ports.append(port)
            
            if top_game_ports:
                print(f"🎯 Try filtering these UDP ports instead:")
                for port in top_game_ports[:3]:
                    print(f"   udp port {port}")
        
        return udp_ports, tcp_ports
        
    except Exception as e:
        print(f"❌ Analysis error: {e}")
        return None, None

if __name__ == "__main__":
    print("🕵️ NETWORK TRAFFIC DETECTIVE")
    print("=" * 50)
    
    # Use working interface
    interface_id = '5'  # Atau '5' atau '6'
    
    print(f"🎯 Analyzing traffic on interface {interface_id}")
    print("📱 Make sure Albion Online is running and active!")
    print("🎮 Try doing some actions in-game during analysis")
    
    try:
        udp_ports, tcp_ports = analyze_game_traffic(interface_id, duration=45)
        
        if udp_ports:
            print(f"\n🔍 DETECTIVE COMPLETE!")
            print(f"Use the port information above to update your filters.")
        else:
            print(f"\n❌ Analysis failed - try different interface or longer duration")
            
    except KeyboardInterrupt:
        print(f"\n\n⏹️ Analysis stopped by user")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")