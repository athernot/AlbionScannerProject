import pyshark
import time
from datetime import datetime

# Configuration - dari hasil testing yang berhasil
INTERFACE_NAME = '5'  # USB Tethering - terbukti bekerja
ALBION_PORT = 5056    # Terbukti digunakan oleh Albion

class AlbionPacketScanner:
    def __init__(self, interface=INTERFACE_NAME, target_port=ALBION_PORT):
        self.interface = interface
        self.target_port = target_port
        self.packet_count = 0
        self.start_time = None
        
    def log_packet(self, packet):
        """Log packet Albion dengan detail yang berguna"""
        self.packet_count += 1
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        
        try:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            src_port = int(packet.udp.srcport)
            dst_port = int(packet.udp.dstport)
            length = int(packet.length)
            
            # Tentukan direction (outgoing vs incoming)
            if src_port == self.target_port:
                direction = "⬅️ IN "
                endpoint = f"{src_ip}:{src_port} → Local:{dst_port}"
            else:
                direction = "➡️ OUT"
                endpoint = f"Local:{src_port} → {dst_ip}:{dst_port}"
            
            print(f"[{timestamp}] {direction} #{self.packet_count:4d} | {endpoint:35} | {length:4d} bytes")
            
            # TODO: Disini bisa ditambahkan parsing packet untuk data game
            # packet_data = packet.get_raw_packet()
            
        except Exception as e:
            print(f"[{timestamp}] ERROR parsing packet #{self.packet_count}: {e}")
    
    def start_capture_with_bpf(self):
        """Method 1: Menggunakan BPF filter (Berkeley Packet Filter)"""
        print(f"🎯 ALBION SCANNER - BPF Filter Method")
        print(f"Interface: {self.interface} (USB Tethering)")
        print(f"Target Port: {self.target_port}")
        print(f"Filter: udp port {self.target_port}")
        print("-" * 80)
        
        try:
            capture = pyshark.LiveCapture(
                interface=self.interface,
                bpf_filter=f"udp port {self.target_port}"
            )
            
            self.start_time = time.time()
            print(f"📡 Capture started at {datetime.now().strftime('%H:%M:%S')}")
            print(f"📱 Make sure Albion Online is running and active!")
            print(f"⏹️  Press Ctrl+C to stop\n")
            
            for packet in capture.sniff_continuously():
                self.log_packet(packet)
                
                # Optional: Stop after certain number of packets for testing
                # if self.packet_count >= 50:
                #     break
            
        except KeyboardInterrupt:
            print(f"\n⏹️ Capture stopped by user")
        except Exception as e:
            print(f"❌ BPF capture error: {e}")
            return False
        finally:
            try:
                capture.close()
            except:
                pass
            
            elapsed = time.time() - self.start_time if self.start_time else 0
            print(f"\n📊 Summary: {self.packet_count} packets captured in {elapsed:.1f} seconds")
        
        return True
    
    def start_capture_with_manual_filter(self):
        """Method 2: Manual filtering (fallback method)"""
        print(f"🎯 ALBION SCANNER - Manual Filter Method")
        print(f"Interface: {self.interface} (USB Tethering)")
        print(f"Target Port: {self.target_port}")
        print("-" * 80)
        
        try:
            capture = pyshark.LiveCapture(interface=self.interface)
            
            self.start_time = time.time()
            total_packets = 0
            
            print(f"📡 Capture started at {datetime.now().strftime('%H:%M:%S')}")
            print(f"📱 Make sure Albion Online is running and active!")
            print(f"⏹️  Press Ctrl+C to stop\n")
            
            for packet in capture.sniff_continuously():
                total_packets += 1
                
                try:
                    # Manual filter untuk UDP port target
                    if hasattr(packet, 'udp'):
                        src_port = int(packet.udp.srcport)
                        dst_port = int(packet.udp.dstport)
                        
                        if src_port == self.target_port or dst_port == self.target_port:
                            self.log_packet(packet)
                    
                    # Progress setiap 500 packet
                    if total_packets % 500 == 0:
                        elapsed = time.time() - self.start_time
                        rate = self.packet_count / elapsed if elapsed > 0 else 0
                        print(f"📊 Progress: {total_packets} total, {self.packet_count} Albion ({rate:.1f}/sec)")
                
                except AttributeError:
                    # Skip non-UDP packets
                    continue
                except Exception as e:
                    continue
            
        except KeyboardInterrupt:
            print(f"\n⏹️ Capture stopped by user")
        except Exception as e:
            print(f"❌ Manual capture error: {e}")
            return False
        finally:
            try:
                capture.close()
            except:
                pass
            
            elapsed = time.time() - self.start_time if self.start_time else 0
            print(f"\n📊 Summary: {self.packet_count} Albion packets from {total_packets} total in {elapsed:.1f} seconds")
        
        return True
    
    def start(self, method="auto"):
        """Start packet capture dengan method yang dipilih"""
        print(f"🚀 ALBION ONLINE PACKET SCANNER")
        print(f"=" * 80)
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        
        if method == "auto":
            # Coba BPF filter dulu, kalau gagal pakai manual
            print("🔧 Trying BPF filter method first...")
            if not self.start_capture_with_bpf():
                print("\n🔧 BPF failed, switching to manual filter method...")
                self.packet_count = 0  # Reset counter
                return self.start_capture_with_manual_filter()
            return True
        elif method == "bpf":
            return self.start_capture_with_bpf()
        elif method == "manual":
            return self.start_capture_with_manual_filter()
        else:
            print(f"❌ Unknown method: {method}")
            return False

def main():
    """Main function"""
    scanner = AlbionPacketScanner()
    
    try:
        success = scanner.start(method="auto")  # auto, bpf, atau manual
        
        if success:
            print(f"✅ Scanner completed successfully!")
        else:
            print(f"❌ Scanner failed!")
            
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()