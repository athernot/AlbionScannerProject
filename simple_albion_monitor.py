# -*- coding: utf-8 -*-
"""
Simple Albion Online Network Monitor
Monitors basic packet flow without complex protocol decoding
"""

import pyshark
import time
import sys
import os
from collections import defaultdict, deque

# Set encoding for Windows console
if sys.platform.startswith('win'):
    os.system('chcp 65001 >nul 2>&1')

class SimpleAlbionMonitor:
    def __init__(self, interface='5', port=5056):
        self.interface = interface
        self.port = port
        self.running = False
        
        # Statistics
        self.stats = {
            'total_packets': 0,
            'incoming': 0,
            'outgoing': 0,
            'bytes_in': 0,
            'bytes_out': 0,
            'start_time': 0
        }
        
        # Traffic analysis
        self.packet_sizes = defaultdict(int)
        self.traffic_timeline = deque(maxlen=100)
        
    def analyze_packet_pattern(self, length, direction):
        """Analyze packet pattern based on size and direction"""
        pattern_type = "unknown"
        
        if direction == "outgoing":
            if 50 <= length <= 80:
                pattern_type = "movement/command"
            elif 80 <= length <= 120:
                pattern_type = "action/interaction"
        else:  # incoming
            if 100 <= length <= 150:
                pattern_type = "status_update"
            elif 150 <= length <= 300:
                pattern_type = "player_data"
            elif length > 300:
                pattern_type = "bulk_data"
        
        return pattern_type
    
    def display_packet_info(self, packet_num, src_ip, src_port, dst_ip, dst_port, length, direction):
        """Display packet information"""
        timestamp = time.strftime("%H:%M:%S")
        
        # Direction symbol
        direction_symbol = "<--" if direction == "incoming" else "-->"
        
        # Pattern analysis
        pattern = self.analyze_packet_pattern(length, direction)
        
        # Format output
        if direction == "incoming":
            endpoint = f"{src_ip}:{src_port} -> Local:{dst_port}"
        else:
            endpoint = f"Local:{src_port} -> {dst_ip}:{dst_port}"
        
        print(f"[{timestamp}] {direction_symbol} #{packet_num:4d} | {endpoint:35} | {length:4d}B | {pattern}")
    
    def display_statistics(self):
        """Display current statistics"""
        runtime = time.time() - self.stats['start_time']
        
        print(f"\n" + "=" * 70)
        print(f"ALBION MONITOR STATISTICS")
        print(f"=" * 70)
        print(f"Runtime: {runtime:.1f} seconds")
        print(f"Total packets: {self.stats['total_packets']}")
        print(f"Incoming: {self.stats['incoming']} ({self.stats['bytes_in']} bytes)")
        print(f"Outgoing: {self.stats['outgoing']} ({self.stats['bytes_out']} bytes)")
        
        if runtime > 0:
            pps = self.stats['total_packets'] / runtime
            bps_in = self.stats['bytes_in'] / runtime
            bps_out = self.stats['bytes_out'] / runtime
            print(f"Rate: {pps:.1f} packets/sec, {bps_in:.0f} bytes/sec in, {bps_out:.0f} bytes/sec out")
        
        # Most common packet sizes
        print(f"\nMost common packet sizes:")
        sorted_sizes = sorted(self.packet_sizes.items(), key=lambda x: x[1], reverse=True)
        for size, count in sorted_sizes[:10]:
            percentage = (count / self.stats['total_packets']) * 100
            print(f"  {size:3d} bytes: {count:3d} packets ({percentage:.1f}%)")
        
        print("=" * 70)
    
    def start_monitoring(self, duration=None):
        """Start monitoring Albion traffic"""
        print("SIMPLE ALBION ONLINE MONITOR")
        print("=" * 50)
        print(f"Interface: {self.interface}")
        print(f"Port: {self.port}")
        print(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("-" * 50)
        print("NOTE: Make sure Albion Online is running and active!")
        print("CTRL+C: Press Ctrl+C to stop monitoring")
        print()
        
        self.running = True
        self.stats['start_time'] = time.time()
        last_stats_display = time.time()
        
        try:
            # Create capture with BPF filter
            capture = pyshark.LiveCapture(
                interface=self.interface,
                bpf_filter=f"udp port {self.port}"
            )
            
            print("SUCCESS: Monitoring started...")
            print()
            
            for packet in capture.sniff_continuously():
                if not self.running:
                    break
                
                try:
                    # Extract basic packet info
                    src_ip = packet.ip.src
                    dst_ip = packet.ip.dst
                    src_port = int(packet.udp.srcport)
                    dst_port = int(packet.udp.dstport)
                    length = int(packet.length)
                    
                    # Determine direction
                    direction = "incoming" if src_port == self.port else "outgoing"
                    
                    # Update statistics
                    self.stats['total_packets'] += 1
                    self.packet_sizes[length] += 1
                    
                    if direction == "incoming":
                        self.stats['incoming'] += 1
                        self.stats['bytes_in'] += length
                    else:
                        self.stats['outgoing'] += 1
                        self.stats['bytes_out'] += length
                    
                    # Store for timeline
                    self.traffic_timeline.append({
                        'timestamp': time.time(),
                        'direction': direction,
                        'length': length
                    })
                    
                    # Display packet info
                    self.display_packet_info(
                        self.stats['total_packets'],
                        src_ip, src_port, dst_ip, dst_port,
                        length, direction
                    )
                    
                    # Display statistics every 30 seconds
                    current_time = time.time()
                    if current_time - last_stats_display > 30:
                        self.display_statistics()
                        last_stats_display = current_time
                    
                    # Check duration limit
                    if duration and (current_time - self.stats['start_time'] > duration):
                        print(f"\nTIMEOUT: Duration limit reached ({duration}s)")
                        break
                
                except Exception as e:
                    print(f"ERROR: Error processing packet: {e}")
                    continue
            
            capture.close()
            
        except KeyboardInterrupt:
            print(f"\nSTOPPED: Monitoring stopped by user")
        except Exception as e:
            print(f"ERROR: Monitoring failed: {e}")
        finally:
            self.running = False
            self.display_statistics()
            
            # Save traffic data
            self.save_traffic_data()
    
    def save_traffic_data(self):
        """Save traffic data to file"""
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filename = f"albion_traffic_{timestamp}.txt"
        
        try:
            with open(filename, 'w') as f:
                f.write("ALBION ONLINE TRAFFIC ANALYSIS\n")
                f.write("=" * 50 + "\n")
                f.write(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Interface: {self.interface}\n")
                f.write(f"Port: {self.port}\n\n")
                
                # Statistics
                runtime = time.time() - self.stats['start_time']
                f.write(f"STATISTICS:\n")
                f.write(f"Runtime: {runtime:.1f} seconds\n")
                f.write(f"Total packets: {self.stats['total_packets']}\n")
                f.write(f"Incoming: {self.stats['incoming']} ({self.stats['bytes_in']} bytes)\n")
                f.write(f"Outgoing: {self.stats['outgoing']} ({self.stats['bytes_out']} bytes)\n\n")
                
                # Packet sizes
                f.write("PACKET SIZES:\n")
                sorted_sizes = sorted(self.packet_sizes.items(), key=lambda x: x[1], reverse=True)
                for size, count in sorted_sizes:
                    percentage = (count / self.stats['total_packets']) * 100
                    f.write(f"{size:3d} bytes: {count:3d} packets ({percentage:.1f}%)\n")
            
            print(f"SAVED: Traffic data saved to: {filename}")
            
        except Exception as e:
            print(f"ERROR: Failed to save traffic data: {e}")

def main():
    """Main function"""
    monitor = SimpleAlbionMonitor(
        interface='5',  # USB Tethering
        port=5056       # Albion port
    )
    
    try:
        # Run for 5 minutes by default, or until Ctrl+C
        monitor.start_monitoring(duration=300)
    except Exception as e:
        print(f"ERROR: {e}")

if __name__ == "__main__":
    main()