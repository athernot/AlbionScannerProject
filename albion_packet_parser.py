import pyshark
import struct
import json
import time
from datetime import datetime
from collections import defaultdict
import hashlib

class AlbionPacketParser:
    def __init__(self, interface='5', port=5056):
        self.interface = interface
        self.port = port
        self.packet_count = 0
        self.parsed_data = defaultdict(list)
        self.unknown_patterns = defaultdict(int)
        
        # Known Albion packet signatures and patterns
        self.packet_signatures = {
            # Common headers/patterns (will be updated as we discover more)
            b'\x01\x00': 'handshake',
            b'\x02\x00': 'auth',
            b'\x03\x00': 'position_update',
            b'\x04\x00': 'chat_message',
            b'\x05\x00': 'player_action',
            b'\x06\x00': 'item_data',
            b'\x07\x00': 'map_data',
            b'\x08\x00': 'player_info',
        }
        
        # Player data structure patterns
        self.player_patterns = {
            'position': {'x': 0, 'y': 0, 'z': 0},
            'name': '',
            'guild': '',
            'health': 0,
            'energy': 0,
            'items': []
        }
    
    def extract_raw_payload(self, packet):
        """Extract raw UDP payload dari packet"""
        try:
            # Get raw packet data
            raw_packet = packet.get_raw_packet()
            
            # Parse IP header untuk mendapatkan offset UDP
            ip_header_length = (raw_packet[14] & 0x0F) * 4  # IP header variable length
            udp_start = 14 + ip_header_length  # Ethernet(14) + IP header
            udp_payload_start = udp_start + 8  # UDP header is 8 bytes
            
            # Extract UDP payload
            payload = raw_packet[udp_payload_start:]
            return payload
            
        except Exception as e:
            print(f"Error extracting payload: {e}")
            return None
    
    def analyze_packet_structure(self, payload):
        """Analisis struktur packet untuk mengidentifikasi pola"""
        if not payload or len(payload) < 4:
            return None
        
        analysis = {
            'length': len(payload),
            'header': payload[:4].hex(),
            'first_bytes': payload[:16].hex() if len(payload) >= 16 else payload.hex(),
            'last_bytes': payload[-16:].hex() if len(payload) >= 16 else payload.hex(),
            'has_strings': False,
            'possible_coordinates': [],
            'possible_ids': [],
            'entropy': self.calculate_entropy(payload)
        }
        
        # Look for ASCII strings (player names, chat, etc)
        try:
            decoded = payload.decode('utf-8', errors='ignore')
            if any(c.isprintable() and c.isascii() for c in decoded):
                analysis['has_strings'] = True
                analysis['decoded_preview'] = decoded[:100]
        except:
            pass
        
        # Look for possible coordinates (float values)
        for i in range(0, len(payload) - 4, 4):
            try:
                float_val = struct.unpack('f', payload[i:i+4])[0]
                if -10000 < float_val < 10000:  # Reasonable coordinate range
                    analysis['possible_coordinates'].append((i, float_val))
            except:
                continue
        
        # Look for possible IDs (uint32)
        for i in range(0, len(payload) - 4, 4):
            try:
                uint_val = struct.unpack('I', payload[i:i+4])[0]
                if 1000 < uint_val < 1000000:  # Reasonable ID range
                    analysis['possible_ids'].append((i, uint_val))
            except:
                continue
        
        return analysis
    
    def calculate_entropy(self, data):
        """Calculate Shannon entropy untuk mendeteksi encrypted/compressed data"""
        if not data:
            return 0
        
        byte_counts = defaultdict(int)
        for byte in data:
            byte_counts[byte] += 1
        
        entropy = 0
        data_len = len(data)
        for count in byte_counts.values():
            p = count / data_len
            if p > 0:
                entropy -= p * (p).bit_length()
        
        return entropy
    
    def try_parse_player_position(self, payload):
        """Coba extract posisi player dari payload"""
        positions = []
        
        # Method 1: Look for 3 consecutive floats (x, y, z)
        for i in range(0, len(payload) - 12, 4):
            try:
                x = struct.unpack('f', payload[i:i+4])[0]
                y = struct.unpack('f', payload[i+4:i+8])[0]
                z = struct.unpack('f', payload[i+8:i+12])[0]
                
                # Validate coordinates (reasonable ranges for game world)
                if (-10000 < x < 10000 and -10000 < y < 10000 and -10000 < z < 10000):
                    positions.append({
                        'offset': i,
                        'x': round(x, 2),
                        'y': round(y, 2),
                        'z': round(z, 2)
                    })
            except:
                continue
        
        return positions
    
    def try_parse_player_name(self, payload):
        """Coba extract nama player dari payload"""
        names = []
        
        # Look for null-terminated strings
        try:
            decoded = payload.decode('utf-8', errors='ignore')
            
            # Split by null bytes and filter reasonable names
            parts = decoded.split('\x00')
            for part in parts:
                if (3 <= len(part) <= 20 and 
                    part.isprintable() and 
                    not part.isdigit() and
                    ' ' not in part):  # Player names usually don't have spaces
                    names.append(part)
        except:
            pass
        
        return names
    
    def parse_packet(self, packet):
        """Main packet parsing function"""
        try:
            # Basic packet info
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            src_port = int(packet.udp.srcport)
            dst_port = int(packet.udp.dstport)
            timestamp = datetime.now()
            
            # Extract payload
            payload = self.extract_raw_payload(packet)
            if not payload:
                return None
            
            # Analyze structure
            analysis = self.analyze_packet_structure(payload)
            
            # Try to parse specific data
            positions = self.try_parse_player_position(payload)
            names = self.try_parse_player_name(payload)
            
            # Create parsed packet object
            parsed_packet = {
                'timestamp': timestamp.isoformat(),
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'direction': 'incoming' if src_port == self.port else 'outgoing',
                'payload_length': len(payload),
                'payload_hex': payload.hex(),
                'analysis': analysis,
                'parsed_data': {
                    'positions': positions,
                    'names': names
                }
            }
            
            # Store for pattern analysis
            header_pattern = payload[:4].hex() if len(payload) >= 4 else payload.hex()
            self.unknown_patterns[header_pattern] += 1
            
            return parsed_packet
            
        except Exception as e:
            print(f"Error parsing packet: {e}")
            return None
    
    def start_capture_and_parse(self, duration=None):
        """Start capturing dan parsing packets"""
        print(f"🔬 ALBION PACKET PARSER")
        print(f"=" * 60)
        print(f"Interface: {self.interface}")
        print(f"Port: {self.port}")
        print(f"Time: {datetime.now().strftime('%H:%M:%S')}")
        print("-" * 60)
        
        try:
            # Use BPF filter for efficiency
            capture = pyshark.LiveCapture(
                interface=self.interface,
                bpf_filter=f"udp port {self.port}"
            )
            
            start_time = time.time()
            
            for packet in capture.sniff_continuously():
                self.packet_count += 1
                
                # Parse packet
                parsed = self.parse_packet(packet)
                if parsed:
                    self.display_parsed_packet(parsed)
                    
                    # Store interesting data
                    if parsed['parsed_data']['positions']:
                        self.parsed_data['positions'].extend(parsed['parsed_data']['positions'])
                    if parsed['parsed_data']['names']:
                        self.parsed_data['names'].extend(parsed['parsed_data']['names'])
                
                # Check duration limit
                if duration and (time.time() - start_time > duration):
                    print(f"\n⏱️ Duration limit reached ({duration}s)")
                    break
                
                # Stop after reasonable amount for analysis
                if self.packet_count >= 100:
                    print(f"\n📊 Stopping after {self.packet_count} packets for analysis")
                    break
            
            capture.close()
            self.print_analysis_summary()
            
        except KeyboardInterrupt:
            print(f"\n⏹️ Capture stopped by user")
            self.print_analysis_summary()
        except Exception as e:
            print(f"❌ Capture error: {e}")
    
    def display_parsed_packet(self, parsed):
        """Display parsed packet information"""
        direction_symbol = "⬅️" if parsed['direction'] == 'incoming' else "➡️"
        
        print(f"\n{direction_symbol} Packet #{self.packet_count}")
        print(f"   {parsed['src_ip']}:{parsed['src_port']} → {parsed['dst_ip']}:{parsed['dst_port']}")
        print(f"   Length: {parsed['payload_length']} bytes | Entropy: {parsed['analysis']['entropy']:.2f}")
        print(f"   Header: {parsed['analysis']['header']}")
        
        # Show interesting data
        if parsed['parsed_data']['positions']:
            print(f"   🎯 Positions found: {len(parsed['parsed_data']['positions'])}")
            for pos in parsed['parsed_data']['positions'][:3]:  # Show first 3
                print(f"      ({pos['x']}, {pos['y']}, {pos['z']}) at offset {pos['offset']}")
        
        if parsed['parsed_data']['names']:
            print(f"   👤 Names found: {parsed['parsed_data']['names']}")
        
        if parsed['analysis']['has_strings']:
            preview = parsed['analysis'].get('decoded_preview', '')[:50]
            print(f"   📝 String preview: {repr(preview)}")
        
        # Show hex preview
        hex_preview = parsed['payload_hex'][:32] + "..." if len(parsed['payload_hex']) > 32 else parsed['payload_hex']
        print(f"   🔢 Hex: {hex_preview}")
    
    def print_analysis_summary(self):
        """Print summary analysis"""
        print(f"\n" + "=" * 60)
        print(f"📊 ANALYSIS SUMMARY")
        print(f"=" * 60)
        print(f"Total packets analyzed: {self.packet_count}")
        
        # Pattern frequency
        print(f"\n📋 Most common packet headers:")
        for pattern, count in sorted(self.unknown_patterns.items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"   {pattern}: {count} packets")
        
        # Positions found
        unique_positions = set()
        for pos in self.parsed_data['positions']:
            unique_positions.add((pos['x'], pos['y'], pos['z']))
        
        if unique_positions:
            print(f"\n🎯 Unique positions found: {len(unique_positions)}")
            for pos in list(unique_positions)[:5]:  # Show first 5
                print(f"   ({pos[0]}, {pos[1]}, {pos[2]})")
        
        # Names found
        unique_names = set(self.parsed_data['names'])
        if unique_names:
            print(f"\n👤 Unique names found: {len(unique_names)}")
            for name in list(unique_names)[:10]:  # Show first 10
                print(f"   {name}")
        
        # Save analysis to file
        self.save_analysis_to_file()
    
    def save_analysis_to_file(self):
        """Save analysis results to JSON file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"albion_analysis_{timestamp}.json"
        
        analysis_data = {
            'timestamp': datetime.now().isoformat(),
            'total_packets': self.packet_count,
            'packet_patterns': dict(self.unknown_patterns),
            'parsed_data': {
                'positions': self.parsed_data['positions'],
                'names': self.parsed_data['names']
            }
        }
        
        try:
            with open(filename, 'w') as f:
                json.dump(analysis_data, f, indent=2)
            print(f"\n💾 Analysis saved to: {filename}")
        except Exception as e:
            print(f"❌ Error saving analysis: {e}")

def main():
    parser = AlbionPacketParser()
    
    print("🚀 Starting Albion Packet Parser...")
    print("📱 Make sure Albion Online is running and active!")
    print("⏹️  Press Ctrl+C to stop and see analysis\n")
    
    try:
        parser.start_capture_and_parse(duration=60)  # 60 seconds max
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()