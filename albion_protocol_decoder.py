import struct
import json
import time
from enum import Enum
from dataclasses import dataclass
from typing import Dict, List, Optional, Any

class PacketType(Enum):
    """Known Albion Online packet types"""
    MOVE = 1
    PLAYER_INFO = 2
    CHAT = 3
    ITEM_UPDATE = 4
    MOB_INFO = 5
    PLAYER_JOIN = 6
    PLAYER_LEAVE = 7
    EQUIPMENT_UPDATE = 8
    HEALTH_UPDATE = 9
    GUILD_INFO = 10
    UNKNOWN = 255

@dataclass
class AlbionPlayer:
    """Player data structure"""
    id: int
    name: str
    guild: str
    position: Dict[str, float]
    health: int
    max_health: int
    equipment: Dict[str, int]
    last_seen: float
    
@dataclass
class AlbionMob:
    """Mob/NPC data structure"""
    id: int
    type_id: int
    position: Dict[str, float]
    health: int
    max_health: int
    last_seen: float

class AlbionProtocolDecoder:
    def __init__(self):
        self.players = {}  # player_id -> AlbionPlayer
        self.mobs = {}     # mob_id -> AlbionMob
        self.items = {}    # item_id -> item_info
        
        # Protocol patterns learned from packet analysis
        self.packet_patterns = {
            # Header patterns for different packet types
            'movement': [b'\x01\x00', b'\x03\x00', b'\x15\x00'],
            'player_data': [b'\x02\x00', b'\x08\x00', b'\x0C\x00'],
            'chat': [b'\x04\x00', b'\x1A\x00'],
            'items': [b'\x06\x00', b'\x0E\x00'],
            'mobs': [b'\x07\x00', b'\x11\x00']
        }
        
        # Known item IDs (would be populated from game data files)
        self.item_database = self.load_item_database()
        
        # Equipment slots
        self.equipment_slots = {
            0: 'head',
            1: 'chest', 
            2: 'shoes',
            3: 'main_hand',
            4: 'off_hand',
            5: 'cape',
            6: 'mount',
            7: 'food',
            8: 'potion'
        }
    
    def load_item_database(self):
        """Load item database (normally from game files)"""
        # This would normally load from Albion's item database
        # For now, we'll use common item ID ranges
        return {
            'weapons': range(1000, 2000),
            'armor': range(2000, 3000),
            'accessories': range(3000, 4000),
            'consumables': range(4000, 5000),
            'materials': range(5000, 10000)
        }
    
    def identify_packet_type(self, payload: bytes) -> PacketType:
        """Identify packet type based on header and content"""
        if len(payload) < 4:
            return PacketType.UNKNOWN
        
        header = payload[:4]
        
        # Check against known patterns
        for packet_type, patterns in self.packet_patterns.items():
            if any(header.startswith(pattern) for pattern in patterns):
                if packet_type == 'movement':
                    return PacketType.MOVE
                elif packet_type == 'player_data':
                    return PacketType.PLAYER_INFO
                elif packet_type == 'chat':
                    return PacketType.CHAT
                elif packet_type == 'items':
                    return PacketType.ITEM_UPDATE
                elif packet_type == 'mobs':
                    return PacketType.MOB_INFO
        
        # Fallback to content-based detection
        return self.detect_packet_type_by_content(payload)
    
    def detect_packet_type_by_content(self, payload: bytes) -> PacketType:
        """Detect packet type by analyzing content"""
        # Movement packets usually contain 3 float values (x, y, z)
        if self.has_coordinate_pattern(payload):
            return PacketType.MOVE
        
        # Player info packets contain text strings
        if self.has_text_content(payload):
            if self.looks_like_chat(payload):
                return PacketType.CHAT
            else:
                return PacketType.PLAYER_INFO
        
        # Item packets have structured binary data
        if self.has_item_pattern(payload):
            return PacketType.ITEM_UPDATE
        
        return PacketType.UNKNOWN
    
    def has_coordinate_pattern(self, payload: bytes) -> bool:
        """Check if payload contains coordinate-like data"""
        if len(payload) < 12:
            return False
        
        # Look for 3 consecutive float values that could be coordinates
        for i in range(0, len(payload) - 12, 4):
            try:
                x = struct.unpack('<f', payload[i:i+4])[0]
                y = struct.unpack('<f', payload[i+4:i+8])[0]
                z = struct.unpack('<f', payload[i+8:i+12])[0]
                
                # Check if values are in reasonable ranges for game coordinates
                if (-5000 < x < 5000 and -5000 < y < 5000 and -1000 < z < 1000):
                    return True
            except struct.error:
                continue
        
        return False
    
    def has_text_content(self, payload: bytes) -> bool:
        """Check if payload contains readable text"""
        try:
            decoded = payload.decode('utf-8', errors='ignore')
            # Check if at least 20% of characters are printable ASCII
            printable_count = sum(1 for c in decoded if c.isprintable() and ord(c) < 128)
            return printable_count > len(decoded) * 0.2
        except:
            return False
    
    def looks_like_chat(self, payload: bytes) -> bool:
        """Check if text content looks like chat message"""
        try:
            decoded = payload.decode('utf-8', errors='ignore')
            # Chat messages often contain common words or punctuation
            chat_indicators = [':', '!', '?', 'hello', 'hi', 'lol', 'gg']
            return any(indicator in decoded.lower() for indicator in chat_indicators)
        except:
            return False
    
    def has_item_pattern(self, payload: bytes) -> bool:
        """Check if payload contains item-like data"""
        # Look for uint32 values in item ID ranges
        for i in range(0, len(payload) - 4, 4):
            try:
                value = struct.unpack('<I', payload[i:i+4])[0]
                # Check if value is in known item ID ranges
                for item_range in self.item_database.values():
                    if value in item_range:
                        return True
            except struct.error:
                continue
        return False
    
    def decode_movement_packet(self, payload: bytes) -> Optional[Dict]:
        """Decode movement/position packet"""
        if len(payload) < 16:
            return None
        
        try:
            # Try different offsets to find the position data
            for offset in range(0, min(len(payload) - 16, 20), 4):
                try:
                    # Try to extract: player_id (uint32) + position (3 floats)
                    player_id = struct.unpack('<I', payload[offset:offset+4])[0]
                    x = struct.unpack('<f', payload[offset+4:offset+8])[0]
                    y = struct.unpack('<f', payload[offset+8:offset+12])[0]
                    z = struct.unpack('<f', payload[offset+12:offset+16])[0]
                    
                    # Validate data
                    if (1000 <= player_id <= 999999999 and 
                        -5000 < x < 5000 and -5000 < y < 5000 and -1000 < z < 1000):
                        
                        return {
                            'type': 'movement',
                            'player_id': player_id,
                            'position': {'x': x, 'y': y, 'z': z},
                            'timestamp': time.time()
                        }
                except struct.error:
                    continue
        except Exception as e:
            pass
        
        return None
    
    def decode_player_info_packet(self, payload: bytes) -> Optional[Dict]:
        """Decode player information packet"""
        try:
            decoded = payload.decode('utf-8', errors='ignore')
            
            # Extract player name (usually first readable string)
            import re
            names = re.findall(r'[A-Za-z][A-Za-z0-9_]{2,19}', decoded)
            guilds = re.findall(r'\[([A-Z0-9]{2,8})\]', decoded)
            
            if names:
                # Try to extract player ID from binary data
                player_id = None
                for i in range(0, min(len(payload) - 4, 20), 4):
                    try:
                        candidate_id = struct.unpack('<I', payload[i:i+4])[0]
                        if 1000 <= candidate_id <= 999999999:
                            player_id = candidate_id
                            break
                    except struct.error:
                        continue
                
                return {
                    'type': 'player_info',
                    'player_id': player_id,
                    'name': names[0],
                    'guild': guilds[0] if guilds else None,
                    'timestamp': time.time()
                }
        except Exception as e:
            pass
        
        return None
    
    def decode_item_packet(self, payload: bytes) -> Optional[Dict]:
        """Decode item/equipment packet"""
        items = []
        
        # Look for item ID + quantity patterns
        for i in range(0, len(payload) - 8, 4):
            try:
                item_id = struct.unpack('<I', payload[i:i+4])[0]
                quantity = struct.unpack('<I', payload[i+4:i+8])[0]
                
                # Validate item data
                if (any(item_id in item_range for item_range in self.item_database.values()) and
                    0 < quantity <= 9999):
                    
                    items.append({
                        'item_id': item_id,
                        'quantity': quantity,
                        'offset': i
                    })
            except struct.error:
                continue
        
        if items:
            return {
                'type': 'items',
                'items': items,
                'timestamp': time.time()
            }
        
        return None
    
    def decode_packet(self, payload: bytes, direction: str) -> Optional[Dict]:
        """Main packet decoding function"""
        if not payload:
            return None
        
        packet_type = self.identify_packet_type(payload)
        
        if packet_type == PacketType.MOVE:
            return self.decode_movement_packet(payload)
        elif packet_type == PacketType.PLAYER_INFO:
            return self.decode_player_info_packet(payload)
        elif packet_type == PacketType.ITEM_UPDATE:
            return self.decode_item_packet(payload)
        elif packet_type == PacketType.CHAT:
            return self.decode_chat_packet(payload)
        
        return {
            'type': 'unknown',
            'packet_type_id': packet_type.value,
            'size': len(payload),
            'header': payload[:8].hex() if len(payload) >= 8 else payload.hex(),
            'timestamp': time.time()
        }
    
    def decode_chat_packet(self, payload: bytes) -> Optional[Dict]:
        """Decode chat message packet"""
        try:
            decoded = payload.decode('utf-8', errors='ignore')
            
            # Look for chat pattern: [sender]: message
            import re
            chat_match = re.search(r'([A-Za-z0-9_]{2,20}):\s*(.+)', decoded)
            
            if chat_match:
                sender = chat_match.group(1)
                message = chat_match.group(2).strip()
                
                return {
                    'type': 'chat',
                    'sender': sender,
                    'message': message,
                    'timestamp': time.time()
                }
        except Exception:
            pass
        
        return None
    
    def update_world_state(self, decoded_packet: Dict):
        """Update internal world state with decoded packet data"""
        if not decoded_packet:
            return
        
        packet_type = decoded_packet.get('type')
        timestamp = decoded_packet.get('timestamp', time.time())
        
        if packet_type == 'movement' and decoded_packet.get('player_id'):
            player_id = decoded_packet['player_id']
            position = decoded_packet['position']
            
            # Update or create player
            if player_id in self.players:
                self.players[player_id].position = position
                self.players[player_id].last_seen = timestamp
            else:
                self.players[player_id] = AlbionPlayer(
                    id=player_id,
                    name=f"Player_{player_id}",  # Will be updated when we get name data
                    guild="",
                    position=position,
                    health=100,  # Default values
                    max_health=100,
                    equipment={},
                    last_seen=timestamp
                )
        
        elif packet_type == 'player_info':
            player_id = decoded_packet.get('player_id')
            name = decoded_packet.get('name')
            guild = decoded_packet.get('guild')
            
            if player_id and name:
                if player_id in self.players:
                    self.players[player_id].name = name
                    if guild:
                        self.players[player_id].guild = guild
                    self.players[player_id].last_seen = timestamp
                else:
                    # Create new player with info
                    self.players[player_id] = AlbionPlayer(
                        id=player_id,
                        name=name,
                        guild=guild or "",
                        position={'x': 0, 'y': 0, 'z': 0},  # Will be updated
                        health=100,
                        max_health=100,
                        equipment={},
                        last_seen=timestamp
                    )
        
        elif packet_type == 'items':
            # Store item data for analysis
            for item in decoded_packet.get('items', []):
                item_id = item['item_id']
                self.items[item_id] = {
                    'last_seen': timestamp,
                    'quantity': item['quantity']
                }
    
    def get_nearby_players(self, center_pos: Dict[str, float], radius: float = 100) -> List[AlbionPlayer]:
        """Get players within radius of center position"""
        nearby = []
        
        for player in self.players.values():
            if not player.position:
                continue
            
            distance = ((player.position['x'] - center_pos['x'])**2 + 
                       (player.position['y'] - center_pos['y'])**2)**0.5
            
            if distance <= radius:
                nearby.append(player)
        
        return sorted(nearby, key=lambda p: p.last_seen, reverse=True)
    
    def get_world_state_summary(self) -> Dict:
        """Get summary of current world state"""
        current_time = time.time()
        
        # Filter recent players (seen in last 60 seconds)
        recent_players = [p for p in self.players.values() 
                         if current_time - p.last_seen < 60]
        
        # Calculate center of activity
        if recent_players:
            avg_x = sum(p.position['x'] for p in recent_players if p.position) / len(recent_players)
            avg_y = sum(p.position['y'] for p in recent_players if p.position) / len(recent_players)
            center = {'x': avg_x, 'y': avg_y}
        else:
            center = {'x': 0, 'y': 0}
        
        return {
            'timestamp': current_time,
            'total_players': len(self.players),
            'recent_players': len(recent_players),
            'center_of_activity': center,
            'players': [
                {
                    'id': p.id,
                    'name': p.name,
                    'guild': p.guild,
                    'position': p.position,
                    'last_seen': p.last_seen
                }
                for p in recent_players
            ]
        }
    
    def export_world_data(self, filename: str = None) -> str:
        """Export current world state to JSON file"""
        if not filename:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            filename = f"albion_world_state_{timestamp}.json"
        
        world_data = {
            'export_time': time.time(),
            'players': {
                str(pid): {
                    'id': p.id,
                    'name': p.name,
                    'guild': p.guild,
                    'position': p.position,
                    'health': p.health,
                    'max_health': p.max_health,
                    'equipment': p.equipment,
                    'last_seen': p.last_seen
                }
                for pid, p in self.players.items()
            },
            'mobs': {
                str(mid): {
                    'id': m.id,
                    'type_id': m.type_id,
                    'position': m.position,
                    'health': m.health,
                    'max_health': m.max_health,
                    'last_seen': m.last_seen
                }
                for mid, m in self.mobs.items()
            },
            'items': self.items
        }
        
        try:
            with open(filename, 'w') as f:
                json.dump(world_data, f, indent=2)
            return filename
        except Exception as e:
            print(f"Error exporting world data: {e}")
            return None

# Enhanced live scanner with protocol decoder
class AdvancedAlbionScanner:
    def __init__(self, interface='5', port=5056):
        self.interface = interface
        self.port = port
        self.decoder = AlbionProtocolDecoder()
        self.running = False
        
        # Statistics
        self.stats = {
            'total_packets': 0,
            'decoded_packets': 0,
            'movement_packets': 0,
            'player_info_packets': 0,
            'item_packets': 0,
            'chat_packets': 0,
            'unknown_packets': 0
        }
        
        # Configuration
        self.config = {
            'display_world_state': True,
            'world_state_interval': 10,  # seconds
            'auto_export_interval': 300,  # 5 minutes
            'max_display_players': 10
        }
    
    def process_packet(self, packet):
        """Process packet using protocol decoder"""
        try:
            # Extract payload - try different methods
            payload = None
            
            # Method 1: Try to get raw packet data
            try:
                raw_packet = packet.get_raw_packet()
                if raw_packet:
                    ip_header_length = (raw_packet[14] & 0x0F) * 4
                    udp_start = 14 + ip_header_length
                    payload = raw_packet[udp_start + 8:]
            except Exception:
                pass
            
            # Method 2: Try to access UDP data layer directly
            if not payload:
                try:
                    if hasattr(packet, 'udp') and hasattr(packet.udp, 'payload'):
                        payload = bytes.fromhex(packet.udp.payload.replace(':', ''))
                except Exception:
                    pass
            
            # Method 3: Try alternative data access
            if not payload:
                try:
                    # Get data from DATA layer if available
                    if hasattr(packet, 'data'):
                        payload = bytes.fromhex(packet.data.data.replace(':', ''))
                except Exception:
                    pass
            
            # If we still don't have payload, skip detailed analysis but track basic info
            if not payload:
                # Still track basic packet info
                src_port = int(packet.udp.srcport)
                dst_port = int(packet.udp.dstport)
                length = int(packet.length)
                timestamp = time.strftime("%H:%M:%S")
                direction = "incoming" if src_port == self.port else "outgoing"
                
                # Update basic statistics
                self.stats['total_packets'] += 1
                
                # Basic classification by size
                if 60 <= length <= 80:
                    self.stats['movement_packets'] += 1
                    packet_type = "movement (estimated)"
                elif 100 <= length <= 200:
                    self.stats['player_info_packets'] += 1
                    packet_type = "player_info (estimated)"
                else:
                    self.stats['unknown_packets'] += 1
                    packet_type = "unknown"
                
                print(f"[{timestamp}] Basic packet | {packet_type} | {length} bytes | {direction}")
                return None
            
            # Determine direction
            src_port = int(packet.udp.srcport)
            direction = 'incoming' if src_port == self.port else 'outgoing'
            
            # Decode packet
            decoded = self.decoder.decode_packet(payload, direction)
            
            # Update statistics
            self.stats['total_packets'] += 1
            
            if decoded:
                self.stats['decoded_packets'] += 1
                packet_type = decoded.get('type', 'unknown')
                
                if packet_type == 'movement':
                    self.stats['movement_packets'] += 1
                elif packet_type == 'player_info':
                    self.stats['player_info_packets'] += 1
                elif packet_type == 'items':
                    self.stats['item_packets'] += 1
                elif packet_type == 'chat':
                    self.stats['chat_packets'] += 1
                else:
                    self.stats['unknown_packets'] += 1
                
                # Update world state
                self.decoder.update_world_state(decoded)
                
                # Display packet info
                self.display_decoded_packet(decoded, direction)
            
            return decoded
            
        except Exception as e:
            print(f"Error processing packet: {e}")
            return None
    
    def display_decoded_packet(self, decoded: Dict, direction: str):
        """Display decoded packet information"""
        timestamp = time.strftime("%H:%M:%S")
        direction_symbol = "⬅️" if direction == 'incoming' else "➡️"
        packet_type = decoded.get('type', 'unknown')
        
        print(f"[{timestamp}] {direction_symbol} {packet_type.upper():<12}", end="")
        
        if packet_type == 'movement':
            pos = decoded['position']
            player_id = decoded.get('player_id', 'Unknown')
            print(f" | Player {player_id} → ({pos['x']:.2f}, {pos['y']:.2f}, {pos['z']:.2f})")
        
        elif packet_type == 'player_info':
            name = decoded.get('name', 'Unknown')
            guild = decoded.get('guild', '')
            player_id = decoded.get('player_id', 'Unknown')
            guild_str = f"[{guild}]" if guild else ""
            print(f" | {name} {guild_str} (ID: {player_id})")
        
        elif packet_type == 'chat':
            sender = decoded.get('sender', 'Unknown')
            message = decoded.get('message', '')[:50]  # Truncate long messages
            print(f" | {sender}: {message}")
        
        elif packet_type == 'items':
            items = decoded.get('items', [])
            print(f" | {len(items)} items")
        
        else:
            size = decoded.get('size', 0)
            print(f" | {size} bytes")
    
    def display_world_state(self):
        """Display current world state summary"""
        world_state = self.decoder.get_world_state_summary()
        
        print(f"\n🌍 WORLD STATE SUMMARY")
        print("-" * 50)
        print(f"Total players discovered: {world_state['total_players']}")
        print(f"Recent players (60s): {world_state['recent_players']}")
        
        if world_state['center_of_activity']:
            center = world_state['center_of_activity']
            print(f"Center of activity: ({center['x']:.2f}, {center['y']:.2f})")
        
        # Display recent players
        recent_players = world_state['players'][:self.config['max_display_players']]
        
        if recent_players:
            print(f"\n👥 RECENT PLAYERS:")
            for player in recent_players:
                name = player['name']
                guild = f"[{player['guild']}]" if player['guild'] else ""
                pos = player['position']
                last_seen = time.time() - player['last_seen']
                
                print(f"  {name} {guild}")
                print(f"    Position: ({pos['x']:.2f}, {pos['y']:.2f}, {pos['z']:.2f})")
                print(f"    Last seen: {last_seen:.1f}s ago")
        
        print("-" * 50)
    
    def display_statistics(self):
        """Display scanning statistics"""
        print(f"\n📊 SCANNING STATISTICS")
        print("-" * 30)
        
        total = self.stats['total_packets']
        decoded = self.stats['decoded_packets']
        success_rate = (decoded / total * 100) if total > 0 else 0
        
        print(f"Total packets: {total}")
        print(f"Decoded packets: {decoded} ({success_rate:.1f}%)")
        print(f"Movement: {self.stats['movement_packets']}")
        print(f"Player info: {self.stats['player_info_packets']}")
        print(f"Items: {self.stats['item_packets']}")
        print(f"Chat: {self.stats['chat_packets']}")
        print(f"Unknown: {self.stats['unknown_packets']}")
    
    def start_scanning(self):
        """Start advanced scanning with protocol decoding"""
        print(f"🚀 ADVANCED ALBION SCANNER")
        print("=" * 60)
        print(f"Interface: {self.interface}")
        print(f"Port: {self.port}")
        print(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("-" * 60)
        print("🔬 Protocol decoder enabled")
        print("📱 Make sure Albion Online is running and active!")
        print("⏹️  Press Ctrl+C to stop")
        print()
        
        self.running = True
        last_world_display = 0
        last_export = 0
        
        try:
            import pyshark
            
            # Configure capture with raw data enabled
            capture = pyshark.LiveCapture(
                interface=self.interface,
                bpf_filter=f"udp port {self.port}",
                use_json=True,      # Enable JSON output
                include_raw=True    # Include raw packet data
            )
            
            print("✅ Capture configured with raw data support")
            
            for packet in capture.sniff_continuously():
                if not self.running:
                    break
                
                self.process_packet(packet)
                
                current_time = time.time()
                
                # Display world state periodically
                if (self.config['display_world_state'] and 
                    current_time - last_world_display > self.config['world_state_interval']):
                    self.display_world_state()
                    last_world_display = current_time
                
                # Auto-export world data
                if (self.config['auto_export_interval'] > 0 and
                    current_time - last_export > self.config['auto_export_interval']):
                    filename = self.decoder.export_world_data()
                    if filename:
                        print(f"💾 World data exported to: {filename}")
                    last_export = current_time
            
            capture.close()
            
        except KeyboardInterrupt:
            print(f"\n⏹️ Scanning stopped by user")
        except Exception as e:
            print(f"❌ Scanning error: {e}")
            print("🔧 Trying fallback method...")
            
            # Fallback method - simpler capture
            try:
                self.start_fallback_scanning()
            except Exception as fallback_error:
                print(f"❌ Fallback also failed: {fallback_error}")
                
        finally:
            self.running = False
            self.display_statistics()
            self.display_world_state()
            
            # Final export
            filename = self.decoder.export_world_data()
            if filename:
                print(f"💾 Final world data exported to: {filename}")
    
    def start_fallback_scanning(self):
        """Fallback scanning method without advanced features"""
        print("\n🔄 Starting fallback scanning method...")
        
        import pyshark
        
        # Simple capture without use_json/include_raw
        capture = pyshark.LiveCapture(
            interface=self.interface,
            bpf_filter=f"udp port {self.port}"
        )
        
        packet_count = 0
        
        for packet in capture.sniff_continuously():
            if not self.running:
                break
                
            packet_count += 1
            
            try:
                # Basic packet info without raw data
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                src_port = int(packet.udp.srcport)
                dst_port = int(packet.udp.dstport)
                length = int(packet.length)
                timestamp = time.strftime("%H:%M:%S")
                
                # Determine direction
                direction = "incoming" if src_port == self.port else "outgoing"
                direction_symbol = "⬅️" if direction == "incoming" else "➡️"
                
                print(f"[{timestamp}] {direction_symbol} Packet #{packet_count} | {src_ip}:{src_port} -> {dst_ip}:{dst_port} | {length} bytes")
                
                # Update basic statistics
                self.stats['total_packets'] += 1
                
                # Simple pattern detection based on packet size
                if 60 <= length <= 80:
                    self.stats['movement_packets'] += 1
                    print(f"  -> Likely movement packet")
                elif 100 <= length <= 200:
                    self.stats['player_info_packets'] += 1  
                    print(f"  -> Likely player info packet")
                elif length > 200:
                    print(f"  -> Large packet (possible bulk data)")
                
                # Safety limit for demo
                if packet_count >= 50:
                    print(f"\n📊 Captured {packet_count} packets in fallback mode")
                    break
                    
            except Exception as e:
                print(f"Error processing fallback packet: {e}")
                continue
        
        capture.close()
        print("✅ Fallback scanning completed")
def main():
    scanner = AdvancedAlbionScanner(
        interface='5',  # USB Tethering
        port=5056       # Albion port
    )
    
    # Configure scanner
    scanner.config['display_world_state'] = True
    scanner.config['world_state_interval'] = 15  # Display every 15 seconds
    scanner.config['auto_export_interval'] = 300  # Export every 5 minutes
    
    try:
        scanner.start_scanning()
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()