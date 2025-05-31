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
                # Create new player 