from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import json
import time
import threading
from datetime import datetime
from collections import deque, defaultdict
import os

# Import our scanner classes
try:
    from albion_protocol_decoder import AdvancedAlbionScanner, AlbionProtocolDecoder
except ImportError:
    print("Warning: Scanner modules not found. Running in demo mode.")
    AdvancedAlbionScanner = None
    AlbionProtocolDecoder = None

app = Flask(__name__)
app.config['SECRET_KEY'] = 'albion_scanner_secret_key'
socketio = SocketIO(app, cors_allowed_origins="*")

class DashboardServer:
    def __init__(self):
        self.scanner = None
        self.scanner_thread = None
        self.is_scanning = False
        
        # Data storage
        self.players = {}
        self.chat_messages = deque(maxlen=100)
        self.packet_stats = {
            'total': 0,
            'movement': 0,
            'player_info': 0,
            'chat': 0,
            'items': 0,
            'unknown': 0
        }
        self.packets_per_second = 0
        self.packet_buffer = deque(maxlen=50)
        
        # Performance tracking
        self.last_update = time.time()
        self.update_lock = threading.Lock()
        
        # Start background tasks
        self.start_background_tasks()
    
    def start_background_tasks(self):
        """Start background tasks for data processing"""
        def stats_updater():
            while True:
                time.sleep(1)
                with self.update_lock:
                    # Calculate packets per second
                    current_time = time.time()
                    recent_packets = [p for p in self.packet_buffer 
                                    if current_time - p['timestamp'] <= 1.0]
                    self.packets_per_second = len(recent_packets)
                    
                    # Emit updates to connected clients
                    self.emit_statistics_update()
                    self.emit_player_update()
        
        stats_thread = threading.Thread(target=stats_updater, daemon=True)
        stats_thread.start()
    
    def process_scanner_packet(self, decoded_packet):
        """Process packet from scanner and update dashboard data"""
        if not decoded_packet:
            return
        
        with self.update_lock:
            # Update packet statistics
            self.packet_stats['total'] += 1
            packet_type = decoded_packet.get('type', 'unknown')
            if packet_type in self.packet_stats:
                self.packet_stats[packet_type] += 1
            
            # Add to packet buffer for rate calculation
            self.packet_buffer.append({
                'timestamp': time.time(),
                'type': packet_type
            })
            
            # Process specific packet types
            if packet_type == 'movement':
                self.process_movement_packet(decoded_packet)
            elif packet_type == 'player_info':
                self.process_player_info_packet(decoded_packet)
            elif packet_type == 'chat':
                self.process_chat_packet(decoded_packet)
            
            # Emit packet update to clients
            socketio.emit('packet_update', {
                'type': packet_type,
                'data': decoded_packet,
                'timestamp': time.time()
            })
    
    def process_movement_packet(self, packet):
        """Process movement packet"""
        player_id = packet.get('player_id')
        position = packet.get('position')
        
        if player_id and position:
            current_time = time.time()
            
            if player_id not in self.players:
                self.players[player_id] = {
                    'id': player_id,
                    'name': f'Player_{player_id}',
                    'guild': '',
                    'position': position,
                    'last_seen': current_time,
                    'movement_history': deque(maxlen=10)
                }
            else:
                player = self.players[player_id]
                # Calculate movement speed
                if player['position']:
                    old_pos = player['position']
                    distance = ((position['x'] - old_pos['x'])**2 + 
                              (position['y'] - old_pos['y'])**2)**0.5
                    time_diff = current_time - player['last_seen']
                    speed = distance / time_diff if time_diff > 0 else 0
                    
                    player['movement_history'].append({
                        'position': position.copy(),
                        'timestamp': current_time,
                        'speed': speed
                    })
                
                player['position'] = position
                player['last_seen'] = current_time
    
    def process_player_info_packet(self, packet):
        """Process player info packet"""
        player_id = packet.get('player_id')
        name = packet.get('name')
        guild = packet.get('guild')
        
        if player_id and name:
            current_time = time.time()
            
            if player_id not in self.players:
                self.players[player_id] = {
                    'id': player_id,
                    'name': name,
                    'guild': guild or '',
                    'position': {'x': 0, 'y': 0, 'z': 0},
                    'last_seen': current_time,
                    'movement_history': deque(maxlen=10)
                }
            else:
                player = self.players[player_id]
                player['name'] = name
                if guild:
                    player['guild'] = guild
                player['last_seen'] = current_time
    
    def process_chat_packet(self, packet):
        """Process chat packet"""
        sender = packet.get('sender')
        message = packet.get('message')
        
        if sender and message:
            chat_entry = {
                'sender': sender,
                'message': message,
                'timestamp': time.time()
            }
            self.chat_messages.append(chat_entry)
            
            # Emit chat update to clients
            socketio.emit('chat_update', chat_entry)
    
    def emit_statistics_update(self):
        """Emit statistics update to all clients"""
        active_players = self.get_active_players_count()
        
        socketio.emit('stats_update', {
            'total_packets': self.packet_stats['total'],
            'packets_per_second': self.packets_per_second,
            'players_detected': len(self.players),
            'active_players': active_players,
            'packet_breakdown': self.packet_stats.copy()
        })
    
    def emit_player_update(self):
        """Emit player data update to all clients"""
        active_players = self.get_active_players(limit=20)
        
        socketio.emit('player_update', {
            'players': active_players,
            'timestamp': time.time()
        })
    
    def get_active_players_count(self):
        """Get count of players seen in last 60 seconds"""
        current_time = time.time()
        return sum(1 for player in self.players.values() 
                  if current_time - player['last_seen'] < 60)
    
    def get_active_players(self, limit=None):
        """Get list of active players"""
        current_time = time.time()
        active = [
            {
                'id': p['id'],
                'name': p['name'],
                'guild': p['guild'],
                'position': p['position'],
                'last_seen': p['last_seen'],
                'time_since_seen': current_time - p['last_seen']
            }
            for p in self.players.values()
            if current_time - p['last_seen'] < 300  # 5 minutes
        ]
        
        # Sort by last seen (most recent first)
        active.sort(key=lambda x: x['last_seen'], reverse=True)
        
        if limit:
            active = active[:limit]
        
        return active
    
    def start_scanner(self, interface='5', port=5056):
        """Start the packet scanner"""
        if self.is_scanning:
            return False, "Scanner is already running"
        
        if not AdvancedAlbionScanner:
            return False, "Scanner module not available"
        
        try:
            self.scanner = AdvancedAlbionScanner(interface, port)
            
            # Override the scanner's packet processing to feed our dashboard
            original_process = self.scanner.process_packet
            
            def dashboard_process_packet(packet):
                # Call original processing
                decoded = original_process(packet)
                # Feed to dashboard
                self.process_scanner_packet(decoded)
                return decoded
            
            self.scanner.process_packet = dashboard_process_packet
            
            # Start scanner in separate thread
            self.scanner_thread = threading.Thread(
                target=self.scanner.start_scanning,
                daemon=True
            )
            self.scanner_thread.start()
            
            self.is_scanning = True
            return True, "Scanner started successfully"
            
        except Exception as e:
            return False, f"Failed to start scanner: {str(e)}"
    
    def stop_scanner(self):
        """Stop the packet scanner"""
        if not self.is_scanning:
            return False, "Scanner is not running"
        
        try:
            if self.scanner:
                self.scanner.running = False
            
            self.is_scanning = False
            return True, "Scanner stopped successfully"
            
        except Exception as e:
            return False, f"Failed to stop scanner: {str(e)}"
    
    def export_data(self):
        """Export current data to JSON"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        export_data = {
            'export_timestamp': time.time(),
            'export_time_readable': datetime.now().isoformat(),
            'statistics': self.packet_stats.copy(),
            'players': {
                str(pid): {
                    'id': p['id'],
                    'name': p['name'],
                    'guild': p['guild'],
                    'position': p['position'],
                    'last_seen': p['last_seen']
                }
                for pid, p in self.players.items()
            },
            'chat_messages': list(self.chat_messages),
            'active_player_count': self.get_active_players_count()
        }
        
        filename = f'albion_dashboard_export_{timestamp}.json'
        
        try:
            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2)
            return True, filename
        except Exception as e:
            return False, str(e)

# Global dashboard instance
dashboard = DashboardServer()

# Flask routes
@app.route('/')
def index():
    """Serve the dashboard HTML"""
    # In a real deployment, you'd use render_template
    # For now, serve the HTML file directly
    try:
        with open('albion_web_dashboard.html', 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        return """
        <h1>Dashboard HTML not found</h1>
        <p>Please make sure albion_web_dashboard.html is in the same directory as this script.</p>
        """

@app.route('/api/status')
def get_status():
    """Get current scanner status"""
    return jsonify({
        'scanning': dashboard.is_scanning,
        'players_detected': len(dashboard.players),
        'active_players': dashboard.get_active_players_count(),
        'total_packets': dashboard.packet_stats['total'],
        'packets_per_second': dashboard.packets_per_second
    })

@app.route('/api/players')
def get_players():
    """Get active players list"""
    players = dashboard.get_active_players(limit=50)
    return jsonify({
        'players': players,
        'count': len(players)
    })

@app.route('/api/chat')
def get_chat():
    """Get recent chat messages"""
    messages = list(dashboard.chat_messages)[-20:]  # Last 20 messages
    return jsonify({
        'messages': messages,
        'count': len(messages)
    })

@app.route('/api/statistics')
def get_statistics():
    """Get packet statistics"""
    return jsonify({
        'packet_stats': dashboard.packet_stats,
        'packets_per_second': dashboard.packets_per_second,
        'players_detected': len(dashboard.players),
        'active_players': dashboard.get_active_players_count()
    })

# SocketIO events
@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    print(f"Client connected: {request.sid}")
    
    # Send initial data to newly connected client
    emit('stats_update', {
        'total_packets': dashboard.packet_stats['total'],
        'packets_per_second': dashboard.packets_per_second,
        'players_detected': len(dashboard.players),
        'active_players': dashboard.get_active_players_count(),
        'packet_breakdown': dashboard.packet_stats.copy()
    })
    
    emit('player_update', {
        'players': dashboard.get_active_players(limit=20),
        'timestamp': time.time()
    })

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    print(f"Client disconnected: {request.sid}")

@socketio.on('start_scanner')
def handle_start_scanner(data):
    """Handle start scanner request"""
    interface = data.get('interface', '5')
    port = data.get('port', 5056)
    
    success, message = dashboard.start_scanner(interface, port)
    
    emit('scanner_response', {
        'action': 'start',
        'success': success,
        'message': message
    })

@socketio.on('stop_scanner')
def handle_stop_scanner():
    """Handle stop scanner request"""
    success, message = dashboard.stop_scanner()
    
    emit('scanner_response', {
        'action': 'stop',
        'success': success,
        'message': message
    })

@socketio.on('export_data')
def handle_export_data():
    """Handle data export request"""
    success, result = dashboard.export_data()
    
    emit('export_response', {
        'success': success,
        'filename': result if success else None,
        'error': result if not success else None
    })

@socketio.on('clear_data')
def handle_clear_data():
    """Handle clear data request"""
    with dashboard.update_lock:
        dashboard.players.clear()
        dashboard.chat_messages.clear()
        dashboard.packet_stats = {
            'total': 0,
            'movement': 0,
            'player_info': 0,
            'chat': 0,
            'items': 0,
            'unknown': 0
        }
        dashboard.packet_buffer.clear()
    
    emit('data_cleared', {'success': True})
    
    # Broadcast update to all clients
    socketio.emit('stats_update', {
        'total_packets': 0,
        'packets_per_second': 0,
        'players_detected': 0,
        'active_players': 0,
        'packet_breakdown': dashboard.packet_stats.copy()
    })

if __name__ == '__main__':
    print("🚀 Starting Albion Scanner Dashboard Server")
    print("=" * 50)
    print(f"Dashboard URL: http://localhost:5000")
    print(f"API Base URL: http://localhost:5000/api/")
    print("-" * 50)
    print("Available endpoints:")
    print("  GET  /              - Dashboard web interface")
    print("  GET  /api/status    - Scanner status")
    print("  GET  /api/players   - Active players list")
    print("  GET  /api/chat      - Recent chat messages")
    print("  GET  /api/statistics - Packet statistics")
    print("-" * 50)
    print("SocketIO events:")
    print("  start_scanner - Start packet scanning")
    print("  stop_scanner  - Stop packet scanning")
    print("  export_data   - Export current data")
    print("  clear_data    - Clear all data")
    print("=" * 50)
    
    # Install required packages if not available
    try:
        import flask_socketio
    except ImportError:
        print("Installing required packages...")
        import subprocess
        subprocess.check_call(['pip', 'install', 'flask', 'flask-socketio'])
    
    try:
        socketio.run(app, debug=True, host='0.0.0.0', port=5000)
    except KeyboardInterrupt:
        print("\n⏹️ Server stopped by user")
    except Exception as e:
        print(f"❌ Server error: {e}")