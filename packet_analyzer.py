import json
import struct
import re
from collections import defaultdict, Counter
import matplotlib.pyplot as plt
import numpy as np
from datetime import datetime

class AlbionPacketAnalyzer:
    def __init__(self, analysis_file=None):
        self.analysis_file = analysis_file
        self.packets = []
        self.patterns = defaultdict(list)
        self.position_timeline = []
        self.movement_vectors = []
        
    def load_analysis_data(self, filename):
        """Load analysis data from JSON file"""
        try:
            with open(filename, 'r') as f:
                data = json.load(f)
            
            self.packets = data.get('packets', [])
            self.patterns = data.get('packet_patterns', {})
            
            print(f"✅ Loaded {len(self.packets)} packets from {filename}")
            return True
            
        except Exception as e:
            print(f"❌ Error loading analysis data: {e}")
            return False
    
    def analyze_packet_patterns(self):
        """Analyze patterns dalam packet headers dan payload"""
        print(f"\n🔍 PACKET PATTERN ANALYSIS")
        print("=" * 50)
        
        # Header patterns
        header_patterns = Counter()
        payload_sizes = []
        direction_counts = {'incoming': 0, 'outgoing': 0}
        
        for packet in self.packets:
            header = packet.get('analysis', {}).get('header', '')
            payload_length = packet.get('payload_length', 0)
            direction = packet.get('direction', 'unknown')
            
            header_patterns[header] += 1
            payload_sizes.append(payload_length)
            direction_counts[direction] += 1
        
        # Print header analysis
        print(f"📋 Most common headers:")
        for header, count in header_patterns.most_common(10):
            percentage = (count / len(self.packets)) * 100
            print(f"   {header}: {count} packets ({percentage:.1f}%)")
        
        # Payload size analysis
        print(f"\n📏 Payload size statistics:")
        print(f"   Min: {min(payload_sizes)} bytes")
        print(f"   Max: {max(payload_sizes)} bytes")
        print(f"   Average: {np.mean(payload_sizes):.1f} bytes")
        print(f"   Most common: {Counter(payload_sizes).most_common(1)[0]}")
        
        # Direction analysis
        print(f"\n📡 Traffic direction:")
        total = sum(direction_counts.values())
        for direction, count in direction_counts.items():
            percentage = (count / total) * 100 if total > 0 else 0
            print(f"   {direction}: {count} packets ({percentage:.1f}%)")
    
    def analyze_positions(self):
        """Analyze player positions and movement"""
        print(f"\n🎯 POSITION ANALYSIS")
        print("=" * 50)
        
        all_positions = []
        position_timeline = []
        
        for packet in self.packets:
            positions = packet.get('parsed_data', {}).get('positions', [])
            timestamp = packet.get('timestamp', '')
            
            for pos in positions:
                all_positions.append((pos['x'], pos['y'], pos['z']))
                position_timeline.append({
                    'timestamp': timestamp,
                    'x': pos['x'],
                    'y': pos['y'],
                    'z': pos['z'],
                    'direction': packet.get('direction', 'unknown')
                })
        
        if not all_positions:
            print("❌ No positions found in packets")
            return
        
        # Position statistics
        x_coords = [pos[0] for pos in all_positions]
        y_coords = [pos[1] for pos in all_positions]
        z_coords = [pos[2] for pos in all_positions]
        
        print(f"📊 Position statistics ({len(all_positions)} positions):")
        print(f"   X range: {min(x_coords):.2f} to {max(x_coords):.2f}")
        print(f"   Y range: {min(y_coords):.2f} to {max(y_coords):.2f}")
        print(f"   Z range: {min(z_coords):.2f} to {max(z_coords):.2f}")
        
        # Movement analysis
        if len(position_timeline) >= 2:
            movements = []
            for i in range(1, len(position_timeline)):
                prev = position_timeline[i-1]
                curr = position_timeline[i]
                
                distance = ((curr['x'] - prev['x'])**2 + 
                           (curr['y'] - prev['y'])**2 + 
                           (curr['z'] - prev['z'])**2)**0.5
                
                if distance > 0.1:  # Filter out noise
                    movements.append(distance)
            
            if movements:
                print(f"\n🏃 Movement analysis:")
                print(f"   Average movement: {np.mean(movements):.2f} units")
                print(f"   Max movement: {max(movements):.2f} units")
                print(f"   Total movements detected: {len(movements)}")
        
        # Save position data for visualization
        self.position_timeline = position_timeline
        return position_timeline
    
    def analyze_player_names(self):
        """Analyze player names found in packets"""
        print(f"\n👤 PLAYER NAME ANALYSIS")
        print("=" * 50)
        
        all_names = []
        name_patterns = defaultdict(int)
        
        for packet in self.packets:
            names = packet.get('parsed_data', {}).get('names', [])
            direction = packet.get('direction', 'unknown')
            
            for name in names:
                all_names.append(name)
                name_patterns[f"{name}_{direction}"] += 1
        
        if not all_names:
            print("❌ No player names found in packets")
            return
        
        unique_names = set(all_names)
        print(f"📋 Found {len(all_names)} name instances ({len(unique_names)} unique)")
        
        # Most common names
        name_counts = Counter(all_names)
        print(f"\n🏆 Most frequent names:")
        for name, count in name_counts.most_common(10):
            print(f"   {name}: {count} times")
        
        # Name length analysis
        name_lengths = [len(name) for name in unique_names]
        print(f"\n📏 Name length statistics:")
        print(f"   Average: {np.mean(name_lengths):.1f} characters")
        print(f"   Range: {min(name_lengths)} to {max(name_lengths)} characters")
        
        return unique_names
    
    def find_protocol_patterns(self):
        """Try to identify Albion protocol patterns"""
        print(f"\n🔬 PROTOCOL PATTERN ANALYSIS")
        print("=" * 50)
        
        # Group packets by header patterns
        header_groups = defaultdict(list)
        
        for packet in self.packets:
            header = packet.get('analysis', {}).get('header', '')
            payload_length = packet.get('payload_length', 0)
            direction = packet.get('direction', 'unknown')
            
            header_groups[header].append({
                'length': payload_length,
                'direction': direction,
                'packet': packet
            })
        
        # Analyze each header group
        for header, packets in header_groups.items():
            if len(packets) < 3:  # Skip rare headers
                continue
            
            lengths = [p['length'] for p in packets]
            directions = [p['direction'] for p in packets]
            
            print(f"\n📋 Header {header} ({len(packets)} packets):")
            print(f"   Length range: {min(lengths)} - {max(lengths)} bytes")
            print(f"   Most common length: {Counter(lengths).most_common(1)[0]}")
            print(f"   Direction: {Counter(directions).most_common(1)[0]}")
            
            # Check if this might be position updates
            position_count = sum(1 for p in packets if p['packet'].get('parsed_data', {}).get('positions'))
            if position_count > len(packets) * 0.5:
                print(f"   🎯 Likely position update packet (contains positions in {position_count}/{len(packets)} packets)")
            
            # Check if this might be chat/names
            name_count = sum(1 for p in packets if p['packet'].get('parsed_data', {}).get('names'))
            if name_count > 0:
                print(f"   👤 Contains player names in {name_count}/{len(packets)} packets")
    
    def create_visualizations(self):
        """Create visualizations untuk analysis results"""
        print(f"\n📊 CREATING VISUALIZATIONS")
        print("=" * 50)
        
        try:
            # Position heatmap
            if self.position_timeline:
                self.plot_position_heatmap()
                self.plot_movement_timeline()
            
            # Packet size distribution
            self.plot_packet_distribution()
            
            print(f"✅ Visualizations saved as PNG files")
            
        except Exception as e:
            print(f"❌ Error creating visualizations: {e}")
    
    def plot_position_heatmap(self):
        """Create heatmap of player positions"""
        if not self.position_timeline:
            return
        
        x_coords = [pos['x'] for pos in self.position_timeline]
        y_coords = [pos['y'] for pos in self.position_timeline]
        
        plt.figure(figsize=(10, 8))
        plt.hexbin(x_coords, y_coords, gridsize=30, cmap='YlOrRd')
        plt.colorbar(label='Position Frequency')
        plt.xlabel('X Coordinate')
        plt.ylabel('Y Coordinate')
        plt.title('Player Position Heatmap')
        plt.savefig('position_heatmap.png', dpi=300, bbox_inches='tight')
        plt.close()
    
    def plot_movement_timeline(self):
        """Plot position changes over time"""
        if len(self.position_timeline) < 2:
            return
        
        timestamps = range(len(self.position_timeline))
        x_coords = [pos['x'] for pos in self.position_timeline]
        y_coords = [pos['y'] for pos in self.position_timeline]
        
        plt.figure(figsize=(12, 6))
        plt.subplot(2, 1, 1)
        plt.plot(timestamps, x_coords, label='X coordinate', alpha=0.7)
        plt.ylabel('X Position')
        plt.legend()
        
        plt.subplot(2, 1, 2)
        plt.plot(timestamps, y_coords, label='Y coordinate', alpha=0.7, color='orange')
        plt.xlabel('Packet Sequence')
        plt.ylabel('Y Position')
        plt.legend()
        
        plt.suptitle('Player Movement Timeline')
        plt.savefig('movement_timeline.png', dpi=300, bbox_inches='tight')
        plt.close()
    
    def plot_packet_distribution(self):
        """Plot packet size and type distribution"""
        payload_sizes = []
        directions = []
        
        for packet in self.packets:
            payload_sizes.append(packet.get('payload_length', 0))
            directions.append(packet.get('direction', 'unknown'))
        
        plt.figure(figsize=(12, 5))
        
        # Packet size histogram
        plt.subplot(1, 2, 1)
        plt.hist(payload_sizes, bins=30, alpha=0.7, edgecolor='black')
        plt.xlabel('Payload Size (bytes)')
        plt.ylabel('Frequency')
        plt.title('Packet Size Distribution')
        
        # Direction pie chart
        plt.subplot(1, 2, 2)
        direction_counts = Counter(directions)
        plt.pie(direction_counts.values(), labels=direction_counts.keys(), autopct='%1.1f%%')
        plt.title('Traffic Direction Distribution')
        
        plt.tight_layout()
        plt.savefig('packet_distribution.png', dpi=300, bbox_inches='tight')
        plt.close()
    
    def generate_report(self):
        """Generate comprehensive analysis report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = f"albion_analysis_report_{timestamp}.txt"
        
        with open(report_filename, 'w') as f:
            f.write("ALBION ONLINE PACKET ANALYSIS REPORT\n")
            f.write("=" * 50 + "\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total packets analyzed: {len(self.packets)}\n\n")
            
            # Add analysis results
            # (Implementation would capture all the print output from analysis functions)
            
        print(f"📄 Report saved as: {report_filename}")

def main():
    analyzer = AlbionPacketAnalyzer()
    
    # You would run this after capturing packets with the parser
    print("🔍 ALBION PACKET ANALYZER")
    print("=" * 50)
    print("This tool analyzes captured packet data.")
    print("First run albion_packet_parser.py to capture data.\n")
    
    # Example usage:
    # analyzer.load_analysis_data("albion_analysis_20231201_143022.json")
    # analyzer.analyze_packet_patterns()
    # analyzer.analyze_positions()
    # analyzer.analyze_player_names()
    # analyzer.find_protocol_patterns()
    # analyzer.create_visualizations()
    # analyzer.generate_report()

if __name__ == "__main__":
    main()