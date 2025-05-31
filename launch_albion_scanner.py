#!/usr/bin/env python3
"""
Albion Online Scanner - Complete Package Launcher
Menggabungkan packet capture, protocol decoding, dan web dashboard
"""

import sys
import os
import subprocess
import time
import threading
import webbrowser
from pathlib import Path

def check_requirements():
    """Check if all required packages are installed"""
    required_packages = [
        'pyshark',
        'flask',
        'flask-socketio',
        'psutil'
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package.replace('-', '_'))
        except ImportError:
            missing_packages.append(package)
    
    return missing_packages

def install_packages(packages):
    """Install missing packages"""
    print(f"📦 Installing missing packages: {', '.join(packages)}")
    
    for package in packages:
        try:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])
            print(f"✅ {package} installed successfully")
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to install {package}: {e}")
            return False
    
    return True

def check_wireshark_installation():
    """Check if Wireshark/TShark is properly installed"""
    tshark_paths = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe"
    ]
    
    for path in tshark_paths:
        if os.path.exists(path):
            print(f"✅ TShark found at: {path}")
            return True, path
    
    # Try finding in PATH
    try:
        result = subprocess.run(['where', 'tshark'], capture_output=True, text=True, shell=True)
        if result.returncode == 0:
            path = result.stdout.strip().split('\n')[0]
            print(f"✅ TShark found in PATH: {path}")
            return True, path
    except:
        pass
    
    return False, None

def check_npcap_installation():
    """Check if Npcap is installed"""
    npcap_paths = [
        r"C:\Windows\System32\Npcap",
        r"C:\Windows\SysWOW64\Npcap"
    ]
    
    for path in npcap_paths:
        if os.path.exists(path):
            print(f"✅ Npcap found at: {path}")
            return True
    
    return False

def print_banner():
    """Print application banner"""
    print("🏰" + "=" * 60 + "🏰")
    print("🗡️            ALBION ONLINE SCANNER SUITE           ⚔️")
    print("🏰" + "=" * 60 + "🏰")
    print("📡 Real-time packet capture and analysis")
    print("🔬 Protocol decoding and player tracking")
    print("🌐 Web dashboard with live visualization")
    print("💾 Data export and analysis tools")
    print("🏰" + "=" * 60 + "🏰")

def show_menu():
    """Show main menu options"""
    print("\n📋 AVAILABLE OPTIONS:")
    print("-" * 30)
    print("1. 🔍 Run System Diagnostics")
    print("2. 🧪 Test Packet Capture")
    print("3. 📊 Simple Traffic Monitor")
    print("4. 🔬 Advanced Protocol Scanner")
    print("5. 🌐 Launch Web Dashboard")
    print("6. 📈 Analyze Existing Data")
    print("7. ⚙️  Configuration & Setup")
    print("8. 📖 View Documentation")
    print("9. ❌ Exit")
    print("-" * 30)

def run_diagnostics():
    """Run system diagnostics"""
    print("\n🔍 RUNNING SYSTEM DIAGNOSTICS")
    print("=" * 50)
    
    # Check Python version
    python_version = sys.version_info
    print(f"🐍 Python Version: {python_version.major}.{python_version.minor}.{python_version.micro}")
    
    if python_version < (3, 7):
        print("⚠️ Warning: Python 3.7+ recommended")
    else:
        print("✅ Python version is compatible")
    
    # Check packages
    print("\n📦 Checking Python packages...")
    missing = check_requirements()
    if missing:
        print(f"❌ Missing packages: {', '.join(missing)}")
        install = input("\n📥 Install missing packages? (y/n): ").lower().strip()
        if install == 'y':
            if install_packages(missing):
                print("✅ All packages installed successfully")
            else:
                print("❌ Some packages failed to install")
                return False
    else:
        print("✅ All required packages are installed")
    
    # Check Wireshark
    print("\n🦈 Checking Wireshark installation...")
    wireshark_ok, tshark_path = check_wireshark_installation()
    if not wireshark_ok:
        print("❌ Wireshark/TShark not found")
        print("💡 Please install Wireshark from: https://www.wireshark.org/")
        return False
    
    # Check Npcap
    print("\n📡 Checking Npcap installation...")
    if not check_npcap_installation():
        print("❌ Npcap not found")
        print("💡 Please install Npcap from: https://npcap.com/")
        return False
    
    print("\n🎉 DIAGNOSTICS COMPLETED - System Ready!")
    return True

def test_packet_capture():
    """Test basic packet capture functionality"""
    print("\n🧪 TESTING PACKET CAPTURE")
    print("=" * 40)
    
    # Check if test script exists
    if not os.path.exists('test.py'):
        print("❌ test.py not found")
        print("💡 Make sure test.py is in the current directory")
        return
    
    print("🔄 Running packet capture test...")
    print("📱 Make sure Albion Online is running!")
    print("⏹️  Test will run for 30 seconds")
    
    countdown = 5
    for i in range(countdown, 0, -1):
        print(f"Starting in {i}...", end="\r")
        time.sleep(1)
    print("🚀 Starting capture...     ")
    
    try:
        # Run test script with timeout
        result = subprocess.run([sys.executable, 'test.py'], timeout=30, capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✅ Packet capture test completed successfully!")
            print("\nOutput preview:")
            print("-" * 30)
            # Show last few lines of output
            output_lines = result.stdout.strip().split('\n')
            for line in output_lines[-10:]:  # Last 10 lines
                print(line)
        else:
            print("❌ Packet capture test failed!")
            print(f"Error: {result.stderr}")
            
    except subprocess.TimeoutExpired:
        print("⏱️ Test completed (30 second timeout)")
        print("💡 If no packets were captured, ensure Albion is active")
    except Exception as e:
        print(f"❌ Test failed: {e}")

def launch_advanced_scanner():
    """Launch the advanced protocol scanner"""
    print("\n🔬 LAUNCHING ADVANCED SCANNER")
    print("=" * 40)
    
    # Check if scanner file exists
    if not os.path.exists('albion_protocol_decoder.py'):
        print("❌ albion_protocol_decoder.py not found")
        print("💡 Make sure all scanner files are in the current directory")
        return
    
    print("🚀 Starting advanced scanner...")
    print("📱 Make sure Albion Online is running!")
    print("⏹️  Press Ctrl+C to stop")
    print()
    
    try:
        subprocess.run([sys.executable, 'albion_protocol_decoder.py'])
    except KeyboardInterrupt:
        print("\n⏹️ Scanner stopped by user")
    except Exception as e:
        print(f"❌ Scanner failed: {e}")

def launch_simple_monitor():
    """Launch the simple traffic monitor"""
    print("\n📊 LAUNCHING SIMPLE TRAFFIC MONITOR")
    print("=" * 50)
    
    # Check if monitor file exists
    if not os.path.exists('simple_albion_monitor.py'):
        print("❌ simple_albion_monitor.py not found")
        print("💡 Make sure the monitor file is in the current directory")
        return
    
    print("🚀 Starting simple traffic monitor...")
    print("📱 Make sure Albion Online is running!")
    print("📊 This will show basic packet flow and statistics")
    print("⏹️  Press Ctrl+C to stop")
    print()
    
    try:
        subprocess.run([sys.executable, 'simple_albion_monitor.py'])
    except KeyboardInterrupt:
        print("\n⏹️ Monitor stopped by user")
    except Exception as e:
        print(f"❌ Monitor failed: {e}")
    """Launch the advanced protocol scanner"""
    print("\n🔬 LAUNCHING ADVANCED SCANNER")
    print("=" * 40)
    
    # Check if scanner file exists
    if not os.path.exists('albion_protocol_decoder.py'):
        print("❌ albion_protocol_decoder.py not found")
        print("💡 Make sure all scanner files are in the current directory")
        return
    
    print("🚀 Starting advanced scanner...")
    print("📱 Make sure Albion Online is running!")
    print("⏹️  Press Ctrl+C to stop")
    print()
    
    try:
        subprocess.run([sys.executable, 'albion_protocol_decoder.py'])
    except KeyboardInterrupt:
        print("\n⏹️ Scanner stopped by user")
    except Exception as e:
        print(f"❌ Scanner failed: {e}")

def launch_web_dashboard():
    """Launch the web dashboard"""
    print("\n🌐 LAUNCHING WEB DASHBOARD")
    print("=" * 40)
    
    # Check if dashboard files exist
    required_files = ['albion_web_dashboard.html', 'dashboard_server.py']
    missing_files = [f for f in required_files if not os.path.exists(f)]
    
    if missing_files:
        print(f"❌ Missing files: {', '.join(missing_files)}")
        print("💡 Make sure all dashboard files are in the current directory")
        return
    
    print("🚀 Starting web server...")
    print("🌐 Dashboard will be available at: http://localhost:5000")
    print("⏹️  Press Ctrl+C to stop server")
    
    # Open browser after a short delay
    def open_browser():
        time.sleep(3)
        try:
            webbrowser.open('http://localhost:5000')
            print("🌐 Browser opened automatically")
        except:
            print("💡 Manually open: http://localhost:5000")
    
    browser_thread = threading.Thread(target=open_browser, daemon=True)
    browser_thread.start()
    
    try:
        # Run dashboard server
        subprocess.run([sys.executable, 'dashboard_server.py'])
    except KeyboardInterrupt:
        print("\n⏹️ Dashboard stopped by user")
    except Exception as e:
        print(f"❌ Dashboard failed to start: {e}")

def analyze_existing_data():
    """Analyze existing captured data"""
    print("\n📊 ANALYZING EXISTING DATA")
    print("=" * 40)
    
    # Look for JSON data files
    json_files = list(Path('.').glob('*.json'))
    albion_files = [f for f in json_files if 'albion' in f.name.lower()]
    
    if not albion_files:
        print("❌ No Albion data files found")
        print("💡 Capture some data first using the scanner")
        return
    
    print("📁 Found data files:")
    for i, file in enumerate(albion_files, 1):
        try:
            file_size = file.stat().st_size
            mod_time = time.ctime(file.stat().st_mtime)
            print(f"  {i}. {file.name} ({file_size} bytes, {mod_time})")
        except:
            print(f"  {i}. {file.name}")
    
    try:
        choice = int(input("\n🔢 Select file to analyze (number): ")) - 1
        if 0 <= choice < len(albion_files):
            selected_file = albion_files[choice]
            print(f"\n🔍 Analyzing: {selected_file.name}")
            
            # Check if analyzer exists
            if not os.path.exists('packet_analyzer.py'):
                print("❌ packet_analyzer.py not found")
                print("💡 Make sure analysis module is available")
                return
            
            # Basic analysis - show file contents
            try:
                import json
                with open(selected_file, 'r') as f:
                    data = json.load(f)
                
                print("📋 File Contents Summary:")
                if isinstance(data, dict):
                    for key, value in data.items():
                        if isinstance(value, list):
                            print(f"  {key}: {len(value)} items")
                        elif isinstance(value, dict):
                            print(f"  {key}: {len(value)} entries")
                        else:
                            print(f"  {key}: {value}")
                
                print("\n✅ Basic analysis completed!")
                print("💡 For detailed analysis, use packet_analyzer.py directly")
                
            except Exception as e:
                print(f"❌ Failed to analyze file: {e}")
        else:
            print("❌ Invalid selection")
            
    except ValueError:
        print("❌ Invalid input")
    except Exception as e:
        print(f"❌ Analysis failed: {e}")

def show_configuration():
    """Show configuration options"""
    print("\n⚙️ CONFIGURATION & SETUP")
    print("=" * 40)
    
    print("📋 Current Configuration:")
    print(f"  Interface: 5 (USB Tethering)")
    print(f"  Port: 5056 (Albion Online)")
    print(f"  Dashboard Port: 5000")
    
    print("\n🔧 Setup Instructions:")
    print("1. Install Wireshark: https://www.wireshark.org/")
    print("2. Install Npcap: https://npcap.com/")
    print("3. Run as Administrator for packet capture")
    print("4. Ensure Albion Online uses the monitored interface")
    
    print("\n📁 Required Files:")
    required_files = [
        'test.py',
        'albion_packet_parser.py',
        'albion_protocol_decoder.py',
        'packet_analyzer.py',
        'dashboard_server.py',
        'albion_web_dashboard.html',
        'wireshark_check.py'
    ]
    
    print("File Status:")
    for file in required_files:
        if os.path.exists(file):
            print(f"  ✅ {file}")
        else:
            print(f"  ❌ {file} (missing)")
    
    print("\n🔧 Troubleshooting:")
    print("  - Run Command Prompt as Administrator")
    print("  - Check Windows Firewall settings")
    print("  - Verify Npcap installation")
    print("  - Ensure Albion uses correct network interface")

def show_documentation():
    """Show documentation and help"""
    print("\n📖 DOCUMENTATION")
    print("=" * 40)
    
    print("🎯 PURPOSE:")
    print("  This suite captures and analyzes Albion Online network traffic")
    print("  to provide real-time player tracking and game data analysis.")
    
    print("\n🔄 WORKFLOW:")
    print("  1. Run diagnostics to ensure system is ready")
    print("  2. Test packet capture to verify interface works")
    print("  3. Use advanced scanner for detailed protocol analysis")
    print("  4. Launch web dashboard for real-time visualization")
    print("  5. Analyze captured data for insights")
    
    print("\n📊 FEATURES:")
    print("  ✅ Real-time packet capture")
    print("  ✅ Protocol decoding (movement, chat, player info)")
    print("  ✅ Player position tracking")
    print("  ✅ Web dashboard with live updates")
    print("  ✅ Data export and analysis")
    
    print("\n⚠️ LEGAL NOTICE:")
    print("  This tool is for educational and research purposes only.")
    print("  Respect game terms of service and use responsibly.")
    print("  Only monitor your own network traffic.")
    
    print("\n🆘 TROUBLESHOOTING:")
    print("  - Run as Administrator if permission errors occur")
    print("  - Check Windows Firewall settings")
    print("  - Ensure Npcap is installed correctly")
    print("  - Verify Albion Online is using the correct network interface")
    
    print("\n🔗 RESOURCES:")
    print("  - Wireshark: https://www.wireshark.org/")
    print("  - Npcap: https://npcap.com/")
    print("  - PyShark docs: https://github.com/KimiNewt/pyshark")

def main():
    """Main application loop"""
    print_banner()
    
    # Quick system check
    if not sys.platform.startswith('win'):
        print("⚠️ This tool is designed for Windows systems")
        print("💡 Linux/Mac support may require modifications")
    
    while True:
        show_menu()
        
        try:
            choice = input("\n🔢 Select option (1-8): ").strip()
            
            if choice == '1':
                run_diagnostics()
            elif choice == '2':
                test_packet_capture()
            elif choice == '3':
                launch_simple_monitor()
            elif choice == '4':
                launch_advanced_scanner()
            elif choice == '5':
                launch_web_dashboard()
            elif choice == '6':
                analyze_existing_data()
            elif choice == '7':
                show_configuration()
            elif choice == '8':
                show_documentation()
            elif choice == '9':
                print("\n👋 Goodbye!")
                break
            else:
                print("❌ Invalid option. Please select 1-9.")
            
            if choice in ['1', '2', '3', '4', '5', '6']:
                input("\n⏸️ Press Enter to continue...")
                
        except KeyboardInterrupt:
            print("\n\n👋 Goodbye!")
            break
        except Exception as e:
            print(f"\n❌ Unexpected error: {e}")
            input("\n⏸️ Press Enter to continue...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Application interrupted by user")
    except Exception as e:
        print(f"\n💥 Fatal error: {e}")
        input("Press Enter to exit...")