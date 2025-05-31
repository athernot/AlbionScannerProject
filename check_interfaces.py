import subprocess
import os
import socket
import psutil

def find_tshark():
    """Cari lokasi TShark di sistem"""
    possible_paths = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
        r"C:\Wireshark\tshark.exe",
    ]
    
    for path in possible_paths:
        if os.path.exists(path):
            return path
    
    # Coba cari di PATH
    try:
        result = subprocess.run(['where', 'tshark'], capture_output=True, text=True, shell=True)
        if result.returncode == 0:
            return result.stdout.strip().split('\n')[0]
    except:
        pass
    
    return None

def list_interfaces_with_tshark():
    """List interface menggunakan TShark langsung"""
    tshark_path = find_tshark()
    
    if not tshark_path:
        print("❌ TShark tidak ditemukan!")
        print("Solusi:")
        print("1. Install Wireshark dari https://www.wireshark.org/download.html")
        print("2. Pastikan TShark terinstal bersama Wireshark")
        return None
    
    print(f"✅ TShark ditemukan di: {tshark_path}")
    
    try:
        result = subprocess.run([tshark_path, '-D'], capture_output=True, text=True, check=True)
        print("\n=== DAFTAR INTERFACE DARI TSHARK ===")
        interfaces = []
        
        for line in result.stdout.strip().split('\n'):
            if line.strip():
                print(line)
                interfaces.append(line)
        
        return interfaces
        
    except subprocess.CalledProcessError as e:
        print(f"Error menjalankan TShark: {e}")
        return None
    except Exception as e:
        print(f"Error: {e}")
        return None

def list_network_interfaces():
    """List interface menggunakan psutil (Python native)"""
    print("\n=== INTERFACE DARI PSUTIL ===")
    
    try:
        interfaces = psutil.net_if_addrs()
        
        for interface_name, addresses in interfaces.items():
            print(f"\nInterface: {interface_name}")
            
            for addr in addresses:
                if addr.family == socket.AF_INET:  # IPv4
                    print(f"  IPv4: {addr.address}")
                elif addr.family == socket.AF_INET6:  # IPv6
                    print(f"  IPv6: {addr.address}")
        
        return list(interfaces.keys())
        
    except Exception as e:
        print(f"Error dengan psutil: {e}")
        return None

def test_interface_names():
    """Test beberapa nama interface yang mungkin bekerja"""
    print("\n=== TEST INTERFACE NAMES ===")
    
    # Ambil daftar interface dari psutil
    try:
        interfaces = psutil.net_if_addrs()
        interface_names = list(interfaces.keys())
        
        print("Interface names yang akan ditest:")
        for i, name in enumerate(interface_names, 1):
            print(f"{i}. '{name}'")
            
        return interface_names
        
    except Exception as e:
        print(f"Error: {e}")
        return []

if __name__ == "__main__":
    print("=== DIAGNOSTIK INTERFACE NETWORK ===\n")
    
    # Method 1: TShark
    tshark_interfaces = list_interfaces_with_tshark()
    
    # Method 2: psutil
    psutil_interfaces = list_network_interfaces()
    
    # Method 3: Test names
    test_names = test_interface_names()
    
    print("\n" + "="*50)
    print("RINGKASAN:")
    
    if tshark_interfaces:
        print(f"✅ TShark menemukan {len(tshark_interfaces)} interface")
    else:
        print("❌ TShark tidak tersedia atau error")
    
    if psutil_interfaces:
        print(f"✅ Python menemukan {len(psutil_interfaces)} interface")
        print("\nRekomendasi nama interface untuk dicoba:")
        for name in psutil_interfaces:
            if any(keyword in name.lower() for keyword in ['usb', 'tether', 'mobile', 'ethernet', 'wi-fi', 'wireless']):
                print(f"  - '{name}'  ⭐ (Recommended)")
            else:
                print(f"  - '{name}'")
    else:
        print("❌ Tidak bisa mendapatkan daftar interface")