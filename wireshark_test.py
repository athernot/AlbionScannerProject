import os
import subprocess
import sys
import winreg

def check_wireshark_installation():
    """Periksa instalasi Wireshark dan komponen yang diperlukan"""
    print("🔍 CHECKING WIRESHARK INSTALLATION")
    print("=" * 40)
    
    # Cek registry Wireshark
    wireshark_paths = []
    
    try:
        # Cek di HKEY_LOCAL_MACHINE
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Wireshark")
        install_dir = winreg.QueryValueEx(key, "InstallDir")[0]
        wireshark_paths.append(install_dir)
        print(f"✅ Wireshark ditemukan di registry: {install_dir}")
        winreg.CloseKey(key)
    except:
        print("❌ Wireshark tidak ditemukan di registry")
    
    # Cek lokasi standar
    standard_paths = [
        r"C:\Program Files\Wireshark",
        r"C:\Program Files (x86)\Wireshark"
    ]
    
    for path in standard_paths:
        if os.path.exists(path):
            wireshark_paths.append(path)
            print(f"✅ Wireshark ditemukan: {path}")
    
    if not wireshark_paths:
        print("❌ Wireshark tidak terinstall!")
        return None
    
    # Cek komponen penting
    wireshark_dir = wireshark_paths[0]
    components = {
        'tshark.exe': os.path.join(wireshark_dir, 'tshark.exe'),
        'dumpcap.exe': os.path.join(wireshark_dir, 'dumpcap.exe'),
        'wireshark.exe': os.path.join(wireshark_dir, 'wireshark.exe')
    }
    
    print(f"\n📁 Checking components in: {wireshark_dir}")
    
    for name, path in components.items():
        if os.path.exists(path):
            print(f"✅ {name} - OK")
        else:
            print(f"❌ {name} - MISSING")
    
    return wireshark_dir

def check_npcap():
    """Periksa instalasi Npcap"""
    print(f"\n🔍 CHECKING NPCAP")
    print("=" * 20)
    
    npcap_paths = [
        r"C:\Windows\System32\Npcap",
        r"C:\Windows\SysWOW64\Npcap"
    ]
    
    npcap_found = False
    
    for path in npcap_paths:
        if os.path.exists(path):
            npcap_found = True
            print(f"✅ Npcap ditemukan: {path}")
            
            # List file di direktori Npcap
            try:
                files = os.listdir(path)
                important_files = ['wpcap.dll', 'packet.dll']
                
                for file in important_files:
                    if file in files:
                        print(f"  ✅ {file}")
                    else:
                        print(f"  ❌ {file} - MISSING")
            except Exception as e:
                print(f"  ❌ Error listing files: {e}")
    
    if not npcap_found:
        print("❌ Npcap tidak ditemukan!")
        print("💡 Download dari: https://npcap.com/")
    
    return npcap_found

def test_tshark_direct(wireshark_dir):
    """Test TShark secara langsung"""
    print(f"\n🧪 TESTING TSHARK DIRECTLY")
    print("=" * 30)
    
    tshark_path = os.path.join(wireshark_dir, 'tshark.exe')
    
    if not os.path.exists(tshark_path):
        print(f"❌ TShark tidak ditemukan di: {tshark_path}")
        return False
    
    try:
        # Test 1: Version check
        print("Test 1: TShark version...")
        result = subprocess.run([tshark_path, '--version'], 
                              capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            version_line = result.stdout.split('\n')[0]
            print(f"✅ {version_line}")
        else:
            print(f"❌ Version check failed: {result.stderr}")
            return False
        
        # Test 2: List interfaces
        print("\nTest 2: List interfaces...")
        result = subprocess.run([tshark_path, '-D'], 
                              capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            interfaces = result.stdout.strip().split('\n')
            print(f"✅ Found {len(interfaces)} interfaces:")
            
            for i, interface in enumerate(interfaces):
                print(f"  {i+1}. {interface}")
                
            return interfaces
        else:
            print(f"❌ Interface listing failed:")
            print(f"   Return code: {result.returncode}")
            print(f"   Error: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print("❌ TShark timeout - mungkin ada masalah permission")
        return False
    except Exception as e:
        print(f"❌ Error running TShark: {e}")
        return False

def test_simple_capture(wireshark_dir, interface_id="1"):
    """Test capture sederhana dengan TShark"""
    print(f"\n🎯 TESTING SIMPLE CAPTURE")
    print("=" * 30)
    
    tshark_path = os.path.join(wireshark_dir, 'tshark.exe')
    
    try:
        print(f"Testing capture pada interface {interface_id}...")
        print("Timeout: 5 detik")
        
        # Capture 1 paket dengan timeout 5 detik
        cmd = [
            tshark_path,
            '-i', interface_id,
            '-c', '1',  # Capture 1 packet
            '-a', 'duration:5'  # Timeout 5 seconds
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            print("✅ Capture berhasil!")
            print("Output:")
            print(result.stdout)
            return True
        else:
            print(f"❌ Capture gagal (return code: {result.returncode})")
            print("Error output:")
            print(result.stderr)
            return False
            
    except subprocess.TimeoutExpired:
        print("⏱️ Capture timeout - normal jika tidak ada traffic")
        return True  # Timeout is actually OK for this test
    except Exception as e:
        print(f"❌ Error during capture: {e}")
        return False

def run_full_diagnostic():
    """Jalankan diagnostic lengkap"""
    print("🏥 WIRESHARK + PYSHARK DIAGNOSTIC")
    print("=" * 50)
    
    # Step 1: Check Wireshark
    wireshark_dir = check_wireshark_installation()
    if not wireshark_dir:
        print("\n❌ GAGAL: Wireshark tidak terinstall")
        print("💡 Solusi: Install Wireshark dari https://www.wireshark.org/")
        return
    
    # Step 2: Check Npcap
    npcap_ok = check_npcap()
    if not npcap_ok:
        print("\n❌ GAGAL: Npcap tidak terinstall")
        print("💡 Solusi: Install Npcap dari https://npcap.com/")
        return
    
    # Step 3: Test TShark
    interfaces = test_tshark_direct(wireshark_dir)
    if not interfaces:
        print("\n❌ GAGAL: TShark tidak bisa list interface")
        print("💡 Solusi: Jalankan sebagai Administrator")
        return
    
    # Step 4: Test simple capture
    print("\n" + "="*50)
    print("🧪 TESTING CAPTURE CAPABILITIES")
    
    # Ambil interface ID dari daftar (biasanya yang pertama)
    first_interface = interfaces[0] if interfaces else "1"
    interface_id = first_interface.split('.')[0] if '.' in first_interface else "1"
    
    capture_ok = test_simple_capture(wireshark_dir, interface_id)
    
    # Final summary
    print("\n" + "="*50)
    print("📋 DIAGNOSTIC SUMMARY")
    print("="*50)
    
    print(f"✅ Wireshark: OK ({wireshark_dir})")
    print(f"✅ Npcap: OK")
    print(f"✅ TShark: OK")
    print(f"✅ Interfaces: {len(interfaces)} found")
    
    if capture_ok:
        print(f"✅ Capture: OK")
        print(f"\n🎉 SEMUA KOMPONEN OK!")
        print(f"💡 Coba gunakan interface ID: {interface_id}")
        print(f"   Atau nama interface dari list di atas")
    else:
        print(f"❌ Capture: FAILED")
        print(f"\n⚠️ Ada masalah dengan capture capability")
        print(f"💡 Coba jalankan sebagai Administrator")

if __name__ == "__main__":
    if not sys.platform.startswith('win'):
        print("❌ Script ini hanya untuk Windows")
        sys.exit(1)
    
    try:
        run_full_diagnostic()
    except KeyboardInterrupt:
        print("\n\n⏹️ Diagnostic dibatalkan")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        print("Coba jalankan sebagai Administrator")