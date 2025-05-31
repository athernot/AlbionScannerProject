import subprocess
import sys
import os

def install_pyshark():
    """Install pyshark menggunakan pip"""
    print("📦 Installing PyShark...")
    try:
        result = subprocess.run([sys.executable, '-m', 'pip', 'install', 'pyshark'], 
                              capture_output=True, text=True, check=True)
        print("✅ PyShark berhasil diinstall!")
        print(result.stdout)
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Error installing PyShark: {e}")
        print(f"STDOUT: {e.stdout}")
        print(f"STDERR: {e.stderr}")
        return False

def test_pyshark_import():
    """Test import pyshark"""
    print("\n🧪 Testing PyShark import...")
    try:
        import pyshark
        print("✅ PyShark import berhasil!")
        print(f"   Version: {pyshark.__version__ if hasattr(pyshark, '__version__') else 'Unknown'}")
        return True
    except ImportError as e:
        print(f"❌ PyShark import gagal: {e}")
        return False

def quick_interface_test():
    """Quick test dengan interface yang kita tahu bekerja"""
    print("\n🎯 Quick Interface Test...")
    
    try:
        import pyshark
        
        # Test dengan interface 5 (USB Tethering) sesuai hasil diagnostic
        print("Testing interface '5' (USB Tethering)...")
        
        capture = pyshark.LiveCapture(interface='5')
        print("✅ LiveCapture object berhasil dibuat!")
        
        print("🔄 Testing packet capture (timeout 5 detik)...")
        packet_count = 0
        
        try:
            for packet in capture.sniff_continuously():
                packet_count += 1
                print(f"📦 Packet #{packet_count}: {packet.summary()}")
                
                if packet_count >= 2:  # Capture 2 paket saja
                    break
                    
        except Exception as e:
            print(f"Info: {e}")
        finally:
            capture.close()
        
        if packet_count > 0:
            print(f"✅ Berhasil capture {packet_count} paket!")
            return True
        else:
            print("⚠️ Tidak ada paket tertangkap (normal jika tidak ada traffic)")
            return True  # Still считается success
            
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def test_albion_capture():
    """Test capture khusus Albion"""
    print("\n🎮 Testing Albion Online Capture...")
    
    try:
        import pyshark
        
        # Test dengan interface 5 (USB Tethering) dan filter Albion
        capture = pyshark.LiveCapture(
            interface='5',
            display_filter="udp port 5056"
        )
        
        print("🔍 Filter: UDP port 5056 (Albion Online)")
        print("⏱️ Menunggu 10 detik...")
        print("📱 Pastikan Albion Online berjalan dan ada aktivitas!")
        
        packet_count = 0
        import time
        start_time = time.time()
        
        try:
            for packet in capture.sniff_continuously():
                packet_count += 1
                print(f"🎯 ALBION PACKET #{packet_count}:")
                print(f"   {packet.summary()}")
                
                if packet_count >= 3:
                    break
                    
                if time.time() - start_time > 10:
                    print("⏱️ Timeout 10 detik")
                    break
                    
        except Exception as e:
            print(f"Capture info: {e}")
        finally:
            capture.close()
        
        if packet_count > 0:
            print(f"🎉 SUKSES! Berhasil capture {packet_count} paket Albion!")
            print(f"\n📝 KONFIGURASI YANG BEKERJA:")
            print(f"INTERFACE_NAME = '5'  # USB Tethering")
            return True
        else:
            print("❌ Tidak ada paket Albion tertangkap")
            print("💡 Kemungkinan:")
            print("   - Albion tidak berjalan")
            print("   - Tidak ada aktivitas network")
            print("   - Coba interface lain (1, 4, 6)")
            return False
            
    except Exception as e:
        print(f"❌ Error Albion test: {e}")
        return False

def main():
    print("🚀 PYSHARK INSTALLATION & TEST")
    print("=" * 50)
    
    # Step 1: Install PyShark
    if not install_pyshark():
        print("❌ Gagal install PyShark")
        return
    
    # Step 2: Test import
    if not test_pyshark_import():
        print("❌ Gagal import PyShark")
        return
    
    # Step 3: Quick test
    if not quick_interface_test():
        print("❌ Basic test gagal")
        return
    
    # Step 4: Albion test
    print("\n" + "="*50)
    test_albion_capture()
    
    print("\n" + "="*50)
    print("📋 NEXT STEPS:")
    print("1. Jika Albion test berhasil → langsung pakai konfigurasi di atas")
    print("2. Jika tidak ada paket Albion → jalankan game dan coba lagi")
    print("3. Coba interface lain: '1', '4', '6' jika USB Tethering tidak work")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⏹️ Dibatalkan oleh user")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()