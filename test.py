# -*- coding: utf-8 -*-
import pyshark
import sys
import os

# Set encoding untuk Windows console
if sys.platform.startswith('win'):
    os.system('chcp 65001 >nul 2>&1')  # Set to UTF-8

# Konfigurasi dari hasil testing yang BERHASIL
INTERFACE_NAME = '5'  # USB Tethering - interface 5 terbukti bekerja
ALBION_PORT = 5056    # Port 5056 terbukti digunakan Albion (1080 packets detected)

try:
    print("TARGET: Menangkap paket Albion Online")
    print(f"Interface: {INTERFACE_NAME} (USB Tethering)")
    print(f"Port: {ALBION_PORT}")
    print("-" * 50)
    
    # METHOD 1: BPF Filter (Berkeley Packet Filter)
    # Ini lebih reliable daripada display_filter
    try:
        print("METHOD: Mencoba dengan BPF filter...")
        capture = pyshark.LiveCapture(
            interface=INTERFACE_NAME, 
            bpf_filter=f"udp port {ALBION_PORT}"
        )
        
        print("SUCCESS: BPF filter berhasil dibuat!")
        print("NOTE: Pastikan Albion Online berjalan dan ada aktivitas...")
        print("CTRL+C: Tekan Ctrl+C untuk berhenti\n")
        
        packet_count = 0
        for packet in capture.sniff_continuously():
            packet_count += 1
            
            # Extract packet info
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            src_port = int(packet.udp.srcport)
            dst_port = int(packet.udp.dstport)
            length = int(packet.length)
            
            # Determine direction
            if src_port == ALBION_PORT:
                direction = "<-- INCOMING"
                endpoint = f"{src_ip}:{src_port} -> Local:{dst_port}"
            else:
                direction = "--> OUTGOING"
                endpoint = f"Local:{src_port} -> {dst_ip}:{dst_port}"
            
            print(f"PACKET #{packet_count:3d} | {direction} | {endpoint} | {length} bytes")
            
            # Stop after 10 packets for demo
            if packet_count >= 10:
                print(f"\nSUCCESS: Successfully captured {packet_count} Albion packets!")
                break
        
        capture.close()
        
    except Exception as bpf_error:
        print(f"ERROR: BPF filter gagal: {bpf_error}")
        print("FALLBACK: Mencoba fallback method...")
        
        # METHOD 2: Manual Filtering (Fallback)
        capture = pyshark.LiveCapture(interface=INTERFACE_NAME)
        
        print("METHOD: Capturing all packets and filtering manually...")
        print("NOTE: Pastikan Albion Online berjalan dan ada aktivitas...\n")
        
        albion_count = 0
        total_count = 0
        
        for packet in capture.sniff_continuously():
            total_count += 1
            
            try:
                # Manual filter for UDP port 5056
                if hasattr(packet, 'udp'):
                    src_port = int(packet.udp.srcport)
                    dst_port = int(packet.udp.dstport)
                    
                    if src_port == ALBION_PORT or dst_port == ALBION_PORT:
                        albion_count += 1
                        
                        # Extract info
                        src_ip = packet.ip.src
                        dst_ip = packet.ip.dst
                        length = int(packet.length)
                        
                        # Direction
                        if src_port == ALBION_PORT:
                            direction = "<-- INCOMING"
                            endpoint = f"{src_ip}:{src_port} -> Local:{dst_port}"
                        else:
                            direction = "--> OUTGOING"
                            endpoint = f"Local:{src_port} -> {dst_ip}:{dst_port}"
                        
                        print(f"ALBION #{albion_count:3d} | {direction} | {endpoint} | {length} bytes")
                        
                        if albion_count >= 10:
                            print(f"\nSUCCESS: Successfully captured {albion_count} Albion packets!")
                            break
                
                # Progress indicator
                if total_count % 200 == 0:
                    print(f"PROGRESS: Processed {total_count} total packets, found {albion_count} Albion packets")
                
                # Safety stop
                if total_count >= 2000 and albion_count == 0:
                    print("TIMEOUT: Stopping - no Albion packets found in 2000 packets")
                    break
                    
            except AttributeError:
                continue
            except Exception as filter_error:
                continue
        
        capture.close()
        
        if albion_count > 0:
            print(f"RESULT: SUCCESS! Found {albion_count} Albion packets from {total_count} total")
        else:
            print(f"RESULT: No Albion packets found from {total_count} packets analyzed")
            print("NOTE: Make sure Albion is running and active!")

except Exception as e:
    print(f"ERROR: {e}")
    print("\nTROUBLESHOOTING:")
    print("1. Pastikan Albion Online berjalan dan ada aktivitas")
    print("2. Jalankan script sebagai Administrator")
    print("3. Pastikan tidak ada firewall yang memblokir")
    print("4. Coba restart Albion Online")