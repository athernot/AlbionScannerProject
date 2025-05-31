import pyshark

# Ganti 'Your_Interface_Name' dengan nama interface yang benar
# Anda bisa mendapatkan nama interface dari Wireshark atau output `ipconfig`
# Contoh: 'Ethernet', 'Wi-Fi'
INTERFACE_NAME = 'Remote NDIS Compatible Device' # Sesuaikan ini!

try:
    print(f"Mencoba menangkap paket di interface: {INTERFACE_NAME}")
    capture = pyshark.LiveCapture(interface=INTERFACE_NAME, display_filter="udp port 5056")
    print("Menunggu paket Albion Online (UDP port 5056)... Pastikan game berjalan dan aktif.")
    for packet in capture.sniff_continuously(packet_count=5):
        print(f"Paket tertangkap: {packet}")
    capture.close() # Tutup capture setelah selesai
except Exception as e:
    print(f"Error saat menangkap paket: {e}")
    print("Pastikan Npcap terinstal, Anda menjalankan skrip sebagai admin, dan nama interface sudah benar.")
