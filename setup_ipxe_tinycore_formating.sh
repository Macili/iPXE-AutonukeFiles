#!/bin/bash
set -e

echo "------------------------------------------"
echo " PXE-Server Setup: BIOS + UEFI for TinyCore"
echo " with automatic formatting of internal disks"
echo "------------------------------------------"

# Root-Check
if [[ "$EUID" -ne 0 ]]; then
  echo "[!] This script must be run as root (e.g., with sudo)"
  exit 1
fi

# Konfiguration
SERVER_IP="192.168.0.1"
DHCP_RANGE_START="192.168.0.100"
DHCP_RANGE_END="192.168.0.200"

TMP_DIR="/tmp/pxe-setup"
WEBROOT="/var/www/html/tinycore"
ISO_MOUNT="/mnt/tinycore"
INITRD_WORK="$TMP_DIR/initrd-work"
TFTBOOT_DIR="/var/lib/tftpboot/"

TC_ISO_URL="http://tinycorelinux.net/13.x/x86_64/release/CorePure64-13.1.iso"
TC_ISO_NAME="CorePure64.iso"

IPXE_BIOS_URL="https://raw.githubusercontent.com/Macili/iPXE-AutonukeFiles/refs/heads/main/undionly.kpxe"
IPXE_UEFI_URL="https://raw.githubusercontent.com/Macili/iPXE-AutonukeFiles/refs/heads/main/ipxe.efi"

# Verzeichnisse vorbereiten
mkdir -p "$TMP_DIR" "$WEBROOT" "$ISO_MOUNT" "$INITRD_WORK" "$TFTBOOT_DIR"

echo
echo "[+] Installing required packages..."
apt update
apt install -y isc-dhcp-server tftpd-hpa nginx wget syslinux-common xz-utils cpio

echo
echo "[+] Downloading required files..."
wget --no-check-certificate -O "$TMP_DIR/undionly.kpxe" "$IPXE_BIOS_URL" || { echo "[!] Failed to download undionly.kpxe"; exit 1; }
wget --no-check-certificate -O "$TMP_DIR/ipxe.efi" "$IPXE_UEFI_URL" || { echo "[!] Failed to download ipxe.efi"; exit 1; }
wget -O "$TMP_DIR/$TC_ISO_NAME" "$TC_ISO_URL" || { echo "[!] Failed to download TinyCore ISO"; exit 1; }

echo
echo "[+] Extracting kernel and initrd from ISO..."
if ! mount -o loop "$TMP_DIR/$TC_ISO_NAME" "$ISO_MOUNT"; then
  echo "[!] Failed to mount ISO. Exiting."
  exit 1
fi
cp "$ISO_MOUNT/boot/vmlinuz64" "$WEBROOT/"
cp "$ISO_MOUNT/boot/corepure64.gz" "$TMP_DIR/"
umount "$ISO_MOUNT"

echo "[+] Modifying initrd with autowipe script..."
cd "$INITRD_WORK"
zcat "$TMP_DIR/corepure64.gz" | cpio -idmv
mkdir -p opt

# bootlocal.sh
cat << 'EOF' > opt/bootlocal.sh
#!/bin/shThi
echo "[+] Autowipe Debug Mode Enabled" > /tmp/autowipe.log
echo "[+] Listing block devices..." >> /tmp/autowipe.log

cat /proc/partitions >> /tmp/autowipe.log

DISKS=$(awk 'NR > 2 && $4 !~ /^(loop|ram|sr|zram|dm)/ { print "/dev/" $4 }' /proc/partitions)

echo "[+] Devices selected for wipe:" >> /tmp/autowipe.log
echo "$DISKS" >> /tmp/autowipe.log

for d in $DISKS; do
    echo "[*] Trying to unmount anything using $d..." >> /tmp/autowipe.log
    umount -f "${d}"* 2>/dev/null || true

    echo "[*] Wiping device: $d" >> /tmp/autowipe.log

    # Partitionstabelle + erste 100MB überschreiben
    dd if=/dev/zero of="$d" bs=1M count=100 status=none >> /tmp/autowipe.log 2>&1

    # Letzte 10MB (am Ende der Disk, z. B. GPT Backup Header)
    DEVICE=$(basename "$d")
	SIZE=$(cat /sys/block/"$DEVICE"/size 2>/dev/null || echo 0)
	END=$((SIZE - 20480))
	if [ "$SIZE" -gt 0 ]; then
		dd if=/dev/zero of="$d" bs=512 seek=$END count=20480 status=none >> /tmp/autowipe.log 2>&1
	else
		echo "[!] Could not determine size of $d — skipping end wipe" >> /tmp/autowipe.log
	fi

    # Neue GPT-Tabelle setzen
    parted -s "$d" mklabel gpt >> /tmp/autowipe.log 2>&1
done

echo >> /tmp/autowipe.log
echo "[+] Wipe completed." >> /tmp/autowipe.log
echo "[.] Waiting 10 seconds before shutdown..." >> /tmp/autowipe.log

sleep 10
poweroff
EOF

chmod +x opt/bootlocal.sh

# tc-config patchen
TC_CONFIG="etc/init.d/tc-config"
if ! grep -q "/opt/bootlocal.sh" "$TC_CONFIG"; then
  sed -i '/\/opt\/bootsync.sh/a\
if [ -x /opt/bootlocal.sh ]; then\
    echo "[+] Running /opt/bootlocal.sh..."\
    /opt/bootlocal.sh\
fi' "$TC_CONFIG"
fi

# Neue initrd bauen
find . | cpio -o -H newc | gzip -9 > "$TMP_DIR/corepure64.gz"
cp "$TMP_DIR/corepure64.gz" "$WEBROOT/"
chmod 444 "$WEBROOT"/corepure64.gz "$WEBROOT"/vmlinuz64

# iPXE Bootskript
echo "[+] Creating iPXE boot script..."
tee /var/www/html/boot.ipxe > /dev/null <<EOF
#!ipxe
kernel http://${SERVER_IP}/tinycore/vmlinuz64
initrd http://${SERVER_IP}/tinycore/corepure64.gz
boot
EOF

# iPXE Binaries ins TFTP-Verzeichnis
echo "[+] Copying iPXE binaries..."
cp "$TMP_DIR/undionly.kpxe" /var/lib/tftpboot/
cp "$TMP_DIR/ipxe.efi" /var/lib/tftpboot/

# Netzwerkinterface bestimmen
INTERFACE=$(ls /sys/class/net | grep -vE 'lo|docker|virbr|veth' | head -n1)
if [ -z "$INTERFACE" ]; then
  echo "[!] Could not determine active network interface"
  exit 1
fi

# Netplan konfigurieren
tee /etc/netplan/99-pxe-static.yaml > /dev/null <<EOF
network:
  version: 2
  ethernets:
    ${INTERFACE}:
      dhcp4: no
      addresses: [${SERVER_IP}/24]
EOF

# DHCP-Konfiguration
tee /etc/dhcp/dhcpd.conf > /dev/null <<EOF
default-lease-time 600;
max-lease-time 7200;
authoritative;
option arch code 93 = unsigned integer 16;
subnet 192.168.0.0 netmask 255.255.255.0 {
    range ${DHCP_RANGE_START} ${DHCP_RANGE_END};
    option routers ${SERVER_IP};
    if option arch = 00:07 {
        filename "ipxe.efi";
    } else {
        filename "undionly.kpxe";
    }
    next-server ${SERVER_IP};
}
EOF

# DHCP-Interface setzen
sed -i "s/^INTERFACESv4=.*/INTERFACESv4=\"$INTERFACE\"/" /etc/default/isc-dhcp-server

# TFTP-Konfiguration
tee /etc/default/tftpd-hpa > /dev/null <<EOF
TFTP_USERNAME="tftp"
TFTP_DIRECTORY="/var/lib/tftpboot"
TFTP_ADDRESS="0.0.0.0:69"
TFTP_OPTIONS="--secure"
EOF

# Netzwerkumschalter
echo "[+] Creating toggle-network script..."
cat <<EOF > /root/toggle-network.sh
#!/bin/bash
set -e

NETPLAN_FILE="/etc/netplan/99-pxe-static.yaml"
INTERFACE="\$(ls /sys/class/net | grep -vE 'lo|docker|virbr|veth' | head -n1)"

echo
echo "Current network configuration:"
ip a show "\$INTERFACE" | grep inet || echo "No IP detected"

echo
echo "Choose network mode:"
echo "1) Enable DHCP (for internet access)"
echo "2) Enable static PXE IP (192.168.0.1)"
read -rp "Selection (1/2): " CHOICE

case "\$CHOICE" in
    1)
        echo "[+] Switching to DHCP..."
        tee "\$NETPLAN_FILE" > /dev/null <<EONET
network:
  version: 2
  ethernets:
    \$INTERFACE:
      dhcp4: true
EONET
        ;;
    2)
        echo "[+] Switching to static PXE IP (192.168.0.1)..."
        tee "\$NETPLAN_FILE" > /dev/null <<EONET
network:
  version: 2
  ethernets:
    \$INTERFACE:
      dhcp4: no
      addresses: [192.168.0.1/24]
EONET
        ;;
    *)
        echo "Invalid selection. Aborting."
        exit 1
        ;;
esac

echo "[+] Applying netplan configuration..."
netplan apply
echo "[+] Done."
ip a show "\$INTERFACE" | grep inet
EOF

chmod +x "/root/toggle-network.sh"

# Cleanup
echo "[+] Cleaning up temporary files..."
rm -rf "$TMP_DIR"

echo "====================================="
echo "====================================="
echo "====================================="
echo
echo
echo "[+] Setup complete. Do following steps:"
echo "    - Restart the server: sudo reboot"
echo "	  - On restart swap ethernet cable to your empty network."
echo "	  - Important! Make sure there is no router on this empty network. Connect only devices who needs to be wiped to this network."
echo "	  - Important! Make sure to disable secure boot on your devices who need to be wiped!"
echo "    - Warning! As soon you choose PXE IPv4 boot on your devices, they will boot directly into and will wipe automatically, without user interaction!"
echo
echo "On next boot:"
echo "  - Static IP will be activated"
echo "  - All PXE services will start"
echo "  - An automatic reboot will be triggered"
echo "  From there on, PXE boot will be available for both BIOS and UEFI."
echo
echo "[+] Ethernet swap back:"
echo "	  - On the /root/ folder, there will be now an additional script to toggle network config. (toogle-network.sh)"
echo "	  - This toggle allows you to switch between DHCP for internet access and static PXE IP."
echo
