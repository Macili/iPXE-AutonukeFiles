#!/bin/bash
set -e

echo "------------------------------------------"
echo " PXE-Server Setup: BIOS + UEFI for ShredOS"
echo " with automatic extraction of kernel/initrd"
echo "------------------------------------------"

# Check for sudo/root
if [[ "$EUID" -ne 0 ]]; then
  echo "[!] This script must be run as root (e.g., with sudo)"
  exit 1
fi

# Configuration
SERVER_IP="192.168.0.1"
DHCP_RANGE_START="192.168.0.100"
DHCP_RANGE_END="192.168.0.200"

TMP_DIR="/tmp/pxe-setup"
[ -d /tmp/pxe-setup ] || mkdir -p /tmp/pxe-setup

WEBROOT="/var/www/html/shredos"
[ -d /var/www/html/shredos ] || mkdir -p /var/www/html/shredos

ISO_MOUNT="/mnt/shredos"
[ -d /mnt/shredos ] || mkdir -p /mnt/shredos

SHREDOS_ISO_NAME="shredos-2024.11_27_x86-64_0.38_20250125_vanilla.iso"
SHREDOS_ISO_URL="https://github.com/PartialVolume/shredos.x86_64/releases/download/v2024.11_27_x86-64_0.38/${SHREDOS_ISO_NAME}"

#IPXE_BIOS_URL="https://boot.ipxe.org/undionly.kpxe"
#IPXE_UEFI_URL="https://boot.ipxe.org/ipxe.efi"
IPXE_BIOS_URL="https://raw.githubusercontent.com/Macili/iPXE-AutonukeFiles/refs/heads/main/undionly.kpxe"
IPXE_UEFI_URL="https://raw.githubusercontent.com/Macili/iPXE-AutonukeFiles/refs/heads/main/ipxe.efi"

echo
echo "[+] Installing required packages..."
sudo apt update
sudo apt install -y isc-dhcp-server tftpd-hpa nginx wget syslinux-common xz-utils

echo
echo "[+] Downloading required files..."
wget --no-check-certificate -O "$TMP_DIR/undionly.kpxe" "$IPXE_BIOS_URL"
wget --no-check-certificate -O "$TMP_DIR/ipxe.efi" "$IPXE_UEFI_URL"
wget -O "$TMP_DIR/$SHREDOS_ISO_NAME" "$SHREDOS_ISO_URL"
cp /usr/lib/syslinux/memdisk "$TMP_DIR/memdisk"

echo "[+] Extracting bzImage (kernel) from ISO..."
sudo mount -o loop "$TMP_DIR/$SHREDOS_ISO_NAME" "$ISO_MOUNT"
sudo cp "$ISO_MOUNT/boot/bzImage" "$WEBROOT/"
sudo umount "$ISO_MOUNT"

echo "[+] Copying ISO and memdisk (for BIOS) to web directory..."
sudo cp "$TMP_DIR/$SHREDOS_ISO_NAME" "$WEBROOT/"
sudo cp "$TMP_DIR/memdisk" "$WEBROOT/"

echo
echo
echo "====================================="
echo "====================================="
echo
echo
echo "[+] Available network interfaces:"
ip -o link show | awk -F': ' '{print $2}' | grep -v lo

echo
read -rp "Enter the network interface to use [Default: eth0]: " INTERFACE
INTERFACE=${INTERFACE:-eth0}

# Prepare Netplan
echo "[+] Writing Netplan configuration..."
sudo tee /etc/netplan/99-pxe-static.yaml > /dev/null <<EOF
network:
  version: 2
  ethernets:
    ${INTERFACE}:
      dhcp4: no
      addresses: [${SERVER_IP}/24]
EOF

# Configure DHCP
echo "[+] Configuring DHCP server..."
sudo tee /etc/dhcp/dhcpd.conf > /dev/null <<EOF
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

sudo sed -i "s/^INTERFACESv4=.*/INTERFACESv4=\"$INTERFACE\"/" /etc/default/isc-dhcp-server

# Configure TFTP
echo "[+] Configuring TFTP server..."
[ -d /var/lib/tftpboot ] || sudo mkdir -p /var/lib/tftpboot
sudo chmod -R 777 /var/lib/tftpboot
sudo tee /etc/default/tftpd-hpa > /dev/null <<EOF
TFTP_USERNAME="tftp"
TFTP_DIRECTORY="/var/lib/tftpboot"
TFTP_ADDRESS="0.0.0.0:69"
TFTP_OPTIONS="--secure"
EOF

sudo cp "$TMP_DIR/undionly.kpxe" /var/lib/tftpboot/
sudo cp "$TMP_DIR/ipxe.efi" /var/lib/tftpboot/

# Write boot script
echo "[+] Creating iPXE boot script for BIOS & UEFI with robust platform detection..."
sudo tee /var/www/html/boot.ipxe > /dev/null <<EOF
#!ipxe
echo iPXE detected platform: \${platform}

# Separate boot paths for BIOS vs UEFI
iseq \${platform} efi && goto uefi || goto bios

:uefi
kernel http://${SERVER_IP}/shredos/bzImage
boot

:bios
kernel http://${SERVER_IP}/shredos/memdisk iso raw
initrd http://${SERVER_IP}/shredos/${SHREDOS_ISO_NAME}
boot
EOF

# systemd oneshot for reboot & service start
echo "[+] Creating systemd service for setup on first boot..."
sudo tee /etc/systemd/system/pxe-init.service > /dev/null <<EOF
[Unit]
Description=Initial PXE Server Setup (Network, Services, Reboot)
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/pxe-init.sh
RemainAfterExit=no

[Install]
WantedBy=multi-user.target
EOF

sudo tee /usr/local/bin/pxe-init.sh > /dev/null <<EOF
#!/bin/bash
netplan apply
systemctl restart isc-dhcp-server
systemctl restart tftpd-hpa
systemctl restart nginx
systemctl disable pxe-init.service
sleep 5
reboot
EOF

sudo chmod +x /usr/local/bin/pxe-init.sh
sudo systemctl enable pxe-init.service

# Create toggle-network.sh in current directory
SCRIPT_DIR="$(pwd)"
TOGGLE_SCRIPT="${SCRIPT_DIR}/toggle-network.sh"

echo "[+] Creating toggle-network.sh script in ${SCRIPT_DIR}..."
cat <<EOF > "$TOGGLE_SCRIPT"
#!/bin/bash
set -e

NETPLAN_FILE="/etc/netplan/99-pxe-static.yaml"
INTERFACE="\$(ip -o link show | awk -F': ' '{print \$2}' | grep -v lo | head -n1)"

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
        sudo tee "\$NETPLAN_FILE" > /dev/null <<EONET
network:
  version: 2
  ethernets:
    \$INTERFACE:
      dhcp4: true
EONET
        ;;
    2)
        echo "[+] Switching to static PXE IP (192.168.0.1)..."
        sudo tee "\$NETPLAN_FILE" > /dev/null <<EONET
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
sudo netplan apply
echo "[+] Done."
echo
ip a show "\$INTERFACE" | grep inet
EOF

chmod +x "$TOGGLE_SCRIPT"

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
echo "    - Warning! As soon you choose PXE boot on your devices, they will boot directly into ShredOS and will wipe automatically, without user interaction!"
echo
echo "On next boot:"
echo "  - Static IP will be activated"
echo "  - All PXE services will start"
echo "  - An automatic reboot will be triggered"
echo "  From there on, PXE boot will be available for both BIOS and UEFI."
echo
echo "[+] Ethernet swap back:"
echo "	  - On the same directory you executed this script, there will be now an additional script to toggle network config."
echo "	  - This toggle allows you to switch between DHCP for internet access and static PXE IP."
echo
