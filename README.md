o Configuring device node:
    - mdkir /dev/net (if it does not already exist)
    - `sudo mknod /dev/net/tun c 10 200`
      Format: mknod <device_node> <file_type> <MAJOR> <MINOR>
      (Conversely sudo mknod /dev/net/tap c 10 200)
    - Finally set permissions for r/w
