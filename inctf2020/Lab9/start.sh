#!/bin/bash

qemu-system-x86_64 \
	-enable-kvm \
        -cpu kvm64 \
	-m 128 \
	-kernel bzImage \
	-nographic \
	-append "console=ttyS0 init=/init quiet kaslr" \
	-initrd rootfs.cpio \
	-monitor /dev/null \
	-gdb tcp::6789
