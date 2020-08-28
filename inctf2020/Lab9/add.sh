#!/bin/sh
cd fs
cp ../$1 .
find . -print0 | cpio --null -ov --format=newc > ../rootfs.cpio
