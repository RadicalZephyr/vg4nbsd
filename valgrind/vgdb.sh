#!/bin/sh
# quick gdb script launching valgrind 
#

VG_ROOT=/home/sjamaan/valgrind
VG_ROOT_LIB=$VG_ROOT/.in_place/
#VG_TOOL=memcheck
VG_TOOL=none
VG_TMP_SCRIPT=/tmp/vg.gdb.peter
BIN=$1
VGBIN=./coregrind/valgrind

export VALGRIND_LIB=$VG_ROOT_LIB
echo "LIB @ $VG_ROOT_LIB"
echo "BIN : $BIN"

cd $VG_ROOT
cat > $VG_TMP_SCRIPT << EOF
break main
run -d -d --trace-syscalls=yes --tool=$VG_TOOL -v $BIN
step
symbol-file .in_place/x86-netbsd/none
EOF

gdb -x $VG_TMP_SCRIPT -q $VGBIN
rm -rf $VG_TMP_SCRIPT
