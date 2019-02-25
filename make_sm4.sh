gcc -Iinclude -c main_sm4.c
gcc main_sm4.o libcrypto.so -o sm4

export LD_LIBRARY_PATH=`pwd`
ldd sm4

