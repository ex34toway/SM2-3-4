gcc -Iinclude -c main_sm4.c
gcc main_sm4.o libcrypto.so -o a.out

export LD_LIBRARY_PATH=`pwd`
ldd a.out

#./a.out
