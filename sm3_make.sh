gcc -Iinclude -c sm3_main.c
gcc sm3_main.o libcrypto.so -o sm3

export LD_LIBRARY_PATH=`pwd`
ldd sm3

gcc -Iinclude -c sm3_main_txt.c
gcc sm3_main_txt.o libcrypto.so -o sm3_txt

export LD_LIBRARY_PATH=`pwd`
ldd sm3_txt
