gcc -Iinclude -Itest -c sm2_test_demo.c
gcc sm2_test_demo.o libcrypto.so -o sm2_test_demo
#gcc sm2_test_main.o libssl.so.1.1 libcrypto.so.1.1 -o sm2_test
export LD_LIBRARY_PATH=`pwd`
ldd sm2_test_demo

