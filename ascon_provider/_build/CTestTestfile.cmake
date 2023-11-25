# CMake generated Testfile for 
# Source directory: /home/simon/vigenere
# Build directory: /home/simon/vigenere/_build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test([=[vigenere]=] "/home/simon/vigenere/_build/test_vigenere")
set_tests_properties([=[vigenere]=] PROPERTIES  ENVIRONMENT "OPENSSL_MODULES=/home/simon/vigenere/_build;OPENSSL_PROGRAM=/usr/bin/openssl;OPENSSL_RUNTIME_DIR=/usr/bin;OPENSSL_LIBRARY_DIR=/usr/lib/x86_64-linux-gnu;SOURCEDIR=/home/simon/vigenere;PERL5LIB=/home/simon/vigenere/t" _BACKTRACE_TRIPLES "/home/simon/vigenere/CMakeLists.txt;54;add_test;/home/simon/vigenere/CMakeLists.txt;0;")
add_test([=[vigenere_err]=] "/home/simon/vigenere/_build/test_vigenere_err")
set_tests_properties([=[vigenere_err]=] PROPERTIES  ENVIRONMENT "OPENSSL_MODULES=/home/simon/vigenere/_build;OPENSSL_PROGRAM=/usr/bin/openssl;OPENSSL_RUNTIME_DIR=/usr/bin;OPENSSL_LIBRARY_DIR=/usr/lib/x86_64-linux-gnu;SOURCEDIR=/home/simon/vigenere;PERL5LIB=/home/simon/vigenere/t" _BACKTRACE_TRIPLES "/home/simon/vigenere/CMakeLists.txt;66;add_test;/home/simon/vigenere/CMakeLists.txt;0;")
add_test([=[openssl]=] "prove" "-PWrapOpenSSL" "/home/simon/vigenere/t")
set_tests_properties([=[openssl]=] PROPERTIES  ENVIRONMENT "OPENSSL_MODULES=/home/simon/vigenere/_build;OPENSSL_PROGRAM=/usr/bin/openssl;OPENSSL_RUNTIME_DIR=/usr/bin;OPENSSL_LIBRARY_DIR=/usr/lib/x86_64-linux-gnu;SOURCEDIR=/home/simon/vigenere;PERL5LIB=/home/simon/vigenere/t" _BACKTRACE_TRIPLES "/home/simon/vigenere/CMakeLists.txt;91;add_test;/home/simon/vigenere/CMakeLists.txt;0;")
subdirs("libprov")
