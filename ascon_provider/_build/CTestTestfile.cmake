# CMake generated Testfile for 
# Source directory: /home/niels/Documents/msc-crypto-mqtt/ascon_provider
# Build directory: /home/niels/Documents/msc-crypto-mqtt/ascon_provider/_build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test([=[ascon]=] "/home/niels/Documents/msc-crypto-mqtt/ascon_provider/_build/test_ascon")
set_tests_properties([=[ascon]=] PROPERTIES  ENVIRONMENT "OPENSSL_MODULES=/home/niels/Documents/msc-crypto-mqtt/ascon_provider/_build;OPENSSL_PROGRAM=/usr/local/bin/openssl;OPENSSL_RUNTIME_DIR=/usr/local/bin;OPENSSL_LIBRARY_DIR=/usr/lib/x86_64-linux-gnu;SOURCEDIR=/home/niels/Documents/msc-crypto-mqtt/ascon_provider;PERL5LIB=/home/niels/Documents/msc-crypto-mqtt/ascon_provider/t" _BACKTRACE_TRIPLES "/home/niels/Documents/msc-crypto-mqtt/ascon_provider/CMakeLists.txt;57;add_test;/home/niels/Documents/msc-crypto-mqtt/ascon_provider/CMakeLists.txt;0;")
add_test([=[ascon_err]=] "/home/niels/Documents/msc-crypto-mqtt/ascon_provider/_build/test_ascon_err")
set_tests_properties([=[ascon_err]=] PROPERTIES  ENVIRONMENT "OPENSSL_MODULES=/home/niels/Documents/msc-crypto-mqtt/ascon_provider/_build;OPENSSL_PROGRAM=/usr/local/bin/openssl;OPENSSL_RUNTIME_DIR=/usr/local/bin;OPENSSL_LIBRARY_DIR=/usr/lib/x86_64-linux-gnu;SOURCEDIR=/home/niels/Documents/msc-crypto-mqtt/ascon_provider;PERL5LIB=/home/niels/Documents/msc-crypto-mqtt/ascon_provider/t" _BACKTRACE_TRIPLES "/home/niels/Documents/msc-crypto-mqtt/ascon_provider/CMakeLists.txt;69;add_test;/home/niels/Documents/msc-crypto-mqtt/ascon_provider/CMakeLists.txt;0;")
add_test([=[openssl]=] "prove" "-PWrapOpenSSL" "/home/niels/Documents/msc-crypto-mqtt/ascon_provider/t")
set_tests_properties([=[openssl]=] PROPERTIES  ENVIRONMENT "OPENSSL_MODULES=/home/niels/Documents/msc-crypto-mqtt/ascon_provider/_build;OPENSSL_PROGRAM=/usr/local/bin/openssl;OPENSSL_RUNTIME_DIR=/usr/local/bin;OPENSSL_LIBRARY_DIR=/usr/lib/x86_64-linux-gnu;SOURCEDIR=/home/niels/Documents/msc-crypto-mqtt/ascon_provider;PERL5LIB=/home/niels/Documents/msc-crypto-mqtt/ascon_provider/t" _BACKTRACE_TRIPLES "/home/niels/Documents/msc-crypto-mqtt/ascon_provider/CMakeLists.txt;94;add_test;/home/niels/Documents/msc-crypto-mqtt/ascon_provider/CMakeLists.txt;0;")
subdirs("libprov")
