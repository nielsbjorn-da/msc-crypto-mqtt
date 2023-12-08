# msc-crypto-mqtt
Candidate project: Simon and Niels, Advisor: Diego

# MQTT architecture designs:
<ol> 
 <li>Trusted broker
<ol>
      <li>Design A</li>
      <li>Design B</li>
    </ol>
</li>
  <li>Semi-honest broker / trusted-but-curious</li>
  <li>Malicious broker </li></ol>


# Project installation guide:
## Download repository from Git:  
1. git clone https://github.com/nielsbjorn-da/msc-crypto-mqtt.git  

## Installation openssl on pi:  
1. cd msc-crypto-mqtt/openssl-3.2.0  
2. ./Configure linux-armv4 
3. make  
4. Navigate to openssl-3.2.0/include/openssl/ssl.h  
5. in ssl.h paste: 
\# define SSL_TXT_ASCON80PQ "ASCON80PQ"  
\# define SSL_TXT_ASCON128 "ASCON128"  
\# define SSL_TXT_ASCON128A "ASCON128A"  

under:  
\# define SSL_TXT_CBC "CBC"  
around line 151.  
7. Navigate back to openssl-3.2.0  
8. make  
9. sudo make install  

## Ascon on pi:  
1. navigate to ascon_provider  
2. cmake -S . -B _build/  
3. cmake --build _build/ 
4. sudo cp _build/asconprovider.so /usr/local/lib/ossl-modules/   


## OQS:
1. navigate to oqs-provider  
2. ./scripts/fullbuild.sh -F  
3. sudo cmake --install _build  

## Openssl.cnf:
1. sudo vim /usr/local/ssl/openssl.cnf  
2. Inset this configuration

[provider_sect]  
default = default_sect  
oqsprovider = oqsprovider_sect  
asconprovider = asconprovider_sect  
  
[default_sect]  
activate = 1  
  
[oqsprovider_sect]  
activate = 1  
  
[asconprovider_sect]  
activate = 1  
  
[openssl_init]  
ssl_conf = ssl_sect  
  
[ssl_sect]  
system_default = system_default_sect  
  
[system_default_sect]  
Ciphersuites = TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384:TLS_AES_128_CCM_8_SHA256:TLS_AES_128_CCM_SHA256:TLS_AES_128_GCM_SHA256:TLS_AES_128_GCM_SHA384:TLS_ASCON_80PQ_SHA256:TLS_ASCON_128_SHA256:TLS_ASCON_128A_SHA256  
Groups = kyber512:p256_kyber512:x25519_kyber512:kyber768:p384_kyber768:x448_kyber768:x25519_kyber768:p256_kyber768:kyber1024:p521_kyber1024:secp256r1:secp384r1:secp521r1:X25519:X448  
  
## MQTT:
1. cd msc-crypto-mqtt/trusted_broker/Design_A/mosquitto_code/mosquitto/client/dilithium_and_falcon/dilithium/dilithium-master/ref  
2. make  
3. make shared  
4. cd msc-crypto-mqtt/trusted_broker/Design_A/mosquitto_code/mosquitto/client/dilithium_and_falcon/falcon/Falcon-impl-20211101/  
5. make  
6. cd msc-crypto-mqtt/trusted_broker/Design_A/mosquitto_code/mosquitto/client/  
7. make  
8. cd msc-crypto-mqtt/trusted_broker/Design_A/mosquitto_code/mosquitto/src/  
9. make  

