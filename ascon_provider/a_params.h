#define S_PARAM_aead "aead"
#define V_PARAM_aead 1
#define S_PARAM_author "author"
#define V_PARAM_author 2
#define S_PARAM_blocksize "blocksize"
#define V_PARAM_blocksize 3
#define S_PARAM_buildinfo "buildinfo"
#define V_PARAM_buildinfo 4
#define S_PARAM_ivlen "ivlen"
#define V_PARAM_ivlen 5
#define S_PARAM_keylen "keylen"
#define V_PARAM_keylen 6
#define S_PARAM_name "name"
#define V_PARAM_name 7
#define S_PARAM_status "status"
#define V_PARAM_status 8
#define S_PARAM_tag "tag"
#define V_PARAM_tag 9
#define S_PARAM_taglen "taglen"
#define V_PARAM_taglen 10
#define S_PARAM_tlsaadpad "tlsaadpad"
#define V_PARAM_tlsaadpad 11
#define S_PARAM_version "version"
#define V_PARAM_version 12

int ascon_params_parse(const char *key);
