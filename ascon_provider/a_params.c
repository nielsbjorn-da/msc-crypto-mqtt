#include "/home/niels/Documents/msc-crypto-mqtt/ascon_provider/a_params.h"
int ascon_params_parse(const char *key)
{
    const char *p = key;
    switch (*p++) {
    case 'a':
    case 'A':
        switch (*p++) {
        case 'e':
        case 'E':
            switch (*p++) {
            case 'a':
            case 'A':
                switch (*p++) {
                case 'd':
                case 'D':
                    switch (*p++) {
                    case '\0':
                        return V_PARAM_aead;
                    }
                    break;
                }
                break;
            }
            break;
        case 'u':
        case 'U':
            switch (*p++) {
            case 't':
            case 'T':
                switch (*p++) {
                case 'h':
                case 'H':
                    switch (*p++) {
                    case 'o':
                    case 'O':
                        switch (*p++) {
                        case 'r':
                        case 'R':
                            switch (*p++) {
                            case '\0':
                                return V_PARAM_author;
                            }
                            break;
                        }
                        break;
                    }
                    break;
                }
                break;
            }
            break;
        }
        break;
    case 'b':
    case 'B':
        switch (*p++) {
        case 'l':
        case 'L':
            switch (*p++) {
            case 'o':
            case 'O':
                switch (*p++) {
                case 'c':
                case 'C':
                    switch (*p++) {
                    case 'k':
                    case 'K':
                        switch (*p++) {
                        case 's':
                        case 'S':
                            switch (*p++) {
                            case 'i':
                            case 'I':
                                switch (*p++) {
                                case 'z':
                                case 'Z':
                                    switch (*p++) {
                                    case 'e':
                                    case 'E':
                                        switch (*p++) {
                                        case '\0':
                                            return V_PARAM_blocksize;
                                        }
                                        break;
                                    }
                                    break;
                                }
                                break;
                            }
                            break;
                        }
                        break;
                    }
                    break;
                }
                break;
            }
            break;
        case 'u':
        case 'U':
            switch (*p++) {
            case 'i':
            case 'I':
                switch (*p++) {
                case 'l':
                case 'L':
                    switch (*p++) {
                    case 'd':
                    case 'D':
                        switch (*p++) {
                        case 'i':
                        case 'I':
                            switch (*p++) {
                            case 'n':
                            case 'N':
                                switch (*p++) {
                                case 'f':
                                case 'F':
                                    switch (*p++) {
                                    case 'o':
                                    case 'O':
                                        switch (*p++) {
                                        case '\0':
                                            return V_PARAM_buildinfo;
                                        }
                                        break;
                                    }
                                    break;
                                }
                                break;
                            }
                            break;
                        }
                        break;
                    }
                    break;
                }
                break;
            }
            break;
        }
        break;
    case 'i':
    case 'I':
        switch (*p++) {
        case 'v':
        case 'V':
            switch (*p++) {
            case 'l':
            case 'L':
                switch (*p++) {
                case 'e':
                case 'E':
                    switch (*p++) {
                    case 'n':
                    case 'N':
                        switch (*p++) {
                        case '\0':
                            return V_PARAM_ivlen;
                        }
                        break;
                    }
                    break;
                }
                break;
            }
            break;
        }
        break;
    case 'k':
    case 'K':
        switch (*p++) {
        case 'e':
        case 'E':
            switch (*p++) {
            case 'y':
            case 'Y':
                switch (*p++) {
                case 'l':
                case 'L':
                    switch (*p++) {
                    case 'e':
                    case 'E':
                        switch (*p++) {
                        case 'n':
                        case 'N':
                            switch (*p++) {
                            case '\0':
                                return V_PARAM_keylen;
                            }
                            break;
                        }
                        break;
                    }
                    break;
                }
                break;
            }
            break;
        }
        break;
    case 'n':
    case 'N':
        switch (*p++) {
        case 'a':
        case 'A':
            switch (*p++) {
            case 'm':
            case 'M':
                switch (*p++) {
                case 'e':
                case 'E':
                    switch (*p++) {
                    case '\0':
                        return V_PARAM_name;
                    }
                    break;
                }
                break;
            }
            break;
        }
        break;
    case 's':
    case 'S':
        switch (*p++) {
        case 't':
        case 'T':
            switch (*p++) {
            case 'a':
            case 'A':
                switch (*p++) {
                case 't':
                case 'T':
                    switch (*p++) {
                    case 'u':
                    case 'U':
                        switch (*p++) {
                        case 's':
                        case 'S':
                            switch (*p++) {
                            case '\0':
                                return V_PARAM_status;
                            }
                            break;
                        }
                        break;
                    }
                    break;
                }
                break;
            }
            break;
        }
        break;
    case 't':
    case 'T':
        switch (*p++) {
        case 'a':
        case 'A':
            switch (*p++) {
            case 'g':
            case 'G':
                switch (*p++) {
                case '\0':
                    return V_PARAM_tag;
                case 'l':
                case 'L':
                    switch (*p++) {
                    case 'e':
                    case 'E':
                        switch (*p++) {
                        case 'n':
                        case 'N':
                            switch (*p++) {
                            case '\0':
                                return V_PARAM_taglen;
                            }
                            break;
                        }
                        break;
                    }
                    break;
                }
                break;
            }
            break;
        case 'l':
        case 'L':
            switch (*p++) {
            case 's':
            case 'S':
                switch (*p++) {
                case 'a':
                case 'A':
                    switch (*p++) {
                    case 'a':
                    case 'A':
                        switch (*p++) {
                        case 'd':
                        case 'D':
                            switch (*p++) {
                            case 'p':
                            case 'P':
                                switch (*p++) {
                                case 'a':
                                case 'A':
                                    switch (*p++) {
                                    case 'd':
                                    case 'D':
                                        switch (*p++) {
                                        case '\0':
                                            return V_PARAM_tlsaadpad;
                                        }
                                        break;
                                    }
                                    break;
                                }
                                break;
                            }
                            break;
                        }
                        break;
                    }
                    break;
                }
                break;
            }
            break;
        }
        break;
    case 'v':
    case 'V':
        switch (*p++) {
        case 'e':
        case 'E':
            switch (*p++) {
            case 'r':
            case 'R':
                switch (*p++) {
                case 's':
                case 'S':
                    switch (*p++) {
                    case 'i':
                    case 'I':
                        switch (*p++) {
                        case 'o':
                        case 'O':
                            switch (*p++) {
                            case 'n':
                            case 'N':
                                switch (*p++) {
                                case '\0':
                                    return V_PARAM_version;
                                }
                                break;
                            }
                            break;
                        }
                        break;
                    }
                    break;
                }
                break;
            }
            break;
        }
        break;
    }
    return 0;
}
