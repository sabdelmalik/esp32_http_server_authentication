idf_component_register( SRCS  "http_digest_authentication.c" 
                              "http_basic_authentication.c" 
                              "http_authentication_common.c"
                              "base64_encoding.c"
                        INCLUDE_DIRS "." "./include"
                        REQUIRES esp_http_server mbedtls)
