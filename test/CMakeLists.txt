idf_component_register(SRCS "test_node_key.c"
                    INCLUDE_DIRS "." ".." "../include"
                    REQUIRES unity mbedtls)

idf_component_get_property(unity unity COMPONENT_LIB)
target_link_libraries(${COMPONENT_LIB} INTERFACE ${unity})
