# Copyright 2024 Morse Micro
# SPDX-License-Identifier: Apache-2.0

get_property(OUTPUT_FORMAT GLOBAL PROPERTY PROPERTY_OUTPUT_FORMAT)

function(generate_start_symbol filename output_variable)
  string(REPLACE "/" "_" temp "${filename}")
  string(REPLACE ":" "_" temp "${temp}")
  string(REPLACE "-" "_" temp "${temp}")
  string(REPLACE "." "_" temp "${temp}")
  set(${output_variable} "_binary_${temp}_start" PARENT_SCOPE)
endfunction()

# Helper function to generate the _end symbol name
function(generate_end_symbol filename output_variable)
  string(REPLACE "/" "_" temp "${filename}")
  string(REPLACE ":" "_" temp "${temp}")
  string(REPLACE "-" "_" temp "${temp}")
  string(REPLACE "." "_" temp "${temp}")
  set(${output_variable} "_binary_${temp}_end" PARENT_SCOPE)
endfunction()

function(add_mbin library mbin section)
  generate_start_symbol(${mbin} section_start_symbol)
  generate_end_symbol(${mbin} section_end_symbol)

  get_filename_component(base_file ${mbin} NAME)
  set(section_binary ${section}_binary)
  add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${base_file}.o
    COMMAND
    ${CMAKE_OBJCOPY}
    -I binary
    -O ${OUTPUT_FORMAT}
    --redefine-sym ${section_start_symbol}=${section}_binary_start
    --redefine-sym ${section_end_symbol}=${section}_binary_end
    --rename-section .data=.rodata,contents,alloc,load,readonly,data
    ${mbin}
    ${base_file}.o
    DEPENDS ${mbin}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  )
  add_custom_target(${section_binary} DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${base_file}.o)
  add_dependencies(${library} ${section_binary})
  target_link_libraries(${library} INTERFACE ${CMAKE_CURRENT_BINARY_DIR}/${base_file}.o)
endfunction()

if(CONFIG_WIFI_MORSE_BCF_MF08651_US)
  set(bcf     bcf_mf08651_us.mbin)
elseif(CONFIG_WIFI_MORSE_BCF_MF08551)
  set(bcf     bcf_mf08551.mbin)
elseif(CONFIG_WIFI_MORSE_BCF_MF08251)
  set(bcf     bcf_mf08251.mbin)
endif()


add_library(firmware INTERFACE)
add_mbin(firmware ${BLOB_DIR}/firmware/${bcf} bcf)
add_mbin(firmware ${BLOB_DIR}/firmware/mm6108.mbin firmware)