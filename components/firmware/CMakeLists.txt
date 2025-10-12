# Copyright 2024-2025 Morse Micro
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

function(add_mbin library fw section)
  generate_start_symbol(${fw} section_start_symbol)
  generate_end_symbol(${fw} section_end_symbol)
  get_filename_component(ftype ${fw} LAST_EXT)

  if(${ftype} EQUAL "bin")
    set(mbin_tool ${ZEPHYR_MORSEMICRO_MODULE_DIR}/tools/convert-bin-to-mbin.py)
    set(bin ${fw})
    get_filename_component(base_file ${bin} NAME)
    set(fw ${CMAKE_CURRENT_BINARY_DIR}/${base_file}.mbin)
    add_custom_command(
      OUTPUT ${fw}
      COMMAND
      ${mbin_tool}
      -s
      -o ${fw}
      ${bin}
      DEPENDS ${bin}
    )
  endif()

  get_filename_component(base_file ${fw} NAME)
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
    ${fw}
    ${base_file}.o
    DEPENDS ${fw}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  )
  add_custom_target(${section_binary} DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${base_file}.o)
  add_dependencies(${library} ${section_binary})
  target_link_libraries(${library} INTERFACE ${CMAKE_CURRENT_BINARY_DIR}/${base_file}.o)
endfunction()


set(bcf     ${CONFIG_WIFI_MORSE_BCF})
if(NOT EXISTS ${BLOB_DIR}/firmware/${bcf})
  message(FATAL_ERROR
  "Invalid BCF specified\n"
  "File must be present in ${BLOB_DIR}/firmware/")
  return()
endif()


add_library(firmware INTERFACE)
add_mbin(firmware ${BLOB_DIR}/firmware/${bcf} bcf)
if(CONFIG_DT_HAS_MORSE_MM8108_ENABLED)
  add_mbin(firmware ${BLOB_DIR}/firmware/mm8108b2-rl.mbin firmware)
else()
  add_mbin(firmware ${BLOB_DIR}/firmware/mm6108.mbin firmware)
endif()