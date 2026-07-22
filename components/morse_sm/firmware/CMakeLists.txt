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
  get_filename_component(ftype ${fw} LAST_EXT)

  if(${ftype} STREQUAL ".bin")
    set(mbin_tool ${ZEPHYR_CURRENT_MODULE_DIR}/tools/convert-bin-to-mbin.py)
    set(bin ${fw})
    get_filename_component(base_file ${bin} NAME)
    set(fw ${CMAKE_CURRENT_BINARY_DIR}/${base_file}.mbin)
    add_custom_command(
      OUTPUT ${fw}
      COMMAND
      ${mbin_tool}
      -o ${fw}
      ${bin}
      DEPENDS ${bin}
    )
  endif()

  generate_start_symbol(${fw} section_start_symbol)
  generate_end_symbol(${fw} section_end_symbol)

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


if(CONFIG_DT_HAS_MORSEMICRO_MM8108_ENABLED)
  set(morse_sm_chip mm8108)
  dt_comp_path(morse_sm_path COMPATIBLE "morsemicro,mm8108" INDEX 0)
else()
  set(morse_sm_chip mm6108)
  dt_comp_path(morse_sm_path COMPATIBLE "morsemicro,mm6108" INDEX 0)
endif()
dt_prop(bcf PATH "${morse_sm_path}" PROPERTY "bcf" REQUIRED)

if(EXISTS ${MMIOT_ROOT}/framework/morsefirmware/mm6108/bcfs/${bcf})
  set(bcf_path ${MMIOT_ROOT}/framework/morsefirmware/mm6108/bcfs/${bcf})
elseif(EXISTS ${MMIOT_ROOT}/framework/morsefirmware/mm8108/bcfs/${bcf})
  set(bcf_path ${MMIOT_ROOT}/framework/morsefirmware/mm8108/bcfs/${bcf})
else()
  message(FATAL_ERROR
  "Invalid BCF specified\n"
  "File must be present in ${MMIOT_ROOT}/framework/morsefirmware/")
  return()
endif()

# Regulatory regions support is dictated by the BCF
# Also pass the chip to verify that it matches the BCF
execute_process(
  COMMAND ${PYTHON_EXECUTABLE} ${ZEPHYR_CURRENT_MODULE_DIR}/scripts/bcf_info.py
    ${bcf_path}
    --chip ${morse_sm_chip}
  OUTPUT_VARIABLE REGIONS
  ERROR_VARIABLE bcf_info_error
  OUTPUT_STRIP_TRAILING_WHITESPACE
  RESULT_VARIABLE bcf_info_result
)

if(NOT bcf_info_result EQUAL 0)
  message(FATAL_ERROR "${bcf_info_error}")
  return()
endif()

if(NOT CONFIG_WIFI_MORSE_REGION STREQUAL "00" AND NOT CONFIG_WIFI_MORSE_REGION IN_LIST REGIONS)
  string(REPLACE ";" ", " regions_str "${REGIONS}")
  message(FATAL_ERROR
  "Invalid/unsupported region specified for regulatory domain\n"
  "CONFIG_WIFI_MORSE_REGION must be \"00\" (application configures region via wifi_mgmt) or one of"
  "the regions supported by the bcf (${bcf}):\n"
  "${regions_str}")
  return()
endif()

add_library(firmware INTERFACE)
if(CONFIG_DT_HAS_MORSEMICRO_MM8108_ENABLED)
  add_mbin(firmware ${MMIOT_ROOT}/framework/morsefirmware/mm8108b2-rl.mbin firmware)
else()
  add_mbin(firmware ${MMIOT_ROOT}/framework/morsefirmware/mm6108.mbin firmware)
endif()
add_mbin(firmware ${bcf_path} bcf)
