# Copyright 2024-2026 Morse Micro
# SPDX-License-Identifier: Apache-2.0

get_property(OUTPUT_FORMAT GLOBAL PROPERTY PROPERTY_OUTPUT_FORMAT)

# Search paths for the FW and BCF
set(bcf_paths
  "${MMIOT_ROOT}/framework/morsefirmware"
  "${MMFW_ROOT}/bcf"
)

set(fw_paths
  "${MMIOT_ROOT}/framework/morsefirmware"
)

# search_paths is a CMake list (semicolon-separated) of directories to search in
# the first path to contain a 'fuzzy' match is then used
# if the file found is a bin instead of the required mbin it is then converted
function(find_mbin out_var file_name search_paths)
  get_filename_component(req_dir  "${file_name}" DIRECTORY)
  get_filename_component(req_name "${file_name}" NAME)
  string(REGEX REPLACE "\\.(bin|mbin)$" "" base "${req_name}")

  # Candidate filenames, (user > mbin > bin).
  if(req_name MATCHES "\\.bin$")
    set(exts bin mbin)
  else()
    set(exts mbin bin)
  endif()
  list(GET exts 0 preferred_ext)
  set(candidates "")
  foreach(ext IN LISTS exts)
    list(APPEND candidates "${base}.${ext}")
  endforeach()

  set(found "")

  foreach(cand IN LISTS candidates)
    if(req_dir)
      set(rel "${req_dir}/${cand}")
    else()
      set(rel "${cand}")
    endif()
    get_filename_component(abs "${rel}" ABSOLUTE BASE_DIR "${APPLICATION_SOURCE_DIR}")
    if(EXISTS "${abs}" AND NOT IS_DIRECTORY "${abs}")
      set(found "${abs}")
      break()
    endif()
  endforeach()

  if(NOT found)
    foreach(search_path IN LISTS search_paths)

      foreach(cand IN LISTS candidates)

        file(GLOB_RECURSE matches LIST_DIRECTORIES false "${search_path}/${cand}")
        if(matches)
          list(LENGTH matches n)
          if(n GREATER 1)
            message(WARNING "Multiple matches for '${cand}' under ${search_path}:\n"
              "  ${matches}\n"
              "Using the first one.")
          endif()
          list(GET matches 0 found)
          break()
        endif()
      endforeach()
      if(found)
        break()
      endif()
    endforeach()
  endif()

  if(NOT found)
    set(${out_var} "" PARENT_SCOPE)
    return()
  endif()

  get_filename_component(found_ext "${found}" LAST_EXT)
  if(NOT found_ext STREQUAL ".${preferred_ext}")
    message(WARNING "${out_var}: exact match not found, "
      "substituted '${found}' for requested '${base}.${preferred_ext}'")
  endif()
  message(STATUS "${out_var}: ${found}")

  if(${found_ext} STREQUAL ".bin")
    set(mbin_tool ${MMIOT_ROOT}/framework/tools/buildsystem/convert-bin-to-mbin.py)
    set(bin ${found})
    get_filename_component(base_file ${bin} NAME)
    set(conv ${CMAKE_CURRENT_BINARY_DIR}/${base}.mbin)
    execute_process(
      COMMAND
      ${PYTHON_EXECUTABLE}
      ${mbin_tool}
      -t 1,2:2
      -o ${conv}
      ${bin}
      RESULT_VARIABLE convert_result
      ERROR_VARIABLE convert_error
    )
    if(NOT convert_result EQUAL 0 OR NOT EXISTS "${conv}")
      message(FATAL_ERROR
        "Failed to convert '${bin}' to mbin${convert_error}\n"
      )
    endif()
    set(found ${conv})
  endif()

  set(${out_var} "${found}" PARENT_SCOPE)
endfunction()

function(compress_mbin input output)
  add_custom_command(
    OUTPUT "${output}"
    COMMAND "${PYTHON_EXECUTABLE}"
      "${ZEPHYR_CURRENT_MODULE_DIR}/scripts/compress-mbin.py"
      -o "${output}" "${input}"
    DEPENDS "${input}" "${ZEPHYR_CURRENT_MODULE_DIR}/scripts/compress-mbin.py"
    VERBATIM
  )
endfunction()

if(CONFIG_DT_HAS_MORSEMICRO_MM8108_ENABLED)
  set(chip_type mm8108)
  set(fw_file "mm8108b2-rl.mbin")
  dt_comp_path(morse_sm_path COMPATIBLE "morsemicro,mm8108" INDEX 0)
elseif(CONFIG_DT_HAS_MORSEMICRO_MM6108_ENABLED)
  set(chip_type mm6108)
  set(fw_file "mm6108.mbin")
  dt_comp_path(morse_sm_path COMPATIBLE "morsemicro,mm6108" INDEX 0)
else()
endif()
dt_prop(bcf PATH "${morse_sm_path}" PROPERTY "bcf" REQUIRED)

get_filename_component(bcf_name "${bcf}" NAME)

find_mbin(fw "${fw_file}" "${fw_paths}")
find_mbin(bcf "${bcf}" "${bcf_paths}")

if(fw STREQUAL "")
  message(FATAL_ERROR
    "Morse Micro firmware for the ${chip_type} was not found\n"
    "Check that submodules exist and are up to date"
  )
  return ()
endif()

if(CONFIG_MORSEMICRO_COMPRESS_FIRMWARE)
  set(fw_processed "${CMAKE_CURRENT_BINARY_DIR}/morsemicro_firmware_compressed.mbin")
  compress_mbin("${fw}" "${fw_processed}")
else()
  set(fw_processed "${fw}")
endif()

if(bcf STREQUAL "")
  message(FATAL_ERROR
    "BCF (${bcf}) was not found\n"
    "Check that submodules exist and are up to date"
  )
  return ()
endif()

# Regulatory regions support is dictated by the BCF
# Pull the supported regions from the BCF
execute_process(
  COMMAND ${PYTHON_EXECUTABLE} ${ZEPHYR_CURRENT_MODULE_DIR}/scripts/bcf_info.py
  ${bcf}
  --chip ${chip_type}
  OUTPUT_VARIABLE regions
  ERROR_VARIABLE bcf_info_error
  OUTPUT_STRIP_TRAILING_WHITESPACE
  RESULT_VARIABLE bcf_info_result
)

if(NOT bcf_info_result EQUAL 0)
  message(FATAL_ERROR "${bcf_info_error}")
  return()
endif()

if(NOT CONFIG_WIFI_MORSE_REGION STREQUAL "00" AND NOT CONFIG_WIFI_MORSE_REGION IN_LIST regions)
  string(REPLACE ";" ", " regions_str "${regions}")
  message(FATAL_ERROR
    "Invalid/unsupported region specified for regulatory domain\n"
    "CONFIG_WIFI_MORSE_REGION must be \"00\" (application configures region via wifi_mgmt) or one of "
    "the regions supported by the bcf (${bcf_name}):\n"
    "${regions_str}")
  return()
endif()

# Set the region list so that it can be written to the device image for runtime validation

string(REPLACE ";" "" bcf_regions_flat "${regions}")
set(bcf_regions_path ${CMAKE_CURRENT_BINARY_DIR}/morsemicro_bcf_regions.raw)
file(WRITE ${bcf_regions_path} "${bcf_regions_flat}")

# Add the binary data

add_library(firmware INTERFACE)
target_include_directories(firmware INTERFACE "${CMAKE_CURRENT_BINARY_DIR}")

generate_inc_file_for_target(
  firmware
  "${fw_processed}"
  "${CMAKE_CURRENT_BINARY_DIR}/morsemicro_firmware.inc"
)
generate_inc_file_for_target(
  firmware
  "${bcf}"
  "${CMAKE_CURRENT_BINARY_DIR}/morsemicro_bcf.inc"
)
generate_inc_file_for_gen_target(
  firmware
  "${bcf_regions_path}"
  "${CMAKE_CURRENT_BINARY_DIR}/morsemicro_bcf_regions.inc"
  bcf
)
