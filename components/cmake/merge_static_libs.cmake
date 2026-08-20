# Copyright 2026 Morse Micro
# SPDX-License-Identifier: Apache-2.0

# To support Zephyr 4.4.x, we need to support CMake 3.20. The next Zephyr version requires CMake 3.28
# so at that point we could leverage the $<PATH:RELATIVE_PATH,...> generator expression instead, and
# Remove this file entirely.
# This exists to support twister and paths which end up with @ symbols.

# -DAR=... -DRANLIB=... -DOUTPUT=... -DLIBS=lib1;lib2;... -P merge_static_libs.cmake

get_filename_component(_dir "${OUTPUT}" DIRECTORY)
file(RELATIVE_PATH _output_rel "${_dir}" "${OUTPUT}")

set(_mri "CREATE ${_output_rel}\n")
foreach (_lib IN LISTS LIBS)
  file(RELATIVE_PATH _lib_rel "${_dir}" "${_lib}")
  string(APPEND _mri "ADDLIB ${_lib_rel}\n")
endforeach ()
string(APPEND _mri "SAVE\nEND\n")

set(_mri_file "${_dir}/merge.mri")
file(WRITE "${_mri_file}" "${_mri}")

execute_process(
  COMMAND "${AR}" -M
  INPUT_FILE "${_mri_file}"
  WORKING_DIRECTORY "${_dir}"
  RESULT_VARIABLE r
)
if (NOT r EQUAL 0)
  message(FATAL_ERROR "ar -M failed with exit code ${r}")
endif ()
execute_process(COMMAND "${RANLIB}" "${OUTPUT}" RESULT_VARIABLE r)
if (NOT r EQUAL 0)
  message(FATAL_ERROR "ranlib failed with exit code ${r}")
endif ()
