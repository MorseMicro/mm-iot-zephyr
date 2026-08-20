#[[
extensions.cmake

Provides morsemicro_add_mangled_library(), a generic helper for merging a set
of static library targets into a single archive and then running the
Morse Micro symbol mangler over it, exposing the result as an IMPORTED
STATIC target.

Public entry point:
    morsemicro_add_mangled_library(...)

Supporting functions:
    morsemicro_get_toolchain_tool(...)
    morsemicro_load_protected_symbols(...)
    morsemicro_merge_static_libraries(...)
    morsemicro_mangle_symbols(...)
#]]

include_guard(GLOBAL)

# ------------------------------------------------------------------------
# morsemicro_get_toolchain_base(<output_var>)
#
# ------------------------------------------------------------------------
function (morsemicro_get_toolchain_base output_var)
  string(REGEX REPLACE "objcopy(\\.exe)?$" "" _base "${CMAKE_OBJCOPY}")
  set(${output_var}
      "${_base}"
      PARENT_SCOPE
  )
endfunction ()

# ------------------------------------------------------------------------
# morsemicro_get_toolchain_tool(<tool_name> <output_var>)
#
# Resolves the full path to a binutils-style tool (e.g. "ar", "ranlib")
# that lives alongside CMAKE_OBJCOPY.
#
#   morsemicro_get_toolchain_tool(ar AR_PATH)
# ------------------------------------------------------------------------
function (morsemicro_get_toolchain_tool tool_name output_var)
  morsemicro_get_toolchain_base(_toolchain_base)
  if (WIN32)
    set(_tool "${_toolchain_base}${tool_name}.exe")
  else ()
    set(_tool "${_toolchain_base}${tool_name}")
  endif ()
  set(${output_var}
      "${_tool}"
      PARENT_SCOPE
  )
endfunction ()

# ------------------------------------------------------------------------
# morsemicro_load_protected_symbols(
#     FILES <path1> <path2> ...
#     OUTPUT_VAR <var>
#     [EXTRA_SYMS <sym1> <sym2> ...]
#     [EXCLUDE_REGEX <regex1> <regex2> ...]
# )
#
# Reads one or more newline-separated symbol files, strips blank/comment
# lines (lines starting with '#'), appends any EXTRA_SYMS, applies any
# caller-supplied EXCLUDE_REGEX patterns, deduplicates, and outputs a
# plain list of symbol names (e.g. "foo;bar;baz").
# Suitable for passing straight to the PROTECTED_SYMS
# argument of morsemicro_add_mangled_library / morsemicro_mangle_symbols.
#
# ------------------------------------------------------------------------
function (morsemicro_load_protected_symbols)
  cmake_parse_arguments(ARG "" "OUTPUT_VAR" "FILES;EXTRA_SYMS;EXCLUDE_REGEX" ${ARGN})

  if (NOT ARG_FILES AND NOT ARG_EXTRA_SYMS)
    message(
      FATAL_ERROR
        "morsemicro_load_protected_symbols: at least one of FILES or EXTRA_SYMS is required"
    )
  endif ()
  if (NOT ARG_OUTPUT_VAR)
    message(FATAL_ERROR "morsemicro_load_protected_symbols: OUTPUT_VAR is required")
  endif ()

  set(_syms)
  foreach (_file IN LISTS ARG_FILES)
    if (NOT EXISTS "${_file}")
      message(FATAL_ERROR "morsemicro_load_protected_symbols: file not found: ${_file}")
    endif ()
    file(STRINGS "${_file}" _file_syms REGEX "^[^#]")
    list(TRANSFORM _file_syms STRIP)
    list(FILTER _file_syms EXCLUDE REGEX "^$")
    list(APPEND _syms ${_file_syms})
  endforeach ()

  list(APPEND _syms ${ARG_EXTRA_SYMS})

  foreach (_regex IN LISTS ARG_EXCLUDE_REGEX)
    set(_before ${_syms})
    list(FILTER _syms EXCLUDE REGEX "${_regex}")
    if (_before STREQUAL _syms)
      message(WARNING "morsemicro_load_protected_symbols: EXCLUDE_REGEX '${_regex}' "
                      "matched no symbols - check it's still correct"
      )
    endif ()
  endforeach ()

  list(REMOVE_DUPLICATES _syms)

  if (NOT _syms)
    message(WARNING "morsemicro_load_protected_symbols: resulting protected symbol list is empty")
  endif ()

  set(${ARG_OUTPUT_VAR}
      "${_syms}"
      PARENT_SCOPE
  )
endfunction ()

# ------------------------------------------------------------------------
# morsemicro_merge_static_libraries(
#     OUTPUT <merged_lib_path>
#     LIBS <lib_file1> <lib_file2> ...
#     [DEPENDS <target_or_file1> ...]
#     [WORKING_DIRECTORY <dir>]
# )
#
# Merges the given static library files into a single archive at OUTPUT
# using "ar -M", then runs ranlib on the result. LIBS can contain
# generator expressions such as $<TARGET_FILE:mylib>.
#
# This only emits an add_custom_command(OUTPUT ${OUTPUT} ...) - callers
# must add a target that depends on OUTPUT to actually build it.
# ------------------------------------------------------------------------
function (morsemicro_merge_static_libraries)
  cmake_parse_arguments(ARG "" "OUTPUT;WORKING_DIRECTORY" "LIBS;DEPENDS" ${ARGN})

  if (NOT ARG_OUTPUT)
    message(FATAL_ERROR "morsemicro_merge_static_libraries: OUTPUT is required")
  endif ()
  if (NOT ARG_LIBS)
    message(FATAL_ERROR "morsemicro_merge_static_libraries: LIBS is required")
  endif ()
  if (NOT ARG_WORKING_DIRECTORY)
    set(ARG_WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
  endif ()

  morsemicro_get_toolchain_tool(ar AR)
  morsemicro_get_toolchain_tool(ranlib RANLIB)

  add_custom_command(
    OUTPUT "${ARG_OUTPUT}"
    COMMAND "${CMAKE_COMMAND}" "-DAR=${AR}" "-DRANLIB=${RANLIB}" "-DOUTPUT=${ARG_OUTPUT}"
            "-DLIBS=${ARG_LIBS}" -P "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/merge_static_libs.cmake"
    WORKING_DIRECTORY "${ARG_WORKING_DIRECTORY}"
    DEPENDS ${ARG_DEPENDS}
    COMMENT "Merging ${ARG_LIBS} into ${ARG_OUTPUT}"
    VERBATIM
  )
endfunction ()

# ------------------------------------------------------------------------
# morsemicro_mangle_symbols(
#     INPUT <lib_path>
#     OUTPUT <mangled_lib_path>
#     MANGLER_SCRIPT <path to librarymangler.py>
#     [PROTECTED_SYMS <sym1> <sym2> ...]     # plain symbol names, e.g. from
#                                             # morsemicro_load_protected_symbols
#     [DEPENDS <target_or_file1> ...]
#     [WORKING_DIRECTORY <dir>]
# )
#
# Copies INPUT to OUTPUT (if they differ) and runs the mangler script on
# OUTPUT in place. Only emits an add_custom_command(OUTPUT ${OUTPUT} ...).
# ------------------------------------------------------------------------
function (morsemicro_mangle_symbols)
  cmake_parse_arguments(
    ARG "" "INPUT;OUTPUT;MANGLER_SCRIPT;WORKING_DIRECTORY" "PROTECTED_SYMS;DEPENDS" ${ARGN}
  )

  if (NOT ARG_INPUT)
    message(FATAL_ERROR "morsemicro_mangle_symbols: INPUT is required")
  endif ()
  if (NOT ARG_OUTPUT)
    message(FATAL_ERROR "morsemicro_mangle_symbols: OUTPUT is required")
  endif ()
  if (NOT ARG_MANGLER_SCRIPT)
    message(FATAL_ERROR "morsemicro_mangle_symbols: MANGLER_SCRIPT is required")
  endif ()
  if (NOT ARG_WORKING_DIRECTORY)
    set(ARG_WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
  endif ()
  if (NOT Python3_EXECUTABLE)
    find_package(
      Python3
      COMPONENTS Interpreter
      REQUIRED
    )
  endif ()

  morsemicro_get_toolchain_base(_toolchain_base)

  set(_protected_sym_flags)
  foreach (_sym IN LISTS ARG_PROTECTED_SYMS)
    list(APPEND _protected_sym_flags -p "${_sym}")
  endforeach ()

  set(_copy_commands)
  if (NOT ARG_INPUT STREQUAL ARG_OUTPUT)
    set(_copy_commands COMMAND "${CMAKE_COMMAND}" -E copy_if_different "${ARG_INPUT}"
                       "${ARG_OUTPUT}"
    )
  endif ()

  add_custom_command(
    OUTPUT "${ARG_OUTPUT}"
    COMMAND "${CMAKE_COMMAND}" -E echo "Mangling ${ARG_OUTPUT}" ${_copy_commands}
    COMMAND "${Python3_EXECUTABLE}" "${ARG_MANGLER_SCRIPT}" -t "${_toolchain_base}" -m
            "${ARG_WORKING_DIRECTORY}" ${_protected_sym_flags} "${ARG_OUTPUT}"
    WORKING_DIRECTORY "${ARG_WORKING_DIRECTORY}"
    DEPENDS "${ARG_INPUT}" ${ARG_DEPENDS}
    COMMENT "Mangling symbols in ${ARG_OUTPUT}"
  )
endfunction ()

# ------------------------------------------------------------------------
# morsemicro_add_mangled_library(
#     NAME <imported_target_name>
#     LIBS <target1> <target2> ...
#     [PROTECTED_SYMS <sym1> <sym2> ...]     # plain symbol names, e.g. from
#                                             # morsemicro_load_protected_symbols
#     [MANGLER_SCRIPT <path>]                # defaults to
#                                             #   ${MMIOT_ROOT}/framework/tools/buildsystem/librarymangler.py
#     [DEFS <def1> <def2> ...]
#     [INC <dir1> <dir2> ...]
#     [WORKING_DIRECTORY <dir>]              # defaults to CMAKE_CURRENT_BINARY_DIR
# )
#
# Top-level entry point. Merges LIBS into a single archive, mangles it,
# and creates an IMPORTED STATIC GLOBAL target called NAME wrapping the
# result, with DEFS/INC applied as INTERFACE properties.
#
# Use morsemicro_load_protected_symbols() to build the list of protected symbols
# from a file, combine multiple sources, or just hardcode a list, then pass it in
# via PROTECTED_SYMS.
#
# Example:
#   morsemicro_load_protected_symbols(
#       FILES "${MMIOT_ROOT}/framework/tools/metadata/protected_syms.txt"
#       OUTPUT_VAR _libmorse_protected_syms
#       EXCLUDE_REGEX "^mbedtls.*"
#   )
#   morsemicro_add_mangled_library(
#       NAME libmorse
#       LIBS morselib mmhostap mmmbedtls
#       PROTECTED_SYMS ${_libmorse_protected_syms}
#       DEFS ${DEFS}
#       INC ${INC}
#   )
# ------------------------------------------------------------------------
function (morsemicro_add_mangled_library)
  cmake_parse_arguments(
    ARG "" "NAME;MANGLER_SCRIPT;WORKING_DIRECTORY" "LIBS;PROTECTED_SYMS;DEFS;INC" ${ARGN}
  )

  if (NOT ARG_NAME)
    message(FATAL_ERROR "morsemicro_add_mangled_library: NAME is required")
  endif ()
  if (NOT ARG_LIBS)
    message(FATAL_ERROR "morsemicro_add_mangled_library: LIBS is required")
  endif ()
  if (NOT ARG_WORKING_DIRECTORY)
    set(ARG_WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
  endif ()
  if (NOT ARG_MANGLER_SCRIPT)
    if (NOT MMIOT_ROOT)
      message(FATAL_ERROR "morsemicro_add_mangled_library: MANGLER_SCRIPT was not given and "
                          "MMIOT_ROOT is not defined, so the default location can't be resolved"
      )
    endif ()
    set(ARG_MANGLER_SCRIPT "${MMIOT_ROOT}/framework/tools/buildsystem/librarymangler.py")
  endif ()

  set(_lib_files)
  foreach (_lib IN LISTS ARG_LIBS)
    list(APPEND _lib_files "$<TARGET_FILE:${_lib}>")
  endforeach ()

  set(_merged_path "${ARG_WORKING_DIRECTORY}/${ARG_NAME}.merged.a")
  morsemicro_merge_static_libraries(
    OUTPUT
    "${_merged_path}"
    LIBS
    ${_lib_files}
    DEPENDS
    ${ARG_LIBS}
    WORKING_DIRECTORY
    "${ARG_WORKING_DIRECTORY}"
  )

  set(_mangled_path "${ARG_WORKING_DIRECTORY}/${ARG_NAME}.a")
  morsemicro_mangle_symbols(
    INPUT
    "${_merged_path}"
    OUTPUT
    "${_mangled_path}"
    MANGLER_SCRIPT
    "${ARG_MANGLER_SCRIPT}"
    PROTECTED_SYMS
    ${ARG_PROTECTED_SYMS}
    DEPENDS
    ${ARG_LIBS}
    WORKING_DIRECTORY
    "${ARG_WORKING_DIRECTORY}"
  )

  add_custom_target(${ARG_NAME}_build ALL DEPENDS "${_mangled_path}")

  add_library(${ARG_NAME} STATIC IMPORTED GLOBAL)
  set_target_properties(${ARG_NAME} PROPERTIES IMPORTED_LOCATION "${_mangled_path}")

endfunction ()
