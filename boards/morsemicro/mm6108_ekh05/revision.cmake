set(BOARD_REVISIONS "v3")
if(NOT DEFINED BOARD_REVISION)
  set(BOARD_REVISION "v3")
else()
  if(NOT BOARD_REVISION IN_LIST BOARD_REVISIONS)
    message(FATAL_ERROR "${BOARD_REVISION} is not a valid revision for mm6108_ekh05. Accepted revisions: ${BOARD_REVISIONS}")
  endif()
endif()

