# grap
if(NOT "${MSVC}" AND NOT "${MSYS}")
  install(FILES grap.py
          RENAME grap 
          PERMISSIONS OWNER_EXECUTE OWNER_READ OWNER_WRITE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE 
          DESTINATION /usr/local/bin)
endif()
