package=sqlite3
$(package)_version=3.24.0
$(package)_download_path=https://www.sqlite.org/2018
$(package)_file_name=sqlite-autoconf-3240000.tar.gz
$(package)_sha256_hash=d9d14e88c6fb6d68de9ca0d1f9797477d82fc3aed613558f87ffbdbbc5ceb74a

define $(package)_config_cmds
  ./configure --prefix=$(host_prefix)
endef

define $(package)_build_cmds
  $($(package)_cc) $($(package)_cflags) -c sqlite3.c -o sqlite3.o -fPIC && \
  $($(package)_ar) -r libsqlite3.a sqlite3.o
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef
