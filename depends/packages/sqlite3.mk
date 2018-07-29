package=sqlite3
$(package)_version=3.24.0
$(package)_download_path=https://www.sqlite.org/2018
$(package)_file_name_noext=sqlite-amalgamation-3240000
$(package)_file_name=$($(package)_file_name_noext).zip
$(package)_sha256_hash=ad68c1216c3a474cf360c7581a4001e952515b3649342100f2d7ca7c8e313da6
$(package)_extract_cmds=mkdir -p $$($(package)_extract_dir) && echo "$$($(package)_sha256_hash)  $$($(package)_source)" > $$($(package)_extract_dir)/.$$($(package)_file_name).hash && $(build_SHA256SUM) -c $$($(package)_extract_dir)/.$$($(package)_file_name).hash && unzip -q $$($(package)_source) && mv $$($(package)_file_name_noext)/* ./ && rm -rf $$($(package)_file_name_noext)

define $(package)_build_cmds
  $($(package)_cc) $($(package)_cflags) -c sqlite3.c -o sqlite3.o && \
  $($(package)_ar) -r libsqlite3.a sqlite3.o
endef

define $(package)_stage_cmds
  mkdir -p $($(package)_staging_dir)/$(host_prefix)/include && \
  mkdir -p $($(package)_staging_dir)/$(host_prefix)/lib && \
  cp $($(package)_extract_dir)/sqlite3.h $($(package)_staging_dir)/$(host_prefix)/include/ && \
  cp $($(package)_extract_dir)/libsqlite3.a $($(package)_staging_dir)/$(host_prefix)/lib/
endef

