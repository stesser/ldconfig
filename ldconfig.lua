#!/usr/libexec/flua

--[[
SPDX-License-Identifier: BSD-2-Clause

Copyright (c) 2024 Stefan Eßer

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:
1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
SUCH DAMAGE.
--]]

local lfs = require("lfs")

local PATH_ELF_HINTS = "/var/run/ld-elf.so.hints"
local PATH_ELF32_HINTS = "/var/run/ld-elf32.so.hints"

local HINTSMAGIC = 1953392709
local MAXFILESIZE = 16 * 1024

local endianness
local insecure
local do_merge
local do_report
local do_rescan

local COMPAT_DIRS

-- print abort or usage message
local function abort(msg)
   local program = string.match(arg[0], "[^/]+$")
   print (program .. ": " .. msg)
   os.exit(1)
end

-- print usage message optionally with failed option character
local function usage(erropt)
   local program = string.match(arg[0], "[^/]+$")
   if erropt then
      print("illegal option -- " .. erropt)
   end
   print("usage: " .. program .. " [-32] [-elf] [-BRimrv] [-f hints_file] [directory | file ...]")
   os.exit(1)
end

-- return a table of compat library backup directories
local function get_compat_dirs()
   local compat_dirs = { -- should use sysctl("user.compatlibs_path")
      "/usr/local/lib/compat/pkg",
      --"usr/local/lib32/compat",
   }
   local compatdir_table = {}
   for i = 1, #compat_dirs do
      compatdir_table[compat_dirs[i]] = i
   end
   return compatdir_table
end

-- return position of a directory in the compat directory table
local function compat_path_idx(dir, trusted)
   if not COMPAT_DIRS then
      if not trusted then
	 COMPAT_DIRS = get_compat_dirs()
      else
	 COMPAT_DIRS = {}
      end
   end
   return COMPAT_DIRS[dir] or -1
end

-- return position where to insert new search path entry
local function insert_at(dirs, name, trusted)
   local pos = #dirs + 1
   local compat_idx = compat_path_idx(name, trusted)
   for i = 1, #dirs do
      if name == dirs[i] then
	 return
      end
   --[[
      if compat_idx < compat_path_idx(dirs[i], trusted) then
	 pos = pos - 1
      end
   --]]
   end
   return pos
end

-- check library directory ownership and permissions
local function validate_dir(name)
   local attr, errmsg = lfs.attributes(name)
   if attr then
      local mode = tonumber(attr.permissions, 8)
      if attr.uid ~= 0 then
	 errmsg = "ignoring directory not owned by root"
      elseif mode & 2 ~= 0 then
	 errmsg = "ignoring world-writable directory"
      elseif mode & (2 << 3) ~= 0 then
	 errmsg = "ignoring group-writable directory"
      else
	 errmsg = nil
      end
   end
   if errmsg then
      return nil, name .. ": " .. errmsg
   else
      return true
   end
end

-- add library directory to the search path
local function add_dir(dirs, name, trusted)
   -- Do some security checks
   if not trusted and not insecure then
      local secure, errmsg = validate_dir(name)
      if not secure then
	 print(errmsg .. ": " .. name)
	 return
      end
   end
   local pos = insert_at(dirs, name, trusted)
   if pos then
      table.insert(dirs, pos, name)
   end
end

-- return table with full pathnames of all files with names like "libc.so.1" in dirs
local function all_libs(dirs)
   local libs = {}
   for _, dir in ipairs(dirs) do
      for name in lfs.dir(dir) do
	 if string.match(name, ".*%.so.[%d]+$") then
	    libs[#libs+1] = dir .. "/" .. name
	 end
      end
   end
   return libs
end

-- parse hintsfile header and return path and detected endianness
local function parse_hdr(data)
   local file_endianness
   local magic, version, strtab, strsize, dirlist, dirlistlen =
      string.unpack("<I4 I4 I4 I4 I4 I4", data)
   if magic == HINTSMAGIC then
      file_endianness = "<"
   else
      magic, version, strtab, strsize, dirlist, dirlistlen =
	 string.unpack(">I4 I4 I4 I4 I4 I4", data)
      if magic == HINTSMAGIC then
	 file_endianness = ">"
      else
	 return nil, "bad magic number"
      end
   end
   if endianness and file_endianness and endianness ~= file_endianness then
      return nil, "conflicting endianness requested"
   end
   endianness = file_endianness
   if version ~= 1 then
      return nil, "invalid hints file version " .. version
   end
   local offset = strtab + dirlist
   return string.sub(data, offset + 1, offset + dirlistlen)
end

-- parse the hints file header with automatic endianness detection
local function add_hints_dirs(data)
   local path, errmsg = parse_hdr(data)
   if not path then
      return nil, errmsg
   end
   local dirs = {}
   for dir in string.gmatch(path, "([^:]+):?") do
      add_dir(dirs, dir, true)
   end
   return dirs
end

-- read hints from file and return dirs and endianness
local function readhints(filename, must_exist)
   local hintsfile = io.open(filename, "rb")
   if hintsfile then
      local data = hintsfile:read("a")
      hintsfile:close()
      return add_hints_dirs(data)
   elseif must_exist then
      return nil, filename .. " not found"
   else
      return {}
   end
end

-- check existence, permissions(?), and size of the hints file
local function validate_hintsfile(hintsfile)
   local attr, errmsg = lfs.attributes(hintsfile)
   if errmsg then
      return nil, errmsg
   end
   if attr.size > MAXFILESIZE then
      return nil, "file is unreasonably large (" .. attr.size .. " bytes)"
   end
   return true
end

-- fetch list of library directories from hints file
local function read_elf_hints(hintsfile, must_exist)
   local valid, errmsg = validate_hintsfile(hintsfile)
   if valid then
      dirs, errmsg = readhints(hintsfile, must_exist)
   end
   if errmsg then
      return nil, errmsg
   end
   return dirs
end

-- generate the data to write to a new hints file
local function generatehints(dirs)
   local path = table.concat(dirs, ":")
   local magic = HINTSMAGIC
   local version = 1
   local strtab = 128
   local strsize = #path + 1
   local dirlist = 0
   local dirlistlen = #path
   endianness = endianness or ""
   local hdr = string.pack(endianness .. "I4 I4 I4 I4 I4 I4",
			   magic, version, strtab, strsize, dirlist, dirlistlen)
   hdr = hdr .. string.rep("\000", strtab - #hdr) .. path .. "\000"
   return hdr
end

-- write a new hints file via a temporary file
local function write_elf_hints(hintsfile, dirs)
   local tmpname = os.tmpname()
   local destdir = string.match(hintsfile, "^(.*)/")
   tmpname = destdir .. "/" .. string.match(tmpname, "[^/]+$")
   local fb = io.open(tmpname, "w")
   if not fb then
      return nil, "failed to open output file " .. hintsfile
   else
      fb:write(generatehints(dirs))
      fb:close()
      if not os.rename(tmpname, hintsfile) then
	 return nil, "failed to open output file " .. hintsfile
      end
   end
   return true
end

-- read a list of directories from a file
local function read_dirs_from_file(dirs, listfile)
   local fp = io.open(listfile, "r")
   if not fp then
      abort("file not found: " .. listfile)
   end
   local linenum = 0
   for buf in fp:read("l") do
      linenum = linenum + 1
      local dir, rest = string.match(buf, "%s*([^#]%S+)%s*(.*)")
      if dir and #dir > 0 then
	 if rest then
	    print(listfile .. ":" .. linenum .. ": trailing characters ignored")
	 end
	 add_dir(dirs, dir, false);
      end
   end
   fp:close()
end

-- update hints file
local function update_elf_hints(hintsfile, newdirs)
   local dirs = {}
   if do_merge then
      dirs = read_elf_hints(hintsfile, false);
   end
   for _, dir in ipairs(newdirs) do
      local attr, errmsg = lfs.attributes(dir)
      if not attr then
	 print("warning: " .. dir .. ": " .. errmsg)
      elseif attr.mode == "file" then
	 read_dirs_from_file(dirs, dir)
      else
	 add_dir(dirs, dir, false);
      end
   end
   local success, errmsg = write_elf_hints(hintsfile, dirs)
   if not success then
      abort(errmsg)
   end
end

-- list all directories in search order
local function list_elf_hints(hintsfile)
   local dirs, errmsg = readhints(hintsfile)
   if not dirs then
      abort(errmsg)
   end
   print (hintsfile .. ":")
   print ("\tsearch directories: " .. table.concat(dirs, ":"))
   local lcount = 0
   for _, lib in ipairs(all_libs(dirs)) do
      local lopt, version = string.match(lib, ".*/lib([^/]+).so.(%d+)")
      if lopt and version then
	 print ("\t" .. tostring(lcount) .. ":-l" .. lopt .. "." .. version .. " => " .. lib)
	 lcount = lcount + 1
      end
   end
end

-- parse command options and arguments
local function parse_opts (simpleopts, argopts, longopts)
   local opt = {}

   local i = 1
   while i <= #arg do
      local optarg = arg[i]
      if string.sub(optarg, 1, 1) == "-" then
	 local optchars = string.sub(optarg, 2)
	 for _, longopt in ipairs(longopts or {}) do
	    if optchars == longopt then
	       opt[longopt] = true
	       optchars = ""
	       break
	    end
	 end
	 if optchars ~= "" then
	    local optchar, optval
	    repeat
	       optchar = string.match(optchars, "^[" .. simpleopts .. "]")
	       if not optchar then
		  break
	       end
	       opt[optchar] = true
	       optchars = string.sub(optchars, 2)
	    until optchar == ""
	    if optchars ~= "" then
	       optchar, optval = string.match(optchars, "^([" .. argopts .. "])(.*)")
	       if optval == "" then
		  if #arg > i then
		     i = i + 1
		     optval = arg[i]
		  end
	       end
	       if optval == "" then
		  usage()
		  os.exit(1)
	       elseif optchar then
		  opt[optchar] = optval
		  optchars = ""
	       end
	       if optchars ~= "" then
		  usage(string.sub(optchars, 1, 1))
		  os.exit(1)
	       end
	    end
	 end
      else
	 for i = i, #arg do
	    opt[#opt + 1] = arg[i]
	 end
	 break
      end
      i = i + 1
   end
   return opt
end

-- main program
local opt = parse_opts("BRimrv", "f", {"32", "elf"})

do_merge = opt.m
do_report = opt.r
do_rescan = opt.R or #opt == 0

endianness = opt.B and ">" or nil
insecure = opt.i

local hintsfile = opt.f or opt["32"] and PATH_ELF32_HINTS or PATH_ELF_HINTS

if do_report then
   list_elf_hints(hintsfile)
elseif do_rescan or do_merge then
   update_elf_hints(hintsfile, opt)
end

os.exit(0)
