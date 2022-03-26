#!/usr/libexec/flua

--[[
SPDX-License-Identifier: BSD-2-Clause-FreeBSD

Copyright (c) 2022 Stefan Eßer

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
--local posix = require("posix")

local hintsmagic = 1953392709
local PATH_ELF_HINTS = "/var/run/ld-elf.so.hints"
local PATH_ELF_HINTS = "/var/tmp/ld-elf.so.hints"
local PATH_ELF32_HINTS = "/var/run/ld-elf32.so.hints"
local MAXFILESIZE = 16 * 1024

local endianness
local insecure
local COMPAT_LIBS = {}
local DIRS = {}

local function get_compat_dirs()
	local compatlibs = { -- should use sysctl("usr.compat_libs")
		"/usr/local/lib/compat/pkg",
		--"usr/local/lib32/compat",
		}
	return compatlibs
end

local function compat_path_idx(dir, trusted)
	COMPAT_LIBS = COMPAT_LIBS or get_compat_dirs()
	for i = 1, #COMPAT_LIBS do
		if dir == COMPAT_LIBS[i] then
			return i
		end
	end
	return -1
end

local function add_dir(name, trusted)
	-- Do some security checks
	if not trusted and not insecure then
		local attr, errmsg = lfs.attributes(name)
		if attr then
			local mode = tonumber(attr.permissions, 8)
			if attr.uid ~= 0 then
				print(name, ": ignoring directory not owned by root")
			elseif mode & 2 ~= 0 then
				print(name, ": ignoring world-writable directory")
			elseif mode & (2 << 3) ~= 0 then
				print(name, ": ignoring group-writable directory")
			else
				local compat_idx = compat_path_idx(name, trusted)
				local insert_at = #DIRS + 1
				for i = 1, #DIRS do
					if name == DIRS[i] then
						return
					end
					if compat_idx < compat_path_idx(DIRS[i], trusted) then
						insert_at = insert_at - 1
					end
				end
				table.insert(DIRS, insert_at, name)
			end
		else
			print(errmsg .. ": " .. name)
		end
	end
end

local function abort(msg)
	print (msg)
	os.exit(1)
end

local function shlibs(path)
	local libs = {}
	for name in lfs.dir(path) do
		if string.match(name, ".*%.so.[%d]+$") then
			libs[#libs+1] = path .. "/" .. name
		end
	end
	return libs
end

local function parsehdr(data, forced_endianness)
	local magic, version, strtab, strsize, dirlist, dirlistlen =
		string.unpack("<I4 I4 I4 I4 I4 I4", data)
	if magic == hintsmagic then
		endianness = "<"
	else
		magic, version, strtab, strsize, dirlist, dirlistlen =
			string.unpack(">I4 I4 I4 I4 I4 I4", data)
		if magic ~= hintsmagic then
			abort("bad magic number")
		end
		endianness = ">"
	end
	if forced_endianness and forced_endianness ~= endianness then
		abort("conflicting endianness requested")
	end
	if version ~= 1 then
		abort("invalid hints file version " .. version)
	end
	local offset = strtab + dirlist
	local path = string.sub(data, offset + 1, offset + dirlistlen)
	for dir in string.gmatch(path, "([^:]+):?") do
		add_dir(dir, false)
	end
end

local function readhints(filename)
	local hintsfile = io.open(filename, "rb")
	if not hintsfile then
		abort("missing hintsfile " .. filename)
	end
	local data = hintsfile:read("a")
	hintsfile:close()
	parsehdr(data)
end

local function list_elf_hints(hintsfile)
	readhints(hintsfile)
	print (hintsfile .. ":")
	print ("\tsearch directories: " .. table.concat(DIRS, ":"))
	local all_libs = {}
	for _, dir in ipairs(DIRS) do
		local libs = shlibs(dir)
		table.move(libs, 1 , #libs, #all_libs + 1, all_libs)
	end
	local lcount = 0
	for _, lib in ipairs(all_libs) do
		local lopt, version = string.match(lib, ".*/lib([^/]+).so.(%d+)")
		if lopt then
			print ("\t" .. tostring(lcount) .. ":-l" .. lopt .. "." .. version .. " => " .. lib)
			lcount = lcount + 1
		end
	end
end

local function read_dirs_from_file(listfile)
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
			add_dir(dir, false);
		end
	end
	fp:close()
end

local function read_elf_hints(hintsfile, must_exist)
	local fd = io.open(hintsfile, "r")
	if not fd then
		if must_exist then
			abort('Cannot open "' .. hintsfile .. '"')
		end
	else
		local attr = lfs.attributes(hintsfile)
		if not attr then
			abort('Cannot stat "'..  hintsfile .. '"')
		end
		if attr.size > MAXFILESIZE then
			abort('"' .. hintsfile .. '" is unreasonably large')
		end
		local hintsdata = fd:read("a")
		parsehdr(hintsdata)
		fd:close()
	end
end

local function generatehints()
	local path = table.concat(DIRS, ":")
	local magic = hintsmagic
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

local function write_elf_hints(hintsfile)
	local tmpname = os.tmpname()
	local destdir = string.match(hintsfile, "^(.*)/")
	tmpname = destdir .. "/" .. string.match(tmpname, "[^/]+$")
	local fb = io.open(tmpname, "w")
	fb:write(generatehints())
	fb:close()
	os.rename(tmpname, hintsfile)
end

local function update_elf_hints(hintsfile, merge, force_be, force_le)
	if force_be then
		endianness = ">"
	elseif force_le then
		endianness = "<"
	end
	if merge then
		read_elf_hints(hintsfile, false);
	end
	for i = 1, #arg do
		local attr, errmsg = lfs.attributes(arg[i])
		if not attr then
			print("warning: " .. arg[i] .. ": " .. errmsg)
		elseif attr.mode == "file" then
			read_dirs_from_file(arg[i])
		else
			add_dir(arg[i], false);
		end
	end
	write_elf_hints(hintsfile);
end

update_elf_hints(PATH_ELF_HINTS, true, false, false)
list_elf_hints(PATH_ELF32_HINTS)
--list_elf_hints("/var/run/ld-elf.so.hints")
