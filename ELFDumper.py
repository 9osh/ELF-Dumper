#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GDB扩展插件：从指定内存范围内dump出合法ELF文件
功能：利用PHT实现内存到合法ELF文件的转换
"""

import gdb
import struct
import os
import sys
import re
from typing import List, Tuple, Optional

class ELFDumper(gdb.Command):
    """GDB命令：从内存dump ELF文件"""
    
    def __init__(self):
        super(ELFDumper, self).__init__("dump-elf", gdb.COMMAND_USER)
        self.elf_header_size = 64  # ELF64 header size
        self.program_header_size = 56  # ELF64 program header size
    
    def invoke(self, arg, from_tty):
        """命令执行入口"""
        try:
            args = gdb.string_to_argv(arg)
            if len(args) < 3:
                print("Usage: dump-elf <start_addr> <end_addr> <output_file> [base_addr]")
                print("Arguments:")
                print("  start_addr: start address (hex)")
                print("  end_addr:   end address (hex)")
                print("  output_file: output file path")
                print("  base_addr:   optional base address (hex, defaults to start_addr)")
                return
            
            start_addr = int(args[0], 16)
            end_addr = int(args[1], 16)
            output_file = args[2]
            base_addr = int(args[3], 16) if len(args) > 3 else start_addr
            
            print(f"[+] Starting ELF dump...")
            print(f"[+] Memory range: 0x{start_addr:x} - 0x{end_addr:x}")
            print(f"[+] Base address: 0x{base_addr:x}")
            print(f"[+] Output file: {output_file}")
            
            # 读取内存数据（容忍空洞，空洞用0填充）
            memory_data = self.read_memory_range(start_addr, end_addr)
            if memory_data is None:
                print("[-] Failed to read memory")
                return
            
            # 解析ELF头
            elf_header = self.parse_elf_header(memory_data)
            if not elf_header:
                print("[-] Invalid ELF header")
                return
            
            # 解析程序头表
            program_headers = self.parse_program_headers(memory_data, elf_header)
            if not program_headers:
                print("[-] Failed to parse program headers")
                return
            
            # 重建ELF文件
            elf_data = self.rebuild_elf_file(memory_data, elf_header, program_headers, base_addr)
            if not elf_data:
                print("[-] Failed to rebuild ELF file")
                return
            
            # 写入文件
            with open(output_file, 'wb') as f:
                f.write(elf_data)
            
            print(f"[+] ELF file saved to: {output_file}")
            print(f"[+] File size: {len(elf_data)} bytes")
            
        except Exception as e:
            print(f"[-] Error: {e}")
    
    def read_memory_range(self, start_addr: int, end_addr: int) -> Optional[bytes]:
        """分段读取指定内存范围的数据，不可读区域用0填充"""
        try:
            size = end_addr - start_addr
            if size <= 0:
                print("[-] Invalid memory range")
                return None
            
            inferior = gdb.selected_inferior()
            page = 0x1000
            buf = bytearray(size)
            pos = 0
            while pos < size:
                chunk = min(page, size - pos)
                addr = start_addr + pos
                try:
                    mem = inferior.read_memory(addr, chunk)
                    buf[pos:pos+chunk] = bytes(mem)
                except Exception:
                    # 填0继续
                    for i in range(chunk):
                        buf[pos + i] = 0
                pos += chunk
            return bytes(buf)
        except Exception as e:
            print(f"[-] Failed to read memory: {e}")
            return None
    
    def parse_elf_header(self, data: bytes) -> Optional[dict]:
        """解析ELF头（自适应32/64位与大小端）"""
        try:
            if len(data) < 64:
                return None
            
            e_ident = data[:16]
            if e_ident[:4] != b'\x7fELF':
                print("[-] Not a valid ELF file")
                return None
            
            elf_class = e_ident[4]  # 1=ELF32, 2=ELF64
            elf_data = e_ident[5]   # 1=little, 2=big
            endian = '<' if elf_data == 1 else '>'
            
            if elf_class == 2:  # ELF64
                fmt = endian + 'HHIQQQIHHHHHH'
                rest = struct.unpack(fmt, data[16:64])
                (e_type, e_machine, e_version, e_entry, e_phoff, e_shoff,
                 e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum,
                 e_shstrndx) = rest
            elif elf_class == 1:  # ELF32
                fmt = endian + 'HHIIIIIHHHHHH'
                rest = struct.unpack(fmt, data[16:16+36])
                (e_type, e_machine, e_version, e_entry, e_phoff, e_shoff,
                 e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum,
                 e_shstrndx) = rest
            else:
                print("[-] Unknown ELF class")
                return None
            
            elf_header = {
                'e_ident': e_ident,
                'class': elf_class,
                'data': elf_data,
                'version': e_version,
                'type': e_type,
                'machine': e_machine,
                'entry': e_entry,
                'phoff': e_phoff,
                'shoff': e_shoff,
                'flags': e_flags,
                'ehsize': e_ehsize,
                'phentsize': e_phentsize,
                'phnum': e_phnum,
                'shentsize': e_shentsize,
                'shnum': e_shnum,
                'shstrndx': e_shstrndx,
                'endian': endian,
            }
            
            print(f"[+] ELF class: {'ELF64' if elf_header['class'] == 2 else 'ELF32'}")
            print(f"[+] Endianness: {'little' if elf_header['data'] == 1 else 'big'}")
            print(f"[+] Program header count: {elf_header['phnum']}")
            print(f"[+] Entry point: 0x{elf_header['entry']:x}")
            
            return elf_header
            
        except Exception as e:
            print(f"[-] Failed to parse ELF header: {e}")
            return None
    
    def parse_program_headers(self, data: bytes, elf_header: dict) -> Optional[List[dict]]:
        """解析程序头表（自适应32/64位与大小端）"""
        try:
            phoff = elf_header['phoff']
            phnum = elf_header['phnum']
            phentsize = elf_header['phentsize']
            endian = elf_header.get('endian', '<')
            
            if phoff + phnum * phentsize > len(data):
                print("[-] Program header table exceeds buffer range")
                return None
            
            headers = []
            for i in range(phnum):
                offset = phoff + i * phentsize
                ph_data = data[offset:offset + phentsize]
                
                # 解析程序头表项
                if elf_header['class'] == 2:  # 64位
                    ph = struct.unpack(endian + 'IIQQQQQQ', ph_data)
                    header = {
                        'type': ph[0],
                        'flags': ph[1],
                        'offset': ph[2],    # 文件偏移
                        'vaddr': ph[3],     # 虚拟地址
                        'paddr': ph[4],     # 物理地址
                        'filesz': ph[5],    # 文件大小
                        'memsz': ph[6],     # 内存大小
                        'align': ph[7]      # 对齐
                    }
                else:  # 32位
                    ph = struct.unpack(endian + 'IIIIIIII', ph_data)
                    header = {
                        'type': ph[0],
                        'offset': ph[1],
                        'vaddr': ph[2],
                        'paddr': ph[3],
                        'filesz': ph[4],
                        'memsz': ph[5],
                        'flags': ph[6],
                        'align': ph[7]
                    }
                
                headers.append(header)
                
                print(f"[+] PH[{i}]: type={header['type']}, vaddr=0x{header['vaddr']:x}, file_off=0x{header['offset']:x}, filesz=0x{header['filesz']:x}")
            
            return headers
            
        except Exception as e:
            print(f"[-] Failed to parse program headers: {e}")
            return None
    
    def rebuild_elf_file(self, memory_data: bytes, elf_header: dict, 
                        program_headers: List[dict], base_addr: int) -> Optional[bytes]:
        """重建ELF文件"""
        # 计算文件大小
        try:
            max_offset = 0
            for ph in program_headers:
                if ph['type'] == 1:  # PT_LOAD
                    end_offset = ph['offset'] + ph['filesz']
                    if end_offset > max_offset:
                        max_offset = end_offset
            
            # 创建文件缓冲区
            file_size = max(max_offset, elf_header['phoff'] + 
                           elf_header['phnum'] * elf_header['phentsize'])
            elf_file = bytearray(file_size)
            
            # 复制ELF头
            elf_file[:self.elf_header_size] = memory_data[:self.elf_header_size]
            
            # 复制程序头表
            phoff = elf_header['phoff']
            phentsize = elf_header['phentsize']
            for i, ph in enumerate(program_headers):
                offset = phoff + i * phentsize
                # 从内存中复制程序头表项
                mem_offset = offset
                if mem_offset + phentsize <= len(memory_data):
                    elf_file[offset:offset + phentsize] = memory_data[mem_offset:mem_offset + phentsize]
            
            # 复制段数据
            for ph in program_headers:
                if ph['type'] == 1:  # PT_LOAD
                    vaddr = ph['vaddr']
                    offset = ph['offset']
                    filesz = ph['filesz']
                    
                    # 计算内存中的位置
                    mem_offset = vaddr - base_addr
                    if mem_offset >= 0 and mem_offset + filesz <= len(memory_data):
                        # 复制段数据
                        elf_file[offset:offset + filesz] = memory_data[mem_offset:mem_offset + filesz]
                        print(f"[+] Copy PT_LOAD: vaddr=0x{vaddr:x}, file_off=0x{offset:x}, size=0x{filesz:x}")
                    else:
                        print(f"[-] Warning: segment out of memory range: vaddr=0x{vaddr:x}")
            
            return bytes(elf_file)
            
        except Exception as e:
            print(f"[-] Failed to rebuild ELF: {e}")
            return None

class AutoDumpELF(gdb.Command):
    """GDB命令：自动检测并dump ELF文件（基于PHT确定范围）"""
    
    def __init__(self):
        super(AutoDumpELF, self).__init__("auto-dump-elf", gdb.COMMAND_USER)
    
    def invoke(self, arg, from_tty):
        """自动检测并dump ELF文件"""
        try:
            args = gdb.string_to_argv(arg)
            if len(args) < 1:
                print("Usage: auto-dump-elf <output_file>")
                print("Arguments:")
                print("  output_file: output file path")
                return
            
            output_file = args[0]
            
            print(f"[+] Auto-detecting ELF...")
            
            # 获取进程内存映射
            memory_maps = self.get_memory_maps()
            if not memory_maps:
                print("[-] Failed to get memory mappings")
                return
            
            # 查找ELF并计算范围
            elf_info = self.find_elf_and_compute_range(memory_maps)
            if not elf_info:
                print("[-] ELF not found")
                return
            
            start_addr = elf_info['start_addr']
            end_addr = elf_info['end_addr']
            base_addr = elf_info['base_addr']
            print(f"[+] Selected range: 0x{start_addr:x} - 0x{end_addr:x} (base=0x{base_addr:x})")
            
            # 执行dump
            gdb.execute(f"dump-elf 0x{start_addr:x} 0x{end_addr:x} {output_file} 0x{base_addr:x}")
            
        except Exception as e:
            print(f"[-] Error: {e}")
    
    def _parse_proc_maps(self, text: str) -> List[dict]:
        maps: List[dict] = []
        # 允许可选0x前缀
        line_re = re.compile(r'^(?:0x)?([0-9a-fA-F]+)-(?:0x)?([0-9a-fA-F]+)\s+([rwxps-]{4})\s+(?:0x)?([0-9a-fA-F]+)')
        for raw in text.splitlines():
            line = raw.strip()
            if not line:
                continue
            m = line_re.match(line)
            if not m:
                continue
            start = int(m.group(1), 16)
            end = int(m.group(2), 16)
            perms = m.group(3)
            offset = int(m.group(4), 16)
            maps.append({'start': start, 'end': end, 'perms': perms, 'offset': offset})
        return maps
    
    def _parse_info_proc_mappings(self, text: str) -> List[dict]:
        maps: List[dict] = []
        # 典型格式（有表头）：Start Addr End Addr Size Offset objfile
        # 行示例：0x400000           0x4ca000    0xca000        0x0  obj
        col_re = re.compile(r'^(?:0x)?([0-9a-fA-F]+)\s+(?:0x)?([0-9a-fA-F]+)\s+(?:0x)?([0-9a-fA-F]+)\s+(?:0x)?([0-9a-fA-F]+)')
        for raw in text.splitlines():
            line = raw.strip()
            if not line:
                continue
            m = col_re.match(line)
            if not m:
                continue
            start = int(m.group(1), 16)
            end = int(m.group(2), 16)
            offset = int(m.group(4), 16)
            # info输出可能没有权限列，保守设为可读
            perms = 'r--p'
            # 过滤表头行
            if start >= end:
                continue
            maps.append({'start': start, 'end': end, 'perms': perms, 'offset': offset})
        return maps
    
    def get_memory_maps(self) -> Optional[List[dict]]:
        """获取进程内存映射，包含多种回退与健壮解析"""
        try:
            pid = None
            try:
                pid = gdb.selected_inferior().pid
            except Exception:
                pid = None
            texts: List[Tuple[str, str]] = []
            # 优先尝试 /proc/<pid>/maps
            if pid:
                try:
                    txt = gdb.execute(f"shell cat /proc/{pid}/maps", to_string=True)
                    texts.append(("/proc/pid/maps", txt))
                except Exception:
                    pass
            # 回退 /proc/self/maps
            try:
                txt = gdb.execute("shell cat /proc/self/maps", to_string=True)
                texts.append(("/proc/self/maps", txt))
            except Exception:
                pass
            # 回退 info proc mappings
            try:
                txt = gdb.execute("info proc mappings", to_string=True)
                texts.append(("info proc mappings", txt))
            except Exception:
                pass
            # 逐个解析
            for src, txt in texts:
                maps = self._parse_proc_maps(txt)
                if not maps:
                    maps = self._parse_info_proc_mappings(txt)
                if maps:
                    return maps
            # 全部失败
            if texts:
                sample = texts[-1][1]
                sample = sample[:400].replace('\n', ' ')
                print(f"[-] Failed to parse memory mappings, sample: {sample} ...")
            return None
        except Exception as e:
            print(f"[-] Failed to get memory mappings: {e}")
            return None
    
    def find_map_containing(self, maps: List[dict], addr: int) -> Optional[dict]:
        for m in maps:
            if m['start'] <= addr < m['end']:
                return m
        return None
    
    def find_elf_and_compute_range(self, memory_maps: List[dict]) -> Optional[dict]:
        try:
            inferior = gdb.selected_inferior()
            # 先定位e_ident所在映射
            for m in memory_maps:
                if 'r' not in m['perms']:
                    continue
                try:
                    ident = inferior.read_memory(m['start'], 16)
                    if bytes(ident)[:4] != b'\x7fELF':
                        continue
                    # 解析头以获端序/位数
                    # 读取最多64字节
                    hdr = inferior.read_memory(m['start'], 64)
                    b = bytes(hdr)
                    e_ident = b[:16]
                    elf_class = e_ident[4]
                    elf_data = e_ident[5]
                    endian = '<' if elf_data == 1 else '>'
                    if elf_class == 2:
                        # 直接从内存解析完整ELF64头
                        header = struct.unpack(endian + '16sHHIQQQIHHHHHH', b)
                        phoff = header[5]
                        phentsize = header[9]
                        phnum = header[10]
                    else:
                        # 读取52字节
                        hdr32 = inferior.read_memory(m['start'], 52)
                        b32 = bytes(hdr32)
                        header = struct.unpack(endian + '16sHHIIIIIHHHHHH', b32)
                        phoff = header[5]
                        phentsize = header[9]
                        phnum = header[10]
                    # 读取PHT
                    min_vaddr = None
                    max_vaddr_end = 0
                    for i in range(phnum):
                        off = m['start'] + phoff + i * phentsize
                        ph_bytes = inferior.read_memory(off, phentsize)
                        pb = bytes(ph_bytes)
                        if elf_class == 2:
                            p = struct.unpack(endian + 'IIQQQQQQ', pb)
                            p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = p
                        else:
                            p = struct.unpack(endian + 'IIIIIIII', pb)
                            p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = p
                        if p_type == 1:  # PT_LOAD
                            if min_vaddr is None or p_vaddr < min_vaddr:
                                min_vaddr = p_vaddr
                            if p_vaddr + p_memsz > max_vaddr_end:
                                max_vaddr_end = p_vaddr + p_memsz
                    if min_vaddr is None:
                        continue
                    # 基于最大虚拟地址定位结束映射
                    end_map = self.find_map_containing(memory_maps, max_vaddr_end - 1)
                    if not end_map:
                        print("[-] No mapping contains max virtual address, falling back to current mapping")
                        end_map = m
                    start_addr = m['start']
                    end_addr = end_map['end']
                    base_addr = m['start']  # 用ELF头所在映射起始作为基址
                    print(f"[+] ELF found at 0x{m['start']:x}, PHT range: min_vaddr=0x{min_vaddr:x}, max_end=0x{max_vaddr_end:x}")
                    return {'start_addr': start_addr, 'end_addr': end_addr, 'base_addr': base_addr}
                except Exception:
                    continue
            return None
        except Exception as e:
            print(f"[-] Failed to compute ELF range: {e}")
            return None

# 注册GDB命令
ELFDumper()
AutoDumpELF()

print("GDB ELF Dumper loaded")
print("Commands:")
print("  dump-elf <start_addr> <end_addr> <output_file> [base_addr] - dump ELF from memory range")
print("  auto-dump-elf <output_file> - auto-detect and dump ELF")
