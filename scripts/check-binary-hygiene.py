#!/usr/bin/env python3
"""Fail when shipped binaries embed build-machine paths or carry symbol tables.

Usage: check-binary-hygiene.py [--allow SUBSTRING]... PATH...
PATH may be a file, a directory (walked) or a .zip/.tar.gz/.deb-free archive
(zip and tar are opened in memory). Non-executable files are ignored.

Rules, per Mach-O slice, ELF or PE image:
  * no absolute build paths (/Users/<name>/, /home/<name>/, /root/, CI work
    dirs, Windows user/runner dirs, macOS temp dirs);
  * Mach-O: no debug (N_STAB) or local symbols; exported/undefined allowed;
  * ELF: no .symtab and no .debug_* sections; .dynsym (exports) allowed;
  * PE: no COFF symbol table and no .debug* sections.
Pure Python so it runs on macOS, the estate Linux runner and Windows.
"""
import argparse
import io
import os
import re
import struct
import sys
import tarfile
import zipfile

PATHS = re.compile(
    rb'/Users/(?!Shared/)[A-Za-z0-9._-]+/'
    rb'|/home/(?:runner|[a-z_][a-z0-9_-]{1,31})/'
    rb'|/root/[A-Za-z0-9._-]'
    rb'|/private/var/folders/|/var/folders/[a-z0-9_]{2}/'
    rb'|/__w/|/github/workspace/'
    rb'|[A-Za-z]:[\\/](?:Users|a)[\\/][A-Za-z0-9._ -]+[\\/]'
    rb'|[A-Za-z]:[\\/]actions-runner[\\/]')
# Case-sensitive on purpose: '/users/<id>/' API routes and '/Root' PDF tokens are not paths.
# Apple's strip leaves this marker symbol in every stripped image.
APPLE_STRIP_MARKER = b'radr://5614542'

MH = {0xfeedface: ('<', 32), 0xfeedfacf: ('<', 64), 0xcefaedfe: ('>', 32), 0xcffaedfe: ('>', 64)}


def macho_symbols(data):
    if data[:4] in (b'\xca\xfe\xba\xbe', b'\xca\xfe\xba\xbf'):
        wide = data[3] == 0xbf
        count = struct.unpack('>I', data[4:8])[0]
        problems = []
        for i in range(count):
            if wide:
                _, _, off, size, _, _ = struct.unpack('>iiQQII', data[8 + 32 * i:40 + 32 * i])
            else:
                _, _, off, size, _ = struct.unpack('>iiIII', data[8 + 20 * i:28 + 20 * i])
            problems += macho_symbols(data[off:off + size])
        return problems
    magic = struct.unpack('<I', data[:4])[0]
    order, bits = MH[magic]
    ncmds = struct.unpack(order + 'I', data[16:20])[0]
    pos = 32 if bits == 64 else 28
    for _ in range(ncmds):
        cmd, size = struct.unpack(order + 'II', data[pos:pos + 8])
        if cmd == 0x2:  # LC_SYMTAB
            symoff, nsyms, stroff = struct.unpack(order + 'III', data[pos + 8:pos + 20])
            entry = 16 if bits == 64 else 12
            stabs = local = 0
            for i in range(nsyms):
                n_strx = struct.unpack(order + 'I', data[symoff + i * entry:symoff + i * entry + 4])[0]
                if data[stroff + n_strx:stroff + n_strx + len(APPLE_STRIP_MARKER)] == APPLE_STRIP_MARKER:
                    continue
                n_type = data[symoff + i * entry + 4]
                if n_type & 0xe0:
                    stabs += 1
                elif n_type & 0x0e == 0x0e and not n_type & 0x01:  # N_SECT, not N_EXT
                    local += 1
            found = []
            if stabs:
                found.append(f'{stabs} debug (N_STAB) symbols')
            if local:
                found.append(f'{local} local symbols')
            return found
        pos += size
    return []


def elf_symbols(data):
    wide = data[4] == 2
    order = '<' if data[5] == 1 else '>'
    if wide:
        shoff, = struct.unpack(order + 'Q', data[0x28:0x30])
        shentsize, shnum, shstrndx = struct.unpack(order + 'HHH', data[0x3a:0x40])
    else:
        shoff, = struct.unpack(order + 'I', data[0x20:0x24])
        shentsize, shnum, shstrndx = struct.unpack(order + 'HHH', data[0x2e:0x34])
    if not shoff or not shnum:
        return []

    def section(i):
        base = shoff + i * shentsize
        if wide:
            name, kind, _, _, off, size = struct.unpack(order + 'IIQQQQ', data[base:base + 40])
        else:
            name, kind, _, _, off, size = struct.unpack(order + 'IIIIII', data[base:base + 24])
        return name, kind, off, size

    _, _, stroff, strsize = section(shstrndx)
    names = data[stroff:stroff + strsize]
    found = []
    for i in range(shnum):
        name, kind, _, _ = section(i)
        label = names[name:names.index(b'\0', name)].decode(errors='replace')
        if kind == 2:
            found.append('.symtab')
        elif label.startswith(('.debug', '.zdebug')):
            found.append(label)
    return found


def pe_symbols(data):
    pe = struct.unpack('<I', data[0x3c:0x40])[0]
    if data[pe:pe + 4] != b'PE\0\0':
        return []
    nsec, = struct.unpack('<H', data[pe + 6:pe + 8])
    symptr, nsyms = struct.unpack('<II', data[pe + 12:pe + 20])
    optsize, = struct.unpack('<H', data[pe + 20:pe + 22])
    strtab = symptr + nsyms * 18
    found = [f'COFF symbol table ({nsyms} entries)'] if symptr and nsyms else []
    table = pe + 24 + optsize
    for i in range(nsec):
        raw = data[table + 40 * i:table + 40 * i + 8].rstrip(b'\0')
        if raw.startswith(b'/') and symptr:
            off = int(raw[1:] or b'0')
            raw = data[strtab + off:data.index(b'\0', strtab + off)]
        if raw.startswith((b'.debug', b'.zdebug')):
            found.append(raw.decode(errors='replace'))
    return found


def kind(data):
    head = data[:4]
    if head == b'\x7fELF':
        return 'elf', elf_symbols
    if len(data) > 0x40 and data[:2] == b'MZ':
        return 'pe', pe_symbols
    if head in (b'\xca\xfe\xba\xbe', b'\xca\xfe\xba\xbf') and struct.unpack('>I', data[4:8])[0] < 32:
        return 'mach-o', macho_symbols
    if len(head) == 4 and struct.unpack('<I', head)[0] in MH:
        return 'mach-o', macho_symbols
    return None, None


def check(name, data, allow, problems):
    label, symbols = kind(data)
    if not label:
        return 0
    paths = sorted({m.group(0).decode(errors='replace') for m in PATHS.finditer(data)
                    if not any(a.encode() in data[max(0, m.start() - 200):m.end() + 200] for a in allow)})
    if paths:
        problems.append(f'{name}: embedded build paths: {", ".join(paths[:5])}')
    try:
        leftovers = symbols(data)
    except (struct.error, ValueError, IndexError, KeyError) as exc:
        leftovers = [f'unparseable {label} ({exc.__class__.__name__})']
    if leftovers:
        problems.append(f'{name}: not stripped: {", ".join(leftovers[:6])}')
    return 1


def walk(path, allow, problems):
    count = 0
    if os.path.isdir(path):
        for root, _, files in os.walk(path):
            for file in files:
                count += walk(os.path.join(root, file), allow, problems)
        return count
    if path.endswith('.zip'):
        with zipfile.ZipFile(path) as archive:
            for member in archive.infolist():
                if not member.is_dir():
                    count += check(f'{path}!{member.filename}', archive.read(member), allow, problems)
        return count
    if path.endswith(('.tar.gz', '.tgz', '.tar')):
        with tarfile.open(path) as archive:
            for member in archive:
                if member.isfile():
                    count += check(f'{path}!{member.name}', archive.extractfile(member).read(), allow, problems)
        return count
    if os.path.islink(path) or not os.path.isfile(path):
        return 0
    with open(path, 'rb') as handle:
        return check(path, handle.read(), allow, problems)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--allow', action='append', default=[],
                        help='ignore a path match within 200 bytes of this substring (record why at the call site)')
    parser.add_argument('paths', nargs='+')
    args = parser.parse_args(argv)
    problems = []
    count = sum(walk(path, args.allow, problems) for path in args.paths)
    for problem in problems:
        print('binary-hygiene: ' + problem, file=sys.stderr)
    if not count:
        print('binary-hygiene: no executables found', file=sys.stderr)
        return 1
    if problems:
        return 1
    print(f'binary-hygiene: {count} binaries clean')
    return 0


if __name__ == '__main__':
    sys.exit(main())
