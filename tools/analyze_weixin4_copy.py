"""Execution-free PE inventory and focused RIP-reference analysis."""
from __future__ import annotations
import argparse
import ast
import bisect
import hashlib
import json
from pathlib import Path
import re
import struct

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_MEM
from capstone.x86 import X86_REG_RIP


class Image:
    def __init__(self, path):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        self.pe = pefile.PE(data=self.data, fast_load=True)
        self.pe.parse_data_directories(directories=[1, 0])
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.md.detail = True
        pdata = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
        raw = self.pe.get_data(pdata.VirtualAddress, pdata.Size)
        self.funcs = sorted((begin + self.base, end + self.base)
                           for begin, end, unwind in struct.iter_unpack('<III', raw[:len(raw)//12*12])
                           if begin < end)
        self.starts = [x[0] for x in self.funcs]

    def va(self, off):
        return self.base + self.pe.get_rva_from_offset(off)

    def off(self, va):
        return self.pe.get_offset_from_rva(va - self.base)

    def containing(self, va):
        i = bisect.bisect_right(self.starts, va) - 1
        return self.funcs[i] if i >= 0 and va < self.funcs[i][1] else None

    def instructions(self, va, n=80):
        off = self.off(va)
        fn = self.containing(va)
        size = fn[1] - va if fn else 0x400
        return [{'va': hex(x.address), 'bytes': x.bytes.hex(), 'asm': x.mnemonic+' '+x.op_str}
                for x in self.md.disasm(self.data[off:off + min(size, 0x10000)], va, count=n)]

    def riprefs(self, targets):
        targets = set(targets)
        result = []
        for section in self.pe.sections:
            if not section.Characteristics & 0x20000000:
                continue
            data = section.get_data()
            start = self.base + section.VirtualAddress
            # REX + MOV/LEA with RIP relative operand. Decode each candidate
            # to verify the instruction and exact effective address.
            pattern = (rb'(?:[\x40-\x4f][\x8d\x8b\x89]|'
                       rb'[\x66\xf2\xf3]?[\x40-\x4f]?\x0f[\x10\x11\x28\x29\x6f\x7f])'
                       rb'[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]')
            for match in re.finditer(pattern, data):
                pos = match.start()
                disp_pos = match.end()
                ins_len = disp_pos - pos + 4
                if disp_pos + 4 > len(data):
                    continue
                dst = start + pos + ins_len + struct.unpack_from('<i', data, disp_pos)[0]
                if dst not in targets:
                    continue
                for ins in self.md.disasm(data[pos:pos+15], start+pos, count=1):
                    if any(o.type == CS_OP_MEM and o.mem.base == X86_REG_RIP and
                           ins.address+ins.size+o.mem.disp == dst for o in ins.operands):
                        fn = self.containing(ins.address)
                        result.append({'va': hex(ins.address), 'target': hex(dst),
                                       'asm': ins.mnemonic+' '+ins.op_str,
                                       'function': [hex(v) for v in fn] if fn else None})
        return result

    def find(self, needle):
        result = []
        pos = 0
        while True:
            pos = self.data.find(needle, pos)
            if pos < 0:
                break
            try:
                va = self.va(pos)
                result.append({'offset': hex(pos), 'va': hex(va)})
            except pefile.PEFormatError:
                pass
            pos += 1
        return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('binary', type=Path)
    ap.add_argument('--out', type=Path, required=True)
    ap.add_argument('--target', action='append', default=[])
    ap.add_argument('--disasm', action='append', default=[])
    ap.add_argument('--no-refs', action='store_true')
    args = ap.parse_args()
    image = Image(args.binary)
    imports = [{'dll': e.dll.decode('ascii', 'replace'),
                'names': [i.name.decode('ascii', 'replace') if i.name else '#'+str(i.ordinal)
                          for i in e.imports]}
               for e in getattr(image.pe, 'DIRECTORY_ENTRY_IMPORT', [])]
    exports = [{'name': x.name.decode('ascii', 'replace') if x.name else None,
                'rva': hex(x.address), 'ordinal': x.ordinal}
               for x in getattr(getattr(image.pe, 'DIRECTORY_ENTRY_EXPORT', None), 'symbols', [])]
    needles = ['com.Tencent.WCDB.Config.Cipher', 'global_config', 'SetDBKey',
               'sqlcipher_export', 'cipher_compatibility', 'cipher_page_size',
               'wcdb_decompress', 'WCDB_CT_', 'cipher_kdf_algorithm',
               'CipherConfig', 'RawKey', 'raw_key', 'LoginKeyInfoTable']
    found = {n: image.find(n.encode()) for n in needles}
    targets = [int(x, 0) for x in args.target]
    targets += [int(x['va'], 0) for n in ['com.Tencent.WCDB.Config.Cipher', 'global_config', 'SetDBKey']
                for x in found[n]]
    report = {'schema': 'weixin-native-inventory-1',
              'file': str(args.binary), 'bytes': len(image.data),
              'sha256': hashlib.sha256(image.data).hexdigest(),
              'image_base': hex(image.base), 'machine': hex(image.pe.FILE_HEADER.Machine),
              'unwind_function_ranges': len(image.funcs),
              'sections': [{'name': s.Name.rstrip(b'\0').decode(), 'rva': hex(s.VirtualAddress),
                            'raw_offset': hex(s.PointerToRawData), 'raw_size': s.SizeOfRawData,
                            'virtual_size': s.Misc_VirtualSize, 'flags': hex(s.Characteristics)}
                           for s in image.pe.sections],
              'imports': imports, 'exports': exports, 'strings': found,
              'riprefs': [] if args.no_refs else image.riprefs(targets),
              'disassembly': {va: image.instructions(int(va, 0), 160) for va in args.disasm}}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps({'output': str(args.out), 'sha256': report['sha256'],
                      'imports': sum(len(e['names']) for e in imports), 'exports': len(exports),
                      'strings': found, 'riprefs': report['riprefs']}, ensure_ascii=False))


if __name__ == '__main__':
    main()
