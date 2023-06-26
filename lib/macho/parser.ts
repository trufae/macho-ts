var util = require('util');
import { Reader } from "./endian-reader.js";
import { constants } from "./constants.js";


export class Parser extends Reader {
    construct() {
    }
    execute(buf: any) {
        var hdr: any = this.parseHead(buf);
        if (!hdr)
            throw new Error('File not in a mach-o format');

        hdr.cmds = this.parseCommands(hdr, hdr.body, buf);
        delete hdr.body;

        return hdr;
    }

    parseLCStr(buf: any, off: any) {
        if (off + 4 > buf.length)
            throw new Error('lc_str OOB');

        var offset = super.readUInt32(buf, off) - 8;
        if (offset > buf.length)
            throw new Error('lc_str offset OOB');

        return this.parseCStr(buf.slice(offset));
    }
    parseHead(buf: any) {
        if (buf.length < 7 * 4)
            return false;

        var magic = buf.readUInt32LE(0);
        var bits;
        if (magic === 0xfeedface || magic === 0xcefaedfe)
            bits = 32;
        else if (magic === 0xfeedfacf || magic == 0xcffaedfe)
            bits = 64;
        else
            return false;

        if ((magic & 0xff) == 0xfe) {
            super.setEndian('be');
        } else {
            super.setEndian('le');
        }

        if (bits === 64 && buf.length < 8 * 4)
            return false;

        var cputype = constants.cpuType[super.readInt32(buf, 4)];
        var cpusubtype = super.readInt32(buf, 8);
        var filetype = super.readUInt32(buf, 12);
        var ncmds = super.readUInt32(buf, 16);
        var sizeofcmds = super.readUInt32(buf, 20);
        var flags = super.readUInt32(buf, 24);

        // Get endian
        var endian;
        if ((cpusubtype & constants.endian.multiple) === constants.endian.multiple)
            endian = 'multiple';
        else if (cpusubtype & constants.endian.be)
            endian = 'be';
        else
            endian = 'le';

        cpusubtype &= constants.cpuSubType.mask;

        // Get subtype
        var subtype;
        if (endian === 'multiple')
            subtype = 'all';
        else if (cpusubtype === 0)
            subtype = 'none';
        else
            subtype = constants.cpuSubType[cputype][cpusubtype];

        // Stringify flags
        var flagMap = this.mapFlags(flags, constants.flags);

        return {
            bits: bits,
            magic: magic,
            cpu: {
                type: cputype,
                subtype: subtype,
                endian: endian
            },
            filetype: constants.fileType[filetype],
            ncmds: ncmds,
            sizeofcmds: sizeofcmds,
            flags: flagMap,

            cmds: null,
            hsize: bits === 32 ? 28 : 32,
            body: bits === 32 ? buf.slice(28) : buf.slice(32)
        };
    }

    parseMain(type: any, buf: any) {
        if (buf.length < 16)
            throw new Error('main OOB');

        return {
            type: type,
            entryoff: super.readUInt64(buf, 0),
            stacksize: super.readUInt64(buf, 8)
        };
    }
    mapFlags(value: any, map: any) {
        var res: any = {};

        for (var bit = 1; (value < 0 || bit <= value) && bit !== 0; bit <<= 1)
            if (value & bit)
                res[map[bit]] = true;

        return res;
    }
    parseCommands(hdr: any, buf: any, file: any) {
        var cmds: any[] = [];

        const align: number = (hdr.bits === 32) ? 4 : 8;

        for (var offset = 0, i = 0; offset + 8 < buf.length, i < hdr.ncmds; i++) {
            var type = constants.cmdType[super.readUInt32(buf, offset)];
            var size = super.readUInt32(buf, offset + 4) - 8;

            var fileoff = offset + hdr.hsize;
            offset += 8;
            if (offset + size > buf.length) {
                throw new Error('Command body OOB');
            }
            var body = buf.slice(offset, offset + size);
            offset += size;
            if (offset & align)
                offset += align - (offset & align);

            var cmd : any = this.parseCommand(type, body, file);
            cmd.fileoff = fileoff;
            cmds.push(cmd);
        }

        return cmds;
    }
    parseFunctionStarts(type: any, buf: any, file: any) {
        if (buf.length !== 8)
            throw new Error('function_starts OOB');

        var dataoff = super.readUInt32(buf, 0);
        var datasize = super.readUInt32(buf, 4);
        var data = file.slice(dataoff, dataoff + datasize);

        var addresses = [];
        var address = 0; // TODO? use start address / "base address"

        // read array of uleb128-encoded deltas
        var delta = 0, shift = 0;
        for (var i = 0; i < data.length; i++) {
            delta |= (data[i] & 0x7f) << shift;
            if ((data[i] & 0x80) !== 0) { // delta value not finished yet
                shift += 7;
                if (shift > 24)
                    throw new Error('function_starts delta too large');
                else if (i + 1 === data.length)
                    throw new Error('function_starts delta truncated');
            } else if (delta === 0) { // end of table
                break;
            } else {
                address += delta;
                addresses.push(address);
                delta = 0;
                shift = 0;
            }
        }

        return {
            type: type,
            dataoff: dataoff,
            datasize: datasize,
            addresses: addresses
        };
    }
    parseSegmentCmd(type: any, buf: any, file: any) {
        var total = type === 'segment' ? 48 : 64;
        if (buf.length < total)
            throw new Error('Segment command OOB');

        var name = this.parseCStr(buf.slice(0, 16));

        if (type === 'segment') {
            var vmaddr = super.readUInt32(buf, 16);
            var vmsize = super.readUInt32(buf, 20);
            var fileoff = super.readUInt32(buf, 24);
            var filesize = super.readUInt32(buf, 28);
            var maxprot = super.readUInt32(buf, 32);
            var initprot = super.readUInt32(buf, 36);
            var nsects = super.readUInt32(buf, 40);
            var flags = super.readUInt32(buf, 44);
        } else {
            var vmaddr = super.readUInt64(buf, 16);
            var vmsize = super.readUInt64(buf, 24);
            var fileoff = super.readUInt64(buf, 32);
            var filesize = super.readUInt64(buf, 40);
            var maxprot = super.readUInt32(buf, 48);
            var initprot = super.readUInt32(buf, 52);
            var nsects = super.readUInt32(buf, 56);
            var flags = super.readUInt32(buf, 60);
        }

        function prot(p:any) {
            var res = { read: false, write: false, exec: false };
            if (p !== constants.prot.none) {
                res.read = (p & constants.prot.read) !== 0;
                res.write = (p & constants.prot.write) !== 0;
                res.exec = (p & constants.prot.execute) !== 0;
            }
            return res;
        }

        const sectSize = type === 'segment' ? 32 + 9 * 4 : 32 + 8 * 4 + 2 * 8;
        const sections: any = [];
        for (let i = 0, off = total; i < nsects; i++, off += sectSize) {
            if (off + sectSize > buf.length)
                throw new Error('Segment OOB');

            const sectname = this.parseCStr(buf.slice(off, off + 16));
            const segname = this.parseCStr(buf.slice(off + 16, off + 32));

            if (type === 'segment') {
                var addr = super.readUInt32(buf, off + 32);
                var size = super.readUInt32(buf, off + 36);
                var offset = super.readUInt32(buf, off + 40);
                var align = super.readUInt32(buf, off + 44);
                var reloff = super.readUInt32(buf, off + 48);
                var nreloc = super.readUInt32(buf, off + 52);
                var flags = super.readUInt32(buf, off + 56);
            } else {
                var addr = super.readUInt64(buf, off + 32);
                var size = super.readUInt64(buf, off + 40);
                var offset = super.readUInt32(buf, off + 48);
                var align = super.readUInt32(buf, off + 52);
                var reloff = super.readUInt32(buf, off + 56);
                var nreloc = super.readUInt32(buf, off + 60);
                var flags = super.readUInt32(buf, off + 64);
            }

            sections.push({
                sectname: sectname,
                segname: segname,
                addr: addr,
                size: size,
                offset: offset,
                align: align,
                reloff: reloff,
                nreloc: nreloc,
                type: constants.segType[flags & constants.segTypeMask],
                attributes: {
                    usr: this.mapFlags(flags & constants.segAttrUsrMask,
                        constants.segAttrUsr),
                    sys: this.mapFlags(flags & constants.segAttrSysMask,
                        constants.segAttrSys)
                },
                data: file.slice(offset, offset + size)
            });
        }

        return {
            type: type,
            name: name,
            vmaddr: vmaddr,
            vmsize: vmsize,
            fileoff: fileoff,
            filesize: filesize,
            maxprot: prot(maxprot),
            initprot: prot(initprot),
            nsects: nsects,
            flags: this.mapFlags(flags, constants.segFlag),
            sections: sections
        };
    }
    parseLinkEdit(type: any, buf: any) {
        if (buf.length !== 8)
            throw new Error('link_edit OOB');

        return {
            type: type,
            dataoff: super.readUInt32(buf, 0),
            datasize: super.readUInt32(buf, 4)
        };
    }

    parseCStr(buf: any) {
        for (var i = 0; i < buf.length; i++)
            if (buf[i] === 0)
                break;
        return buf.slice(0, i).toString();
    }

    parseCommand(type: any, buf: any, file: any) {
        if (type === 'segment')
            return this.parseSegmentCmd(type, buf, file);
        else if (type === 'segment_64')
            return this.parseSegmentCmd(type, buf, file);
        else if (type === 'symtab')
            return this.parseSymtab(type, buf);
        else if (type === 'symseg')
            return this.parseSymseg(type, buf);
        else if (type === 'encryption_info')
            return this.parseEncryptionInfo(type, buf);
        else if (type === 'encryption_info_64')
            return this.parseEncryptionInfo64(type, buf);
        else if (type === 'rpath')
            return this.parseRpath(type, buf);
        else if (type === 'dysymtab')
            return this.parseDysymtab(type, buf);
        else if (type === 'load_dylib' || type === 'id_dylib')
            return this.parseLoadDylib(type, buf);
        else if (type === 'load_weak_dylib')
            return this.parseLoadDylib(type, buf);
        else if (type === 'load_dylinker' || type === 'id_dylinker')
            return this.parseLoadDylinker(type, buf);
        else if (type === 'version_min_macosx' || type === 'version_min_iphoneos')
            return this.parseVersionMin(type, buf);
        else if (type === 'code_signature' || type === 'segment_split_info')
            return this.parseLinkEdit(type, buf);
        else if (type === 'function_starts')
            return this.parseFunctionStarts(type, buf, file);
        else if (type === 'data_in_code')
            return this.parseLinkEdit(type, buf);
        else if (type === 'dylib_code_sign_drs')
            return this.parseLinkEdit(type, buf);
        else if (type === 'main')
            return this.parseMain(type, buf);
        else
            return { type: type, data: buf };
    }
    parseSymtab(type: any, buf: any) {
        if (buf.length !== 16)
            throw new Error('symtab OOB');

        return {
            type: type,
            symoff: super.readUInt32(buf, 0),
            nsyms: super.readUInt32(buf, 4),
            stroff: super.readUInt32(buf, 8),
            strsize: super.readUInt32(buf, 12)
        };
    }

    parseSymseg(type: any, buf: any) {
        if (buf.length !== 8)
            throw new Error('symseg OOB');

        return {
            type: type,
            offset: super.readUInt32(buf, 0),
            size: super.readUInt32(buf, 4)
        };
    }

    parseEncryptionInfo(type: any, buf: any) {
        if (buf.length !== 12)
            throw new Error('encryptinfo OOB');

        return {
            type: type,
            offset: super.readUInt32(buf, 0),
            size: super.readUInt32(buf, 4),
            id: super.readUInt32(buf, 8),
        };
    }

    parseEncryptionInfo64(type: any, buf: any) {
        if (buf.length !== 16)
            throw new Error('encryptinfo64 OOB');

        return this.parseEncryptionInfo(type, buf.slice(0, 12));
    }

    parseDysymtab(type: any, buf: any) {
        if (buf.length !== 72) {
            throw new Error('dysymtab OOB');
        }

        return {
            type: type,
            ilocalsym: super.readUInt32(buf, 0),
            nlocalsym: super.readUInt32(buf, 4),
            iextdefsym: super.readUInt32(buf, 8),
            nextdefsym: super.readUInt32(buf, 12),
            iundefsym: super.readUInt32(buf, 16),
            nundefsym: super.readUInt32(buf, 20),
            tocoff: super.readUInt32(buf, 24),
            ntoc: super.readUInt32(buf, 28),
            modtaboff: super.readUInt32(buf, 32),
            nmodtab: super.readUInt32(buf, 36),
            extrefsymoff: super.readUInt32(buf, 40),
            nextrefsyms: super.readUInt32(buf, 44),
            indirectsymoff: super.readUInt32(buf, 48),
            nindirectsyms: super.readUInt32(buf, 52),
            extreloff: super.readUInt32(buf, 56),
            nextrel: super.readUInt32(buf, 60),
            locreloff: super.readUInt32(buf, 64),
            nlocrel: super.readUInt32(buf, 68)
        };
    }

    parseLoadDylinker(type: any, buf: any) {
        return {
            type: type,
            cmd: this.parseLCStr(buf, 0)
        };
    }

    parseRpath(type: any, buf: any) {
        if (buf.length < 8)
            throw new Error('lc_rpath OOB');

        return {
            type: type,
            name: this.parseLCStr(buf, 0),
        };
    }

    parseLoadDylib(type: any, buf: any) {
        if (buf.length < 16) {
            throw new Error('load_dylib OOB');
        }
        return {
            type: type,
            name: this.parseLCStr(buf, 0),
            timestamp: super.readUInt32(buf, 4),
            current_version: super.readUInt32(buf, 8),
            compatibility_version: super.readUInt32(buf, 12)
        };
    }

    parseVersionMin(type: any, buf: any) {
        if (buf.length !== 8)
            throw new Error('min version OOB');

        return {
            type: type,
            version: super.readUInt16(buf, 2) + '.' + buf[1] + '.' + buf[0],
            sdk: super.readUInt16(buf, 6) + '.' + buf[5] + '.' + buf[4]
        };
    }
};

// NOTE: returned addresses are relative to the "base address", i.e.
//       the vmaddress of the first "non-null" segment [e.g. initproto!=0]
//       (i.e. __TEXT ?)