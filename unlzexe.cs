using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

static class Program
{
    const int FAILURE = 1;
    const int SUCCESS = 0;

    const int EXIT_FAILURE = 1;

    static string tmpfname = "$tmpfil$.exe";
    static string backup_ext = ".olz";
    static string? ifname, ifext,    //ipath argv[0] an LZEXE file.
                   ofdir, ofname;   //opath from argv[1] else =ipath 
                                   // <-- fnamechk
    static string ipath { get => ifname + ifext; }
    static string bkpath { get => ifname + backup_ext; }
    static string opath {get=>ofdir + ofname;}
    static string tmpfpath {get=>ofdir + tmpfname;}

    static int Main(string[] argv)
    {
        var argc = argv.Length;
        Stream ifile, ofile;  // <-- File.Open
        int ver;  // <-- rdhead
        bool rename_sw = (argc == 1);
            //  true: ifile moved to bkpath, ofile takes ipath
           // false: ofile takes user provided path, ifile stays in place

        Console.WriteLine("UNLZEXE Ver. 0.6");
        if(argc != 2 && argc != 1)
        {
            Console.WriteLine("usage: UNLZEXE packedfile [unpackedfile]");
            return EXIT_FAILURE;
        }
        if(fnamechk(out ifname, out ifext, out ofdir, out ofname, argc, argv) != SUCCESS)
        {
            return EXIT_FAILURE;
        }

        try
        {
            ifile = File.Open(ipath, FileMode.Open, FileAccess.Read);
        } catch
        {
            Console.WriteLine($"'{ipath}' :not found");
            return EXIT_FAILURE;
        }

        if(rdhead(ifile, out ver) != SUCCESS)
        {
            Console.WriteLine($"'{ipath}' is not LZEXE file.");
            ifile.Close();
            return EXIT_FAILURE;
        }
        try
        {
            ofile = File.Open(tmpfpath, FileMode.Create, FileAccess.Write);
        } catch
        {
            Console.WriteLine($"can't open '{tmpfpath}'.");
            ifile.Close();
            return EXIT_FAILURE;
        }
        Console.WriteLine($"file '{ipath}' is compressed by LZEXE Ver. 0.{ver}");
        var ireader = new BinaryReader(ifile);
        var owriter = new BinaryWriter(ofile);
        if(mkreltbl(ireader, owriter, ver) != SUCCESS)
        {
            ifile.Close();
            ofile.Close();
            File.Delete(tmpfpath);
            return EXIT_FAILURE;
        }
        if(unpack(ireader, owriter) != SUCCESS)
        {
            ifile.Close();
            ofile.Close();
            File.Delete(tmpfpath);
            return EXIT_FAILURE;
        }
        ifile.Close();
        wrhead(owriter);
        ofile.Close();

        if(fnamechg(ipath, ofdir, ofname, rename_sw) != SUCCESS)
        {
            return EXIT_FAILURE;
        }
        return 0;
    }

    /* file name check */
    static int fnamechk(out string ifname, out string ifext, out string ofdir, out string ofname,
                  int argc, string[] argv)
    {
        int idx_name, idx_ext;   // seperation points of directory, basename and extention
                                 // <-- parsepath
        string opath;
        string ipath = argv[0];
        ofdir = "";
        ofname = "";
        parsepath(ipath, out idx_name, out idx_ext);
        ifname = ipath.Substring(0, idx_ext);
        ifext = (idx_ext < ipath.Length) ? ipath.Substring(idx_ext) : ".exe"; //add .exe if no extention
        ipath = Program.ipath;
        if(tmpfname.Equals(ipath + idx_name, StringComparison.OrdinalIgnoreCase))
        {   Console.WriteLine($"'{ipath}':bad filename.");
            return FAILURE;
        } 
        if(argc == 1)
            opath = ipath;
        else
            opath = argv[1];
        parsepath(opath, out idx_name, out idx_ext);
        ofname = opath.Substring(idx_name);               // <base>.<ext>
        ofdir = opath.Substring(0, idx_name);            // <dir>
        if(idx_ext >= opath.Length) {ofname += ".exe";}  //add .exe if no extention
        else if(backup_ext.Equals(opath + idx_ext, StringComparison.OrdinalIgnoreCase)) 
        {   Console.WriteLine($"'{opath}':bad filename.");
            return FAILURE;
        }
        return SUCCESS;
    }

    static int fnamechg(string ipath, string ofdir, string ofname, bool rename_sw)
    {
        if(rename_sw && !backup_ext.Equals(ifext, StringComparison.OrdinalIgnoreCase))
        {   
            File.Delete(bkpath);
            try
            {
                File.Move(ipath, bkpath);
            } catch
            {
                Console.WriteLine($"can't make '{bkpath}'.");
                File.Delete(tmpfpath);
                return FAILURE;
            }
            Console.WriteLine($"'{ipath}' is renamed to '{bkpath}'.");
        }
        if (!tmpfname.Equals(ofname, StringComparison.OrdinalIgnoreCase))
        {   
            File.Delete(opath);
        }
        try
        {
            File.Move(tmpfpath, opath);
        } catch
        {
            if(rename_sw)
            {   //return ifile to its place
                File.Move(bkpath, ipath);
            }
            Console.WriteLine($"can't make '{opath}'.  unpacked file '{tmpfname}' is remained.");
            return FAILURE;
        }
        Console.WriteLine($"unpacked file '{opath}' is generated.");
        return SUCCESS;
    }

    static void parsepath(string pathname, out int fname, out int ext)
    {
        int i;

        fname = 0; ext = 0;
        for(i = 0; i < pathname.Length; i++)
        {
            switch(pathname[i])
            {
                case ':':
                case '/':
                case '\\': fname = i + 1; break;
                case '.': ext = i; break;
            }
        }
        if(ext <= fname) ext = i;
    }
    static string[] MZtemplate = ["magic", "cblp", "cp", "crlc", "cparhdr", "minalloc", "maxalloc", "ss", "sp", "csum", "ip", "cs", "lfarlc", "ovno"];
    static string[] LZtemplate = ["ip", "cs", "sp", "ss", "loadsize", "incsize", "csize", "crcchk"];

    static Dictionary<string,ushort> HeaderInit(byte[] buffer, string[] template)
    {
        Debug.Assert(buffer.Length == template.Length);

        Span<ushort> head = MemoryMarshal.Cast<byte, ushort>(buffer.AsSpan());
        Dictionary<string, ushort> back = new();
        for(int i=0;i<template.Length;i++)
        {
            back.Add(template[i], head[i]);
        }
        return back;
    }

    static byte[] HeaderUnload(Dictionary<string, ushort> head, string[] template)
    {
        var buffer = (from name in template select head[name]).ToArray();
        byte[] back = new byte[template.Length * sizeof(ushort)];
        for (int i = 0; i < template.Length; i++)
        {
            back[i] = ((byte)buffer[i*2]);
            back[i+1] = ((byte)(buffer[i*2] >> 8));
        }
        return back;
    }

    static Dictionary<string, ushort> ihead = new();
    static Dictionary<string, ushort> ohead = new();
    static Dictionary<string, ushort> inf = new();
    static long loadsize;
    static byte[] sig90 = {
        0x06, 0x0E, 0x1F, 0x8B, 0x0E, 0x0C, 0x00, 0x8B,
        0xF1, 0x4E, 0x89, 0xF7, 0x8C, 0xDB, 0x03, 0x1E,
        0x0A, 0x00, 0x8E, 0xC3, 0xB4, 0x00, 0x31, 0xED,
        0xFD, 0xAC, 0x01, 0xC5, 0xAA, 0xE2, 0xFA, 0x8B,
        0x16, 0x0E, 0x00, 0x8A, 0xC2, 0x29, 0xC5, 0x8A,
        0xC6, 0x29, 0xC5, 0x39, 0xD5, 0x74, 0x0C, 0xBA,
        0x91, 0x01, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0xFF,
        0x4C, 0xCD, 0x21, 0x53, 0xB8, 0x53, 0x00, 0x50,
        0xCB, 0x2E, 0x8B, 0x2E, 0x08, 0x00, 0x8C, 0xDA,
        0x89, 0xE8, 0x3D, 0x00, 0x10, 0x76, 0x03, 0xB8,
        0x00, 0x10, 0x29, 0xC5, 0x29, 0xC2, 0x29, 0xC3,
        0x8E, 0xDA, 0x8E, 0xC3, 0xB1, 0x03, 0xD3, 0xE0,
        0x89, 0xC1, 0xD1, 0xE0, 0x48, 0x48, 0x8B, 0xF0,
        0x8B, 0xF8, 0xF3, 0xA5, 0x09, 0xED, 0x75, 0xD8,
        0xFC, 0x8E, 0xC2, 0x8E, 0xDB, 0x31, 0xF6, 0x31,
        0xFF, 0xBA, 0x10, 0x00, 0xAD, 0x89, 0xC5, 0xD1,
        0xED, 0x4A, 0x75, 0x05, 0xAD, 0x89, 0xC5, 0xB2,
        0x10, 0x73, 0x03, 0xA4, 0xEB, 0xF1, 0x31, 0xC9,
        0xD1, 0xED, 0x4A, 0x75, 0x05, 0xAD, 0x89, 0xC5,
        0xB2, 0x10, 0x72, 0x22, 0xD1, 0xED, 0x4A, 0x75,
        0x05, 0xAD, 0x89, 0xC5, 0xB2, 0x10, 0xD1, 0xD1,
        0xD1, 0xED, 0x4A, 0x75, 0x05, 0xAD, 0x89, 0xC5,
        0xB2, 0x10, 0xD1, 0xD1, 0x41, 0x41, 0xAC, 0xB7,
        0xFF, 0x8A, 0xD8, 0xE9, 0x13, 0x00, 0xAD, 0x8B,
        0xD8, 0xB1, 0x03, 0xD2, 0xEF, 0x80, 0xCF, 0xE0,
        0x80, 0xE4, 0x07, 0x74, 0x0C, 0x88, 0xE1, 0x41,
        0x41, 0x26, 0x8A, 0x01, 0xAA, 0xE2, 0xFA, 0xEB,
        0xA6, 0xAC, 0x08, 0xC0, 0x74, 0x40, 0x3C, 0x01,
        0x74, 0x05, 0x88, 0xC1, 0x41, 0xEB, 0xEA, 0x89
    }, sig91 = {
        0x06, 0x0E, 0x1F, 0x8B, 0x0E, 0x0C, 0x00, 0x8B,
        0xF1, 0x4E, 0x89, 0xF7, 0x8C, 0xDB, 0x03, 0x1E,
        0x0A, 0x00, 0x8E, 0xC3, 0xFD, 0xF3, 0xA4, 0x53,
        0xB8, 0x2B, 0x00, 0x50, 0xCB, 0x2E, 0x8B, 0x2E,
        0x08, 0x00, 0x8C, 0xDA, 0x89, 0xE8, 0x3D, 0x00,
        0x10, 0x76, 0x03, 0xB8, 0x00, 0x10, 0x29, 0xC5,
        0x29, 0xC2, 0x29, 0xC3, 0x8E, 0xDA, 0x8E, 0xC3,
        0xB1, 0x03, 0xD3, 0xE0, 0x89, 0xC1, 0xD1, 0xE0,
        0x48, 0x48, 0x8B, 0xF0, 0x8B, 0xF8, 0xF3, 0xA5,
        0x09, 0xED, 0x75, 0xD8, 0xFC, 0x8E, 0xC2, 0x8E,
        0xDB, 0x31, 0xF6, 0x31, 0xFF, 0xBA, 0x10, 0x00,
        0xAD, 0x89, 0xC5, 0xD1, 0xED, 0x4A, 0x75, 0x05,
        0xAD, 0x89, 0xC5, 0xB2, 0x10, 0x73, 0x03, 0xA4,
        0xEB, 0xF1, 0x31, 0xC9, 0xD1, 0xED, 0x4A, 0x75,
        0x05, 0xAD, 0x89, 0xC5, 0xB2, 0x10, 0x72, 0x22,
        0xD1, 0xED, 0x4A, 0x75, 0x05, 0xAD, 0x89, 0xC5,
        0xB2, 0x10, 0xD1, 0xD1, 0xD1, 0xED, 0x4A, 0x75,
        0x05, 0xAD, 0x89, 0xC5, 0xB2, 0x10, 0xD1, 0xD1,
        0x41, 0x41, 0xAC, 0xB7, 0xFF, 0x8A, 0xD8, 0xE9,
        0x13, 0x00, 0xAD, 0x8B, 0xD8, 0xB1, 0x03, 0xD2,
        0xEF, 0x80, 0xCF, 0xE0, 0x80, 0xE4, 0x07, 0x74,
        0x0C, 0x88, 0xE1, 0x41, 0x41, 0x26, 0x8A, 0x01,
        0xAA, 0xE2, 0xFA, 0xEB, 0xA6, 0xAC, 0x08, 0xC0,
        0x74, 0x34, 0x3C, 0x01, 0x74, 0x05, 0x88, 0xC1,
        0x41, 0xEB, 0xEA, 0x89, 0xFB, 0x83, 0xE7, 0x0F,
        0x81, 0xC7, 0x00, 0x20, 0xB1, 0x04, 0xD3, 0xEB,
        0x8C, 0xC0, 0x01, 0xD8, 0x2D, 0x00, 0x02, 0x8E,
        0xC0, 0x89, 0xF3, 0x83, 0xE6, 0x0F, 0xD3, 0xEB,
        0x8C, 0xD8, 0x01, 0xD8, 0x8E, 0xD8, 0xE9, 0x72
    }, sigbuf = new byte[sig90.Length];

    /* EXE header test (is it LZEXE file?) */
    static int rdhead(Stream ifile, out int ver)
    {
        long entry;
        byte[]  ihead_buffer = new byte[0x10 * sizeof(ushort)], 
                ohead_buffer = new byte[0x10 * sizeof(ushort)];

        ver = 0;
        if(ifile.Read(ihead_buffer, 0, ihead_buffer.Length) != ihead_buffer.Length)
            return FAILURE;
        ihead = HeaderInit(ihead_buffer, MZtemplate);
        Array.Copy(ihead_buffer, ohead_buffer, ohead_buffer.Length);
        ohead = HeaderInit(ohead_buffer, MZtemplate);
        if ((ihead["magic"] != 0x5a4d && ihead["magic"] != 0x4d5a) ||
           ihead["ovno"] != 0 || ihead["lfarlc"] != 0x1c)  
            return FAILURE;  //not a valid MZ EXE (with no overlay information)
        entry = ((long)(ihead["cparhdr"] + ihead["cs"]) << 4) + ihead["ip"];
        ifile.Position = entry;
        if(ifile.Read(sigbuf, 0, sigbuf.Length) != sigbuf.Length) // ifile.position = cs:(e_ip + 0xe8) 
            return FAILURE;
        if(Enumerable.SequenceEqual(sigbuf, sig90))
        {
            ver = 90;
            return SUCCESS;
        }
        if(Enumerable.SequenceEqual(sigbuf, sig91))
        {
            ver = 91;
            return SUCCESS;
        }
        return FAILURE;
    }

    /* make relocation table */
    static int mkreltbl(BinaryReader ifile, BinaryWriter ofile, int ver)
    {
        long fpos;
        int i;
        byte[] inf_buffer = new byte[8 * sizeof(ushort)];

        fpos = (long)(ihead["cs"] + ihead["cparhdr"]) << 4;		/* goto CS:0000 */
        ifile.BaseStream.Position = fpos;
        ifile.Read(inf_buffer, 0, inf_buffer.Length); //lz header
        inf = HeaderInit(inf_buffer, LZtemplate);
        ohead["ip"] = inf["ip"];
        ohead["cs"] = inf["cs"];
        ohead["sp"] = inf["sp"];
        ohead["ss"] = inf["ss"];
        /* inf[4]:size of compressed load module (PARAGRAPH)*/
        /* inf[5]:increase of load module size (PARAGRAPH)*/
        /* inf[6]:size of decompressor with  compressed relocation table (BYTE) */
        /* inf[7]:check sum of decompresser with compressd relocation table(Ver.0.90) */
        ohead["lfarlc"] = 0x1c;		/* start position of relocation table */
        ofile.BaseStream.Position = 0x1cL;
        switch(ver)
        {
            case 90:
                i = reloc90(ifile, ofile, fpos);
                break;
            case 91:
                i = reloc91(ifile, ofile, fpos);
                break;
            default: i = FAILURE; break;
        }
        if(i != SUCCESS)
        {
            Console.WriteLine("error at relocation table.");
            return (FAILURE);
        }
        fpos = ofile.BaseStream.Position; //0x1cL + 4*ohead["crlc"] (2 words per relocation)
        i = (0x200 - (int)fpos) & 0x1ff;  //complement to a disk sector
        ohead["cparhdr"] = unchecked((ushort)(int)((fpos + i) >> 4));

        for(; i > 0; i--)
            ofile.Write((byte)0);
        return SUCCESS;
    }
    /* for LZEXE ver 0.90 */
    static int reloc90(BinaryReader ifile, BinaryWriter ofile, long fpos)
    {
        uint c;
        ushort rel_count = 0;
        ushort rel_seg, rel_off;

        ifile.BaseStream.Position = fpos + 0x19d;  // cs:019d after functions
        /* 0x19d=compressed relocation table address */
        rel_seg = 0;
        do
        {
            if(ifile.BaseStream.Position >= ifile.BaseStream.Length) return FAILURE;
            c = ifile.ReadUInt16();
            for(; c > 0; c--)
            {
                rel_off = ifile.ReadUInt16();
                ofile.Write(rel_off);
                ofile.Write(rel_seg);
                rel_count++;
            }
            rel_seg += 0x1000;
        } while(rel_seg != 0);
        ohead["crlc"] = rel_count;
        return (SUCCESS);
    }
    /* for LZEXE ver 0.91*/
    static int reloc91(BinaryReader ifile, BinaryWriter ofile, long fpos)
    {
        ushort span;
        ushort rel_count = 0;
        ushort rel_seg, rel_off;

        ifile.BaseStream.Position = fpos + 0x158; // cs:0158 after functions
        /* 0x158=compressed relocation table address */
        rel_off = 0; rel_seg = 0;
        for(; ; )
        {
            if(ifile.BaseStream.Position >= ifile.BaseStream.Length) return (FAILURE);
            if((span = (byte)ifile.ReadByte()) == 0)
            {
                span = ifile.ReadUInt16();
                if(span == 0)
                {
                    rel_seg += 0x0fff;
                    continue;
                } else if(span == 1)
                {
                    break;
                }
            }
            rel_off += span;
            rel_seg += unchecked((ushort)((rel_off & ~0x0f) >> 4));
            rel_off &= 0x0f;
            ofile.Write(rel_off);
            ofile.Write(rel_seg);
            rel_count++;
        }
        ohead["crlc"] = rel_count;
        return (SUCCESS);
    }

    /*---------------------*/
    struct Bitstream
    {
        public BinaryReader fp;
        public ushort buf;
        public byte count;
    }

    static byte[] data = new byte[0x4500];

    /*---------------------*/
    /* decompressor routine */
    static int unpack(BinaryReader ifile, BinaryWriter ofile)
    {
        int len;
        ushort span;
        long fpos;
        var bits = default(Bitstream);
        int p = 0;

        fpos = ((long)ihead["cs"] - (long)inf["loadsize"] + (long)ihead["cparhdr"]) << 4; //(cs-loadsize):0
        ifile.BaseStream.Position = fpos;
        fpos = (long)ohead["cparhdr"] << 4;  //after the padded header
        ofile.BaseStream.Position = fpos;
        initbits(ref bits, ifile);
        Console.WriteLine(" unpacking. ");
        for(; ; )
        {
            if(p > 0x4000)
            {
                ofile.Write(data, 0, 0x2000);
                p -= 0x2000;
                Array.Copy(data, 0x2000, data, 0, p);
                Console.Write('.');
            }
            if(getbit(ref bits) != 0)
            {
                data[p++] = (byte)ifile.ReadByte();
                continue;
            }
            if(getbit(ref bits) == 0)
            {
                len = getbit(ref bits) << 1;
                len |= getbit(ref bits);
                len += 2;
                span = unchecked((ushort)((byte)ifile.ReadByte() | 0xff00));
            } else
            {
                span = (byte)ifile.ReadByte();
                len = (byte)ifile.ReadByte();
                span = unchecked((ushort)(span | ((len & ~0x07) << 5) | 0xe000));
                len = (len & 0x07) + 2;
                if(len == 2)
                {
                    len = (byte)ifile.ReadByte();
                    if(len == 0)
                        break;    /* end mark of compreesed load module */
                    if(len == 1)
                        continue; /* segment change */
                    else
                        len++;
                }
            }
            for(; len > 0; len--, p++)
            {
                data[p] = data[p + unchecked((short)span)];
            }
        }
        if(p != 0)
            ofile.Write(data, 0, p);
        loadsize = ofile.BaseStream.Position - fpos;
        Console.WriteLine("end");
        return (SUCCESS);
    }

    /* write EXE header*/
    static void wrhead(BinaryWriter ofile)
    {
        if(ihead["maxalloc"] != 0)
        {
            ohead["minalloc"] -= unchecked((ushort)(inf["incsize"] + ((inf["csize"] + 0xf) >> 4) + 9));
            if(ihead["maxalloc"] != 0xffff)
                ohead["maxalloc"] -= unchecked((ushort)(ihead["maxalloc"] - ohead["maxalloc"]));
        }
        ohead["cblp"] = unchecked((ushort)(((ushort)loadsize + (ohead["cparhdr"] << 4)) & 0x1ff));
        ohead["cp"] = (ushort)((loadsize + ((long)ohead["cparhdr"] << 4) + 0x1ff) >> 9);
        byte[] ohead_buffer = HeaderUnload(ohead, MZtemplate);
        ofile.BaseStream.Position = 0;
        ofile.Write(ohead_buffer, 0, 0x0e * sizeof(ushort));
    }


    /*-------------------------------------------*/

    /* get compress information bit by bit */
    static void initbits(ref Bitstream p, BinaryReader filep)
    {
        p.fp = filep;
        p.count = 0x10;
        p.buf = p.fp.ReadUInt16();
    }

    static int getbit(ref Bitstream p)
    {
        int b;
        b = p.buf & 1;
        if(--p.count == 0)
        {
            p.buf = p.fp.ReadUInt16();
            p.count = 0x10;
        } else
            p.buf >>= 1;

        return b;
    }
}
