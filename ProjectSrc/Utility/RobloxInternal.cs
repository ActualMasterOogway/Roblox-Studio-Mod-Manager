using PeNet;
using PeNet.Header.Pe;
using RobloxStudioModManager;
using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using IcedIntel = Iced.Intel;

namespace Utility
{
    public static class RobloxInternal
    {
        public static async Task Patch(StudioBootstrapper bootstrapper)
        {
            var path = bootstrapper.GetLocalStudioPath();
            bootstrapper.Echo("Applying internal patch...");
            var image = await Task.Run(() => File.ReadAllBytes(path)).ConfigureAwait(false);

            var pe = new PeFile(image);
            ulong imageBase = pe.ImageNtHeaders.OptionalHeader.ImageBase;
            ImageSectionHeader[] sections = pe.ImageSectionHeaders;

            byte[] key = Encoding.ASCII.GetBytes("VoiceChatEnableApiSecurityCheck");
            ulong strAddr = FindStringAddress(image, sections, key, imageBase);
            if (strAddr == 0)
            {
                bootstrapper.Echo("Error: target string not found.");
                return;
            }

            var textSec = sections.FirstOrDefault(s => s.Name.TrimEnd('\0') == ".text");
            if (textSec == null)
            {
                bootstrapper.Echo("Error: .text section missing.");
                return;
            }

            int rawStart = (int)textSec.PointerToRawData;
            int rawSize = (int)textSec.SizeOfRawData;
            ulong textBase = imageBase + (ulong)textSec.VirtualAddress;
            var code = new byte[rawSize];
            Array.Copy(image, rawStart, code, 0, rawSize);

            var codeReader = new IcedIntel.ByteArrayCodeReader(code);
            var decoder = IcedIntel.Decoder.Create(64, codeReader);
            decoder.IP = textBase;

            var instructions = new InstructionList();
            while (codeReader.CanReadByte)
            {
                decoder.Decode(out var insn);
                instructions.Add(insn);
            }

            ulong? patchRip = GetPatchAddress(instructions, strAddr);
            if (!patchRip.HasValue)
            {
                bootstrapper.Echo("Error: patch location not found.");
                return;
            }

            var targetInsn = instructions.First(i => i.IP == patchRip.Value);
            int offset = rawStart + (int)(patchRip.Value - textBase);
            for (int i = 0; i < targetInsn.Length; i++)
                image[offset + i] = 0x90;

            await Task.Run(() => File.WriteAllBytes(path, image)).ConfigureAwait(false);
            bootstrapper.Echo("Internal patch applied successfully.");
        }

        static ulong FindStringAddress(byte[] image, ImageSectionHeader[] secs, byte[] needle, ulong baseAddr)
        {
            foreach (var s in secs)
            {
                string name = s.Name.TrimEnd('\0');
                if (name != ".rdata" && name != ".data") continue;
                int start = (int)s.PointerToRawData;
                int size = (int)s.SizeOfRawData;
                int idx = image.AsSpan(start, size).IndexOf(needle);
                if (idx >= 0)
                    return baseAddr + (ulong)s.VirtualAddress + (ulong)idx;
            }
            return 0;
        }

        static ulong? GetPatchAddress(InstructionList insns, ulong strAddr)
        {
            ulong? idFunc = null;
            for (int i = 0; i < insns.Count; i++)
            {
                var ins = insns[i];
                for (int op = 0; op < ins.OpCount; op++)
                {
                    if (ins.GetOpKind(op) != IcedIntel.OpKind.Memory) continue;
                    if (ins.MemoryBase == IcedIntel.Register.RIP &&
                        (ulong)ins.MemoryDisplacement64 == strAddr &&
                        ins.Mnemonic != IcedIntel.Mnemonic.Lea)
                    {
                        for (int j = i - 1; j >= 0; j--)
                        {
                            var prev = insns[j];
                            if (prev.Mnemonic == IcedIntel.Mnemonic.Call &&
                                !(j > 0 && insns[j - 1].Mnemonic == IcedIntel.Mnemonic.Lea))
                            {
                                idFunc = prev.NearBranchTarget;
                                break;
                            }
                        }
                        break;
                    }
                }
                if (idFunc.HasValue) break;
            }
            if (!idFunc.HasValue) return null;

            for (int i = 1; i < insns.Count; i++)
            {
                var ins = insns[i];
                if (ins.Mnemonic == IcedIntel.Mnemonic.Call &&
                    ins.NearBranchTarget == idFunc.Value &&
                    insns[i - 1].Mnemonic == IcedIntel.Mnemonic.Je)
                {
                    return insns[i - 1].IP;
                }
            }
            return null;
        }

        class InstructionList : System.Collections.Generic.List<IcedIntel.Instruction> { }
    }
}
