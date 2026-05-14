import java.io.FileWriter;
import java.lang.reflect.Method;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

public class memory extends GhidraScript {
    FileWriter out;

    public void run() throws Exception {
        String[] args = getScriptArgs();
        out = new FileWriter(args[0]);

        if (args[1].equals("read_memory")) readMemory(args[2], Integer.decode(args[3]), args[4]);
        if (args[1].equals("sections")) sections();
        if (args[1].equals("read_section")) readSection(args[2], args[3]);
        if (args[1].equals("va_to_file_offset")) vaToFileOffset(args[2]);

        out.close();
    }

    void readMemory(String addrText, int length, String format) throws Exception {
        Address addr = currentProgram.getAddressFactory().getAddress(addrText);
        if (addr == null) {
            out.write("{\"error\":\"bad address\"}");
            return;
        }

        byte[] bytes = new byte[length];
        int read = currentProgram.getMemory().getBytes(addr, bytes);
        writeBytes(addr.toString(), bytes, read, format);
    }

    void sections() throws Exception {
        Memory memory = currentProgram.getMemory();
        MemoryBlock[] blocks = memory.getBlocks();
        out.write("{\"sections\":[");
        for (int i = 0; i < blocks.length; i++) {
            MemoryBlock b = blocks[i];
            if (i > 0) out.write(",");
            out.write("{\"name\":" + q(b.getName()));
            out.write(",\"start\":" + q(b.getStart().toString()));
            out.write(",\"end\":" + q(b.getEnd().toString()));
            out.write(",\"size\":" + b.getSize());
            out.write(",\"read\":" + b.isRead());
            out.write(",\"write\":" + b.isWrite());
            out.write(",\"execute\":" + b.isExecute());
            out.write(",\"initialized\":" + b.isInitialized());
            Long off = fileOffset(b, b.getStart());
            if (off != null) out.write(",\"file_offset\":" + off);
            out.write("}");
        }
        out.write("]}");
    }

    void readSection(String name, String format) throws Exception {
        MemoryBlock block = currentProgram.getMemory().getBlock(name);
        if (block == null) {
            out.write("{\"error\":\"section not found\"}");
            return;
        }
        int length = (int)Math.min(block.getSize(), 1024 * 1024);
        byte[] bytes = new byte[length];
        int read = currentProgram.getMemory().getBytes(block.getStart(), bytes);
        writeBytes(block.getStart().toString(), bytes, read, format);
    }

    void vaToFileOffset(String addrText) throws Exception {
        Address addr = currentProgram.getAddressFactory().getAddress(addrText);
        if (addr == null) {
            out.write("{\"error\":\"bad address\"}");
            return;
        }
        MemoryBlock block = currentProgram.getMemory().getBlock(addr);
        if (block == null) {
            out.write("{\"error\":\"address not mapped\",\"address\":" + q(addrText) + "}");
            return;
        }
        Long off = fileOffset(block, addr);
        out.write("{\"address\":" + q(addr.toString()));
        out.write(",\"section\":" + q(block.getName()));
        if (off == null) {
            out.write(",\"file_offset\":null");
        } else {
            out.write(",\"file_offset\":" + off);
            out.write(",\"file_offset_hex\":" + q("0x" + Long.toHexString(off)));
        }
        out.write("}");
    }

    Long fileOffset(MemoryBlock block, Address addr) {
        try {
            Method getSourceInfos = block.getClass().getMethod("getSourceInfos");
            List infos = (List)getSourceInfos.invoke(block);
            if (infos == null || infos.size() == 0) return null;
            Object info = infos.get(0);
            try {
                Method getFileBytesOffsetAt = info.getClass().getMethod("getFileBytesOffset", Address.class);
                long offset = ((Number)getFileBytesOffsetAt.invoke(info, addr)).longValue();
                if (offset >= 0) return offset;
            } catch (Exception ignored) {
            }
            Method getFileBytesOffset = info.getClass().getMethod("getFileBytesOffset");
            long startOffset = ((Number)getFileBytesOffset.invoke(info)).longValue();
            if (startOffset < 0) return null;
            return startOffset + addr.subtract(block.getStart());
        } catch (Exception e) {
            return null;
        }
    }

    void writeBytes(String address, byte[] bytes, int read, String format) throws Exception {
        out.write("{\"address\":" + q(address));
        out.write(",\"length\":" + read);
        if (format.equals("bytes")) {
            out.write(",\"bytes\":[");
            for (int i = 0; i < read; i++) {
                if (i > 0) out.write(",");
                out.write(Integer.toString(bytes[i] & 0xff));
            }
            out.write("]");
        } else if (format.equals("ascii")) {
            out.write(",\"ascii\":" + q(ascii(bytes, read)));
        } else {
            out.write(",\"hex\":" + q(hex(bytes, read)));
            out.write(",\"ascii\":" + q(ascii(bytes, read)));
        }
        out.write("}");
    }

    String hex(byte[] bytes, int length) {
        StringBuilder s = new StringBuilder();
        for (int i = 0; i < length; i++) {
            if (i > 0) s.append(" ");
            s.append(String.format("%02x", bytes[i] & 0xff));
        }
        return s.toString();
    }

    String ascii(byte[] bytes, int length) {
        StringBuilder s = new StringBuilder();
        for (int i = 0; i < length; i++) {
            int b = bytes[i] & 0xff;
            s.append(b >= 0x20 && b < 0x7f ? (char)b : '.');
        }
        return s.toString();
    }

    String q(String s) {
        if (s == null) return "null";
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r") + "\"";
    }
}
