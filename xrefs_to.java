import java.io.FileWriter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class xrefs_to extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        FileWriter out = new FileWriter(args[0]);
        Address addr = currentProgram.getAddressFactory().getAddress(args[1]);
        if (addr == null) {
            out.write("{\"error\":\"bad address\"}");
            out.close();
            return;
        }

        out.write("{\"address\":" + q(addr.toString()) + ",\"xrefs\":[");
        int count = 0;
        ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(addr);
        while (refs.hasNext()) {
            Reference r = refs.next();
            Function f = currentProgram.getFunctionManager().getFunctionContaining(r.getFromAddress());
            if (count > 0) out.write(",");
            out.write("{\"from\":" + q(r.getFromAddress().toString()));
            out.write(",\"type\":" + q(r.getReferenceType().toString()));
            if (f != null) out.write(",\"function\":" + q(f.getName()) + ",\"function_address\":" + q(f.getEntryPoint().toString()));
            out.write("}");
            count++;
        }
        out.write("]}");
        out.close();
    }

    String q(String s) {
        if (s == null) return "null";
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n") + "\"";
    }
}
