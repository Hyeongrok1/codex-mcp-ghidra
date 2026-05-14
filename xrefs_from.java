import java.io.FileWriter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Reference;

public class xrefs_from extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        FileWriter out = new FileWriter(args[0]);
        Address addr = currentProgram.getAddressFactory().getAddress(args[1]);
        if (addr == null) {
            out.write("{\"error\":\"bad address\"}");
            out.close();
            return;
        }

        Reference[] refs = currentProgram.getReferenceManager().getReferencesFrom(addr);
        out.write("{\"address\":" + q(addr.toString()) + ",\"xrefs\":[");
        for (int i = 0; i < refs.length; i++) {
            Reference r = refs[i];
            if (i > 0) out.write(",");
            out.write("{\"to\":" + q(r.getToAddress().toString()));
            out.write(",\"type\":" + q(r.getReferenceType().toString()) + "}");
        }
        out.write("]}");
        out.close();
    }

    String q(String s) {
        if (s == null) return "null";
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n") + "\"";
    }
}
