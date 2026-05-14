import java.io.FileWriter;
import java.util.HashSet;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

public class finders extends GhidraScript {
    FileWriter out;

    public void run() throws Exception {
        String[] args = getScriptArgs();
        out = new FileWriter(args[0]);

        if (args[1].equals("calling")) functionsCalling(args[2], Integer.parseInt(args[3]));
        if (args[1].equals("string_refs")) functionsReferencingString(args[2], Integer.parseInt(args[3]));

        out.close();
    }

    void functionsCalling(String name, int limit) throws Exception {
        HashSet<String> seen = new HashSet<>();
        int count = 0;
        out.write("{\"query\":" + q(name) + ",\"functions\":[");

        SymbolIterator symbols = currentProgram.getSymbolTable().getAllSymbols(true);
        while (symbols.hasNext() && count < limit) {
            Symbol s = symbols.next();
            if (!s.getName().toLowerCase().contains(name.toLowerCase())) continue;

            ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(s.getAddress());
            while (refs.hasNext() && count < limit) {
                Reference r = refs.next();
                Function f = currentProgram.getFunctionManager().getFunctionContaining(r.getFromAddress());
                if (f == null) continue;
                String key = f.getEntryPoint().toString();
                if (seen.contains(key)) continue;
                seen.add(key);

                if (count > 0) out.write(",");
                out.write("{\"address\":" + q(f.getEntryPoint().toString()));
                out.write(",\"name\":" + q(f.getName()));
                out.write(",\"ref\":" + q(r.getFromAddress().toString()));
                out.write(",\"target\":" + q(s.getName()));
                out.write("}");
                count++;
            }
        }
        out.write("]}");
    }

    void functionsReferencingString(String query, int limit) throws Exception {
        HashSet<String> seen = new HashSet<>();
        int count = 0;
        String needle = query.toLowerCase();
        out.write("{\"query\":" + q(query) + ",\"functions\":[");

        for (Data data : currentProgram.getListing().getDefinedData(true)) {
            if (count >= limit) break;
            if (!StringDataInstance.isString(data)) continue;
            String value = StringDataInstance.getStringDataInstance(data).getStringValue();
            if (value == null || !value.toLowerCase().contains(needle)) continue;

            Address stringAddr = data.getAddress();
            ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(stringAddr);
            while (refs.hasNext() && count < limit) {
                Reference r = refs.next();
                Function f = currentProgram.getFunctionManager().getFunctionContaining(r.getFromAddress());
                if (f == null) continue;
                String key = f.getEntryPoint().toString() + ":" + stringAddr.toString();
                if (seen.contains(key)) continue;
                seen.add(key);

                if (count > 0) out.write(",");
                out.write("{\"address\":" + q(f.getEntryPoint().toString()));
                out.write(",\"name\":" + q(f.getName()));
                out.write(",\"ref\":" + q(r.getFromAddress().toString()));
                out.write(",\"string_address\":" + q(stringAddr.toString()));
                out.write(",\"string\":" + q(value));
                out.write("}");
                count++;
            }
        }
        out.write("]}");
    }

    String q(String s) {
        if (s == null) return "null";
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r") + "\"";
    }
}
