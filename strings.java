import java.io.FileWriter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;

public class strings extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        FileWriter out = new FileWriter(args[0]);
        String needle = args[1].toLowerCase();
        int limit = Integer.parseInt(args[2]);
        int count = 0;

        out.write("{\"strings\":[");
        for (Data data : currentProgram.getListing().getDefinedData(true)) {
            if (count >= limit) break;
            if (!StringDataInstance.isString(data)) continue;
            String value = StringDataInstance.getStringDataInstance(data).getStringValue();
            if (value == null || !value.toLowerCase().contains(needle)) continue;
            if (count > 0) out.write(",");
            out.write("{\"address\":" + q(data.getAddress().toString()));
            out.write(",\"value\":" + q(value) + "}");
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
