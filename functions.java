import java.io.FileWriter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;

public class functions extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        FileWriter out = new FileWriter(args[0]);
        int limit = Integer.parseInt(args[1]);
        int count = 0;

        out.write("{\"functions\":[");
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (count >= limit) break;
            if (count > 0) out.write(",");
            out.write("{\"address\":" + q(f.getEntryPoint().toString()));
            out.write(",\"name\":" + q(f.getName()) + "}");
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
