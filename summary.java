import java.io.FileWriter;

import ghidra.app.script.GhidraScript;

public class summary extends GhidraScript {
    public void run() throws Exception {
        FileWriter out = new FileWriter(getScriptArgs()[0]);
        out.write("{");
        out.write("\"name\":" + q(currentProgram.getName()) + ",");
        out.write("\"language\":" + q(currentProgram.getLanguageID().toString()) + ",");
        out.write("\"image_base\":" + q(currentProgram.getImageBase().toString()) + ",");
        out.write("\"functions\":" + currentProgram.getFunctionManager().getFunctionCount());
        out.write("}");
        out.close();
    }

    String q(String s) {
        if (s == null) return "null";
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n") + "\"";
    }
}
