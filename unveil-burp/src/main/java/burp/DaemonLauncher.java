package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;

import java.io.File;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * "Invisible Engine" — when the extension loads, ping the daemon; if no response,
 * auto-start unveil-daemon.exe from the fixed path (Windows) so the user never touches a terminal.
 * Fixed path: Windows %LOCALAPPDATA%\\Unveil\\unveil-daemon.exe
 */
public final class DaemonLauncher {

    private static final String DEFAULT_DAEMON_URL = "http://127.0.0.1:8000";
    private static final int HEARTBEAT_TIMEOUT_MS = 2500;
    private static final ExecutorService EXECUTOR = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "Unveil-DaemonLauncher");
        t.setDaemon(true);
        return t;
    });

    private DaemonLauncher() {}

    /**
     * Call from extension initialize (off EDT). Runs in background: heartbeat then
     * optionally start the exe on Windows so no console is shown.
     */
    public static void tryStartBackendIfNeeded(MontoyaApi api) {
        EXECUTOR.execute(() -> {
            Logging log = api.logging();
            try {
                String baseUrl = resolveDaemonBaseUrl();
                if (ping(baseUrl)) {
                    log.logToOutput("Unveil: backend already running at " + baseUrl);
                    return;
                }
                if (isWindows()) {
                    String exePath = getWindowsExePath();
                    if (exePath != null && new File(exePath).isFile()) {
                        startProcessHidden(exePath);
                        log.logToOutput("Unveil: backend started automatically from " + exePath);
                    } else {
                        log.logToOutput("Unveil: backend not running; no exe at " + (exePath != null ? exePath : "LOCALAPPDATA\\Unveil\\unveil-daemon.exe") + ". Run install.ps1 or start daemon manually.");
                    }
                } else {
                    log.logToOutput("Unveil: backend not running at " + baseUrl + ". Start the daemon manually (e.g. run 'unveil' or load the Unveil tab and use Test connection).");
                }
            } catch (Throwable t) {
                log.logToError("Unveil: auto-start check failed: " + (t.getMessage() != null ? t.getMessage() : t.getClass().getSimpleName()));
            }
        });
    }

    private static String resolveDaemonBaseUrl() {
        try {
            String home = System.getProperty("user.home");
            if (home != null && !home.isEmpty()) {
                File configFile = new File(home, ".unveil" + File.separator + "config.json");
                if (configFile.isFile()) {
                    String json = Files.readString(configFile.toPath(), StandardCharsets.UTF_8);
                    com.google.gson.JsonObject config = com.google.gson.JsonParser.parseString(json).getAsJsonObject();
                    if (config.has("daemon_host") && config.has("daemon_port")) {
                        String host = config.get("daemon_host").getAsString();
                        int port = config.get("daemon_port").getAsInt();
                        if (host != null && !host.isEmpty() && port > 0 && port <= 65535) {
                            return "http://" + host + ":" + port;
                        }
                    }
                }
            }
        } catch (Exception ignored) {}
        return DEFAULT_DAEMON_URL;
    }

    private static boolean ping(String baseUrl) {
        String url = (baseUrl.endsWith("/") ? baseUrl : baseUrl + "/") + "health";
        try {
            HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(HEARTBEAT_TIMEOUT_MS);
            conn.setReadTimeout(HEARTBEAT_TIMEOUT_MS);
            int code = conn.getResponseCode();
            return code >= 200 && code < 300;
        } catch (Exception ignored) {
            return false;
        }
    }

    private static boolean isWindows() {
        String os = System.getProperty("os.name", "");
        return os.toLowerCase(Locale.ROOT).startsWith("windows");
    }

    private static String getWindowsExePath() {
        String appData = System.getenv("LOCALAPPDATA");
        if (appData == null || appData.isEmpty()) return null;
        return appData + File.separator + "Unveil" + File.separator + "unveil-daemon.exe";
    }

    /**
     * Start the exe without showing a console window (Windows: cmd /c start /B).
     */
    private static void startProcessHidden(String exePath) throws IOException {
        File exe = new File(exePath);
        String path = exe.getAbsolutePath();
        ProcessBuilder pb;
        if (isWindows()) {
            // start /B "" "path" runs the exe in background; no new window
            pb = new ProcessBuilder("cmd.exe", "/c", "start", "/B", "", path);
        } else {
            pb = new ProcessBuilder(path);
        }
        pb.redirectErrorStream(true);
        pb.redirectOutput(ProcessBuilder.Redirect.DISCARD);
        pb.redirectError(ProcessBuilder.Redirect.DISCARD);
        pb.start();
    }
}
