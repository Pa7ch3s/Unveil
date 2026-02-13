package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import javax.swing.RowFilter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.Desktop;
import java.awt.event.ActionEvent;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Unveil tab — path, options (-e, -O, -f), scan, then Summary / Hunt plan / Raw JSON views.
 */
public class UnveilTab {

    private final MontoyaApi api;
    private final Logging logging;
    private final JPanel mainPanel;
    private final JTextField targetField;
    private final JTextField unveilExeField;
    private final JCheckBox optExtended;
    private final JCheckBox optOffensive;
    private final JCheckBox optForce;
    private final JButton scanButton;
    private final JLabel statusLabel;
    private final JTabbedPane resultsTabs;
    private final JTextArea summaryArea;
    private final JTable huntPlanTable;
    private final DefaultTableModel huntPlanModel;
    private final JTextArea rawJsonArea;
    private final JPanel resultsToolbar;
    private final JLabel versionLabel;
    private final JButton exportHtmlBtn;
    private final JTextField huntPlanFilterField;
    private final DefaultListModel<String> discoveredHtmlModel = new DefaultListModel<>();
    private final JList<String> discoveredHtmlList;
    private final DefaultTableModel discoveredAssetsModel;
    private final JTable discoveredAssetsTable;
    private final JComboBox<String> discoveredAssetsTypeFilter;
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private static final int RECENT_TARGETS_MAX = 5;
    private final List<String> recentTargets = new ArrayList<>();

    private static final Gson GSON = new Gson();
    private static final String EMPTY_MESSAGE =
        "Scan results will appear here.\n\n" +
        "Enter a path above, set options if needed, then click Scan.";

    public UnveilTab(MontoyaApi api) {
        this.api = api;
        this.logging = api.logging();
        this.mainPanel = new JPanel(new BorderLayout(10, 10));
        this.mainPanel.setBorder(new EmptyBorder(16, 16, 16, 16));

        JLabel intro = new JLabel("Find attack surfaces in apps and binaries. Enter a path, set options, then scan.");
        intro.setBorder(new EmptyBorder(0, 0, 12, 0));
        mainPanel.add(intro, BorderLayout.NORTH);

        // Path + Browse + Scan
        JPanel inputPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 8));
        inputPanel.add(new JLabel("Path:"));
        this.targetField = new JTextField(45);
        targetField.setToolTipText("e.g. /Applications/MyApp.app or C:\\Program Files\\MyApp");
        inputPanel.add(targetField);

        JButton browseButton = new JButton("Browse…");
        browseButton.addActionListener(this::onBrowse);
        inputPanel.add(browseButton);

        this.scanButton = new JButton("Scan");
        scanButton.addActionListener(this::onScan);
        inputPanel.add(scanButton);
        JButton rescanBtn = new JButton("Rescan last");
        rescanBtn.setToolTipText("Run scan again on the last target");
        rescanBtn.addActionListener(e -> rescanLast());
        inputPanel.add(rescanBtn);

        this.statusLabel = new JLabel(" ");
        statusLabel.setForeground(new Color(100, 100, 100));
        inputPanel.add(statusLabel);

        // Unveil options: -e, -O, -f
        JPanel optionsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 4));
        optionsPanel.add(new JLabel("Options:"));
        this.optExtended = new JCheckBox("Extended (-e)", false);
        optExtended.setToolTipText("Extended surface expansion (deep persistence & lateral surfaces)");
        optionsPanel.add(optExtended);
        this.optOffensive = new JCheckBox("Offensive (-O)", false);
        optOffensive.setToolTipText("Offensive surface synthesis (exploit-chain modeling, hunt plan)");
        optionsPanel.add(optOffensive);
        this.optForce = new JCheckBox("Force (-f)", false);
        optForce.setToolTipText("Force analysis of unsigned / malformed binaries");
        optionsPanel.add(optForce);

        // Optional path to unveil binary
        JPanel unveilPathPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        unveilPathPanel.add(new JLabel("Unveil executable (optional):"));
        this.unveilExeField = new JTextField(40);
        unveilExeField.setToolTipText("Leave empty to auto-detect (~/.local/bin/unveil). Set full path if scan fails.");
        unveilPathPanel.add(unveilExeField);
        JButton unveilBrowseButton = new JButton("Browse…");
        unveilBrowseButton.setToolTipText("Select the unveil executable (e.g. from pipx or venv)");
        unveilBrowseButton.addActionListener(this::onBrowseUnveilExe);
        unveilPathPanel.add(unveilBrowseButton);
        this.versionLabel = new JLabel("Unveil CLI: —");
        versionLabel.setForeground(new Color(100, 100, 100));
        versionLabel.setFont(versionLabel.getFont().deriveFont(Font.ITALIC, versionLabel.getFont().getSize2D() - 1));
        unveilPathPanel.add(versionLabel);

        // Results: toolbar + tabbed view
        this.resultsToolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        JButton copyBtn = new JButton("Copy JSON");
        copyBtn.addActionListener(e -> copyRawJson());
        resultsToolbar.add(copyBtn);
        JButton saveJsonBtn = new JButton("Save JSON…");
        saveJsonBtn.addActionListener(e -> saveJson());
        resultsToolbar.add(saveJsonBtn);
        JButton saveCompactBtn = new JButton("Save compact JSON…");
        saveCompactBtn.addActionListener(e -> saveCompactJson());
        resultsToolbar.add(saveCompactBtn);
        this.exportHtmlBtn = new JButton("Export HTML…");
        exportHtmlBtn.addActionListener(e -> exportHtml());
        resultsToolbar.add(exportHtmlBtn);
        resultsToolbar.setVisible(false);

        this.resultsTabs = new JTabbedPane();
        this.summaryArea = new JTextArea(8, 60);
        summaryArea.setEditable(false);
        summaryArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        summaryArea.setLineWrap(true);
        summaryArea.setWrapStyleWord(true);
        summaryArea.setText(EMPTY_MESSAGE);
        resultsTabs.addTab("Summary", new JScrollPane(summaryArea));

        this.huntPlanModel = new DefaultTableModel(
            new String[] { "Missing role", "Suggested surface", "Hunt targets", "Reason" }, 0);
        this.huntPlanTable = new JTable(huntPlanModel);
        huntPlanTable.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        huntPlanTable.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        huntPlanTable.setAutoCreateRowSorter(true);
        JPanel huntPlanPanel = new JPanel(new BorderLayout(4, 4));
        JPanel huntPlanToolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        huntPlanToolbar.add(new JLabel("Filter:"));
        this.huntPlanFilterField = new JTextField(20);
        huntPlanFilterField.setToolTipText("Filter rows by text in any column");
        huntPlanFilterField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override public void insertUpdate(javax.swing.event.DocumentEvent e) { applyHuntPlanFilter(); }
            @Override public void removeUpdate(javax.swing.event.DocumentEvent e) { applyHuntPlanFilter(); }
            @Override public void changedUpdate(javax.swing.event.DocumentEvent e) { applyHuntPlanFilter(); }
        });
        huntPlanToolbar.add(huntPlanFilterField);
        huntPlanPanel.add(huntPlanToolbar, BorderLayout.NORTH);
        huntPlanPanel.add(new JScrollPane(huntPlanTable), BorderLayout.CENTER);
        JPopupMenu huntPlanMenu = new JPopupMenu();
        JMenuItem copyCellItem = new JMenuItem("Copy cell");
        copyCellItem.addActionListener(e -> copyHuntPlanCell());
        huntPlanMenu.add(copyCellItem);
        JMenuItem copyRowItem = new JMenuItem("Copy row (tab-separated)");
        copyRowItem.addActionListener(e -> copyHuntPlanRow());
        huntPlanMenu.add(copyRowItem);
        JMenuItem copySurfaceItem = new JMenuItem("Copy suggested surface");
        copySurfaceItem.addActionListener(e -> copyHuntPlanSuggestedSurface());
        huntPlanMenu.add(copySurfaceItem);
        huntPlanTable.setComponentPopupMenu(huntPlanMenu);
        resultsTabs.addTab("Hunt plan", huntPlanPanel);

        JPanel discoveredHtmlPanel = new JPanel(new BorderLayout(4, 4));
        this.discoveredHtmlList = new JList<>(discoveredHtmlModel);
        discoveredHtmlList.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        discoveredHtmlPanel.add(new JScrollPane(discoveredHtmlList), BorderLayout.CENTER);
        JPanel discoveredHtmlToolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        discoveredHtmlToolbar.add(new JLabel("HTML files found inside the target — open for attacks, redev, or transparency."));
        JButton openHtmlBtn = new JButton("Open in browser");
        openHtmlBtn.addActionListener(e -> openSelectedHtml());
        discoveredHtmlToolbar.add(openHtmlBtn);
        JButton copyPathBtn = new JButton("Copy path");
        copyPathBtn.addActionListener(e -> copySelectedHtmlPath());
        discoveredHtmlToolbar.add(copyPathBtn);
        JButton copyFileUrlBtn = new JButton("Copy file:// URL");
        copyFileUrlBtn.addActionListener(e -> copySelectedHtmlFileUrl());
        discoveredHtmlToolbar.add(copyFileUrlBtn);
        JButton exportListBtn = new JButton("Export list…");
        exportListBtn.addActionListener(e -> exportDiscoveredHtmlList());
        discoveredHtmlToolbar.add(exportListBtn);
        discoveredHtmlPanel.add(discoveredHtmlToolbar, BorderLayout.NORTH);
        discoveredHtmlList.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                if (e.getClickCount() == 2) openSelectedHtml();
            }
        });
        JPopupMenu discoveredHtmlMenu = new JPopupMenu();
        JMenuItem openItem = new JMenuItem("Open in browser");
        openItem.addActionListener(e -> openSelectedHtml());
        discoveredHtmlMenu.add(openItem);
        discoveredHtmlMenu.addSeparator();
        JMenuItem copyPathItem = new JMenuItem("Copy path");
        copyPathItem.addActionListener(e -> copySelectedHtmlPath());
        discoveredHtmlMenu.add(copyPathItem);
        JMenuItem copyUrlItem = new JMenuItem("Copy file:// URL");
        copyUrlItem.addActionListener(e -> copySelectedHtmlFileUrl());
        discoveredHtmlMenu.add(copyUrlItem);
        discoveredHtmlMenu.addSeparator();
        JMenuItem exportListItem = new JMenuItem("Export list to file…");
        exportListItem.addActionListener(e -> exportDiscoveredHtmlList());
        discoveredHtmlMenu.add(exportListItem);
        discoveredHtmlList.setComponentPopupMenu(discoveredHtmlMenu);
        resultsTabs.addTab("Discovered HTML", discoveredHtmlPanel);

        // Discovered assets (all types: html, xml, json, config, script, plist, etc.)
        this.discoveredAssetsModel = new DefaultTableModel(new String[] { "Path", "Type" }, 0);
        this.discoveredAssetsTable = new JTable(discoveredAssetsModel);
        discoveredAssetsTable.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        discoveredAssetsTable.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        discoveredAssetsTable.setAutoCreateRowSorter(true);
        JPanel discoveredAssetsPanel = new JPanel(new BorderLayout(4, 4));
        JPanel discoveredAssetsToolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        discoveredAssetsToolbar.add(new JLabel("Type:"));
        this.discoveredAssetsTypeFilter = new JComboBox<>(new String[] { "All", "html", "xml", "json", "config", "script", "plist", "manifest", "policy", "cert", "data" });
        discoveredAssetsTypeFilter.addActionListener(e -> applyDiscoveredAssetsTypeFilter());
        discoveredAssetsToolbar.add(discoveredAssetsTypeFilter);
        JButton openAssetBtn = new JButton("Open");
        openAssetBtn.addActionListener(e -> openSelectedAsset());
        discoveredAssetsToolbar.add(openAssetBtn);
        JButton copyAssetPathBtn = new JButton("Copy path");
        copyAssetPathBtn.addActionListener(e -> copySelectedAssetPath());
        discoveredAssetsToolbar.add(copyAssetPathBtn);
        JButton copyAssetFileUrlBtn = new JButton("Copy file:// URL");
        copyAssetFileUrlBtn.addActionListener(e -> copySelectedAssetFileUrl());
        discoveredAssetsToolbar.add(copyAssetFileUrlBtn);
        JButton exportAssetsBtn = new JButton("Export list…");
        exportAssetsBtn.addActionListener(e -> exportDiscoveredAssetsList());
        discoveredAssetsToolbar.add(exportAssetsBtn);
        discoveredAssetsPanel.add(discoveredAssetsToolbar, BorderLayout.NORTH);
        discoveredAssetsPanel.add(new JScrollPane(discoveredAssetsTable), BorderLayout.CENTER);
        discoveredAssetsTable.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent ev) {
                if (ev.getClickCount() == 2) openSelectedAsset();
            }
        });
        JPopupMenu discoveredAssetsMenu = new JPopupMenu();
        JMenuItem openAssetItem = new JMenuItem("Open");
        openAssetItem.addActionListener(e -> openSelectedAsset());
        discoveredAssetsMenu.add(openAssetItem);
        discoveredAssetsMenu.addSeparator();
        JMenuItem copyAssetPathItem = new JMenuItem("Copy path");
        copyAssetPathItem.addActionListener(e -> copySelectedAssetPath());
        discoveredAssetsMenu.add(copyAssetPathItem);
        JMenuItem copyAssetUrlItem = new JMenuItem("Copy file:// URL");
        copyAssetUrlItem.addActionListener(e -> copySelectedAssetFileUrl());
        discoveredAssetsMenu.add(copyAssetUrlItem);
        discoveredAssetsMenu.addSeparator();
        JMenuItem exportAssetsItem = new JMenuItem("Export list to file…");
        exportAssetsItem.addActionListener(e -> exportDiscoveredAssetsList());
        discoveredAssetsMenu.add(exportAssetsItem);
        discoveredAssetsTable.setComponentPopupMenu(discoveredAssetsMenu);
        resultsTabs.addTab("Discovered assets", discoveredAssetsPanel);

        this.rawJsonArea = new JTextArea(18, 80);
        rawJsonArea.setEditable(false);
        rawJsonArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        rawJsonArea.setLineWrap(false);
        rawJsonArea.setText(EMPTY_MESSAGE);
        resultsTabs.addTab("Raw JSON", new JScrollPane(rawJsonArea));

        JPanel top = new JPanel(new BorderLayout(0, 10));
        top.add(intro, BorderLayout.NORTH);
        JPanel controls = new JPanel();
        controls.setLayout(new BoxLayout(controls, BoxLayout.PAGE_AXIS));
        controls.add(inputPanel);
        controls.add(optionsPanel);
        controls.add(unveilPathPanel);
        top.add(controls, BorderLayout.CENTER);

        JPanel center = new JPanel(new BorderLayout(0, 8));
        center.add(resultsToolbar, BorderLayout.NORTH);
        center.add(resultsTabs, BorderLayout.CENTER);
        resultsTabs.setBorder(BorderFactory.createEtchedBorder());

        mainPanel.add(top, BorderLayout.NORTH);
        mainPanel.add(center, BorderLayout.CENTER);

        executor.submit(this::fetchUnveilVersion);
    }

    private void fetchUnveilVersion() {
        try {
            String exe = resolveUnveilPath();
            ProcessBuilder pb = new ProcessBuilder(exe, "--version");
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
            p.waitFor();
            String version = out.isEmpty() ? "—" : out.split("\\r?\\n")[0];
            SwingUtilities.invokeLater(() -> versionLabel.setText("Unveil CLI: " + version));
        } catch (Exception e) {
            SwingUtilities.invokeLater(() -> versionLabel.setText("Unveil CLI: not found"));
        }
    }

    public JComponent getTabComponent() {
        return mainPanel;
    }

    private void applyHuntPlanFilter() {
        TableRowSorter<?> sorter = (TableRowSorter<?>) huntPlanTable.getRowSorter();
        if (sorter == null) return;
        String q = huntPlanFilterField.getText();
        if (q == null) q = "";
        q = q.trim();
        if (q.isEmpty()) {
            sorter.setRowFilter(null);
        } else {
            String search = "(?i)" + java.util.regex.Pattern.quote(q);
            sorter.setRowFilter(RowFilter.regexFilter(search, 0, 1, 2, 3));
        }
    }

    private static void setChooserToApplicationsOrHome(JFileChooser chooser) {
        File applications = new File("/Applications");
        if (applications.isDirectory()) {
            chooser.setCurrentDirectory(applications);
        } else {
            String home = System.getProperty("user.home");
            if (home != null) {
                File homeDir = new File(home);
                if (homeDir.isDirectory()) chooser.setCurrentDirectory(homeDir);
            }
        }
    }

    private void onBrowse(ActionEvent e) {
        JFileChooser chooser = new JFileChooser();
        chooser.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);
        chooser.setDialogTitle("Choose app, folder, or file to scan");
        chooser.setFileHidingEnabled(false);
        String targetText = targetField.getText() != null ? targetField.getText().trim() : "";
        if (!targetText.isEmpty()) {
            File current = new File(targetText);
            if (current.exists()) {
                chooser.setCurrentDirectory(current.isDirectory() ? current : current.getParentFile());
            } else {
                setChooserToApplicationsOrHome(chooser);
            }
        } else {
            setChooserToApplicationsOrHome(chooser);
        }
        if (chooser.showOpenDialog(mainPanel) == JFileChooser.APPROVE_OPTION) {
            File f = chooser.getSelectedFile();
            if (f != null) {
                targetField.setText(f.getAbsolutePath());
                statusLabel.setText(" ");
            }
        }
    }

    private void onBrowseUnveilExe(ActionEvent e) {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Select file");
        chooser.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);
        chooser.setFileHidingEnabled(false);
        String exeText = unveilExeField.getText() != null ? unveilExeField.getText().trim() : "";
        if (!exeText.isEmpty()) {
            File current = new File(exeText);
            if (current.exists()) {
                chooser.setCurrentDirectory(current.isDirectory() ? current : current.getParentFile());
                if (current.isFile()) chooser.setSelectedFile(current);
            } else {
                setChooserToUserHome(chooser);
            }
        } else {
            setChooserToUserHome(chooser);
        }
        if (chooser.showOpenDialog(mainPanel) == JFileChooser.APPROVE_OPTION) {
            File f = chooser.getSelectedFile();
            if (f != null) {
                unveilExeField.setText(f.getAbsolutePath());
                statusLabel.setText(" ");
            }
        }
    }

    private static void setChooserToUserHome(JFileChooser chooser) {
        String home = System.getProperty("user.home");
        if (home != null) {
            File homeDir = new File(home);
            if (homeDir.isDirectory()) chooser.setCurrentDirectory(homeDir);
        }
    }

    private void onScan(ActionEvent e) {
        String target = targetField.getText() == null ? "" : targetField.getText().trim();
        if (target.isEmpty()) {
            statusLabel.setText("Enter or choose a path first.");
            return;
        }
        statusLabel.setText("Scanning…");
        summaryArea.setText("Scanning " + target + "…\n\nPlease wait.");
        huntPlanModel.setRowCount(0);
        rawJsonArea.setText("");
        resultsToolbar.setVisible(false);
        scanButton.setEnabled(false);
        executor.submit(() -> runUnveil(target));
    }

    private void rescanLast() {
        if (recentTargets.isEmpty()) {
            statusLabel.setText("No previous scan.");
            return;
        }
        String last = recentTargets.get(0);
        targetField.setText(last);
        statusLabel.setText("Scanning…");
        summaryArea.setText("Scanning " + last + "…\n\nPlease wait.");
        huntPlanModel.setRowCount(0);
        rawJsonArea.setText("");
        resultsToolbar.setVisible(false);
        scanButton.setEnabled(false);
        executor.submit(() -> runUnveil(last));
    }

    private static String getUnveilPath() {
        String home = System.getProperty("user.home");
        if (home != null && !home.isEmpty()) {
            File pipx = new File(home, ".local/bin/unveil");
            if (pipx.canExecute()) return pipx.getAbsolutePath();
        }
        return "unveil";
    }

    private String resolveUnveilPath() {
        String custom = unveilExeField.getText();
        if (custom != null) {
            String t = custom.trim();
            if (!t.isEmpty()) {
                File f = new File(t);
                if (f.isFile()) return f.getAbsolutePath();
            }
        }
        return getUnveilPath();
    }

    private List<String> buildUnveilArgs(String target, String jsonPath, String htmlPath) {
        List<String> args = new ArrayList<>();
        args.add(resolveUnveilPath());
        args.add("-C");
        args.add(target);
        args.add("-q");
        if (optExtended.isSelected()) args.add("-e");
        if (optOffensive.isSelected()) args.add("-O");
        if (optForce.isSelected()) args.add("-f");
        if (jsonPath != null && !jsonPath.isEmpty()) {
            args.add("-xj");
            args.add(jsonPath);
        }
        if (htmlPath != null && !htmlPath.isEmpty()) {
            args.add("-xh");
            args.add(htmlPath);
        }
        return args;
    }

    private void runUnveil(String target) {
        File reportFile;
        try {
            reportFile = File.createTempFile("unveil-report-", ".json");
            reportFile.deleteOnExit();
        } catch (IOException ex) {
            onUnveilError("Could not create temp file: " + ex.getMessage(), ex.getMessage(), false);
            return;
        }
        List<String> args = buildUnveilArgs(target, reportFile.getAbsolutePath(), null);

        try {
            ProcessBuilder pb = new ProcessBuilder(args);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            p.getInputStream().readAllBytes();
            int exit = p.waitFor();
            String result = "";
            if (reportFile.exists()) {
                result = new String(Files.readAllBytes(reportFile.toPath()), StandardCharsets.UTF_8).trim();
            }
            try {
                Files.deleteIfExists(reportFile.toPath());
            } catch (IOException ignored) {}

            String finalResult = result;
            SwingUtilities.invokeLater(() -> {
                scanButton.setEnabled(true);
                if (exit != 0) {
                    statusLabel.setText("Scan failed.");
                    summaryArea.setText("Unveil exited with code " + exit + ".\n\n" +
                        (finalResult.isEmpty() ? "Check options or unveil CLI." : finalResult));
                    resultsToolbar.setVisible(false);
                } else if (finalResult.isEmpty()) {
                    statusLabel.setText("Done (no output).");
                    summaryArea.setText("Scan finished but no report file was produced.");
                    resultsToolbar.setVisible(false);
                } else {
                    statusLabel.setText("Done.");
                    recentTargets.remove(target);
                    recentTargets.add(0, target);
                    while (recentTargets.size() > RECENT_TARGETS_MAX) recentTargets.remove(recentTargets.size() - 1);
                    applyReport(finalResult);
                    resultsToolbar.setVisible(true);
                }
            });
        } catch (Exception ex) {
            logging.logToError("Unveil scan failed: " + ex.getMessage());
            String msg = ex.getMessage();
            boolean notFound = msg != null && (msg.contains("No such file") || msg.contains("error=2"));
            onUnveilError(ex.getMessage(), msg, notFound);
        }
    }

    private void onUnveilError(String displayMsg, String rawMsg, boolean notFound) {
        SwingUtilities.invokeLater(() -> {
            scanButton.setEnabled(true);
            statusLabel.setText("Error.");
            String install = "Install: pipx install git+https://github.com/Pa7ch3s/Unveil.git\n\n" +
                (notFound ? "If already installed, set \"Unveil executable (optional)\" to the full path (e.g. from 'which unveil')." : "");
            summaryArea.setText("Could not run Unveil.\n\n" + displayMsg + "\n\n" + install);
            resultsToolbar.setVisible(false);
        });
    }

    private void applyReport(String json) {
        rawJsonArea.setText(json);
        rawJsonArea.setCaretPosition(0);

        try {
            JsonObject report = JsonParser.parseString(json).getAsJsonObject();
            JsonObject metadata = report.has("metadata") ? report.getAsJsonObject("metadata") : null;
            JsonObject verdict = report.has("verdict") ? report.getAsJsonObject("verdict") : null;

            StringBuilder summary = new StringBuilder();
            String target = metadata != null && metadata.has("target")
                ? metadata.get("target").getAsString() : "—";
            summary.append("Target: ").append(target).append("\n\n");

            if (verdict != null) {
                summary.append("Verdict\n");
                summary.append("  Exploitability band: ").append(str(verdict.get("exploitability_band"))).append("\n");
                summary.append("  Kill chain complete: ").append(verdict.has("killchain_complete") ? verdict.get("killchain_complete").getAsBoolean() : false).append("\n");
                summary.append("  Chain completion: ").append(verdict.has("chain_completion") ? verdict.get("chain_completion").getAsDouble() : 0).append("\n");
                if (verdict.has("missing_roles")) {
                    JsonArray arr = verdict.getAsJsonArray("missing_roles");
                    summary.append("  Missing roles: ");
                    if (arr != null && arr.size() > 0) {
                        List<String> roles = new ArrayList<>();
                        for (JsonElement el : arr) roles.add(el.getAsString());
                        summary.append(String.join(", ", roles));
                    } else summary.append("(none)");
                    summary.append("\n");
                }
                if (verdict.has("families")) {
                    JsonArray arr = verdict.getAsJsonArray("families");
                    if (arr != null && arr.size() > 0) {
                        summary.append("  Families: ");
                        List<String> list = new ArrayList<>();
                        for (JsonElement el : arr) list.add(el.getAsString());
                        summary.append(String.join(", ", list)).append("\n");
                    }
                }
                if (verdict.has("hunt_plan")) {
                    JsonArray hp = verdict.getAsJsonArray("hunt_plan");
                    summary.append("\nHunt plan entries: ").append(hp != null ? hp.size() : 0).append("\n");
                }
            }

            summaryArea.setText(summary.toString());
            summaryArea.setCaretPosition(0);

            huntPlanModel.setRowCount(0);
            if (verdict != null && verdict.has("hunt_plan")) {
                JsonArray hp = verdict.getAsJsonArray("hunt_plan");
                if (hp != null) {
                    for (JsonElement el : hp) {
                        JsonObject row = el.getAsJsonObject();
                        huntPlanModel.addRow(new String[] {
                            str(row.get("missing_role")),
                            str(row.get("suggested_surface")),
                            str(row.get("hunt_targets")),
                            str(row.get("reason"))
                        });
                    }
                }
            }
            huntPlanFilterField.setText("");

            discoveredHtmlModel.clear();
            if (report.has("discovered_html")) {
                JsonArray arr = report.getAsJsonArray("discovered_html");
                if (arr != null) {
                    for (JsonElement el : arr) {
                        if (el.isJsonPrimitive()) discoveredHtmlModel.addElement(el.getAsString());
                    }
                }
            }
            discoveredAssetsModel.setRowCount(0);
            if (report.has("discovered_assets")) {
                JsonObject assets = report.getAsJsonObject("discovered_assets");
                if (assets != null) {
                    for (String type : assets.keySet()) {
                        JsonArray paths = assets.getAsJsonArray(type);
                        if (paths != null) {
                            for (JsonElement el : paths) {
                                if (el.isJsonPrimitive())
                                    discoveredAssetsModel.addRow(new Object[] { el.getAsString(), type });
                            }
                        }
                    }
                }
            }
            applyDiscoveredAssetsTypeFilter();
        } catch (Exception e) {
            logging.logToError("Unveil report parse error: " + e.getMessage());
            summaryArea.setText("Report received but parsing failed.\n\nSee Raw JSON tab.\n\n" + e.getMessage());
        }
    }

    private static String str(JsonElement el) {
        if (el == null || el.isJsonNull()) return "";
        if (el.isJsonPrimitive()) return el.getAsString();
        return el.toString();
    }

    private void openSelectedHtml() {
        String path = discoveredHtmlList.getSelectedValue();
        if (path == null || path.isEmpty()) return;
        try {
            File f = new File(path);
            if (f.exists() && Desktop.isDesktopSupported()) {
                Desktop.getDesktop().open(f);
                statusLabel.setText("Opened in default app.");
            } else {
                statusLabel.setText("Open not supported or file missing.");
            }
        } catch (Exception ex) {
            statusLabel.setText("Open failed.");
            logging.logToError("Open HTML failed: " + ex.getMessage());
        }
    }

    private void copySelectedHtmlPath() {
        String path = discoveredHtmlList.getSelectedValue();
        if (path == null || path.isEmpty()) return;
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(path), null);
        statusLabel.setText("Path copied.");
    }

    private static String pathToFileUrl(String path) {
        if (path == null) return "";
        String p = path.replace("\\", "/");
        if (p.length() >= 2 && p.charAt(1) == ':')
            return "file:///" + p;
        if (!p.startsWith("/")) p = "/" + p;
        return "file://" + p;
    }

    private void copySelectedHtmlFileUrl() {
        String path = discoveredHtmlList.getSelectedValue();
        if (path == null || path.isEmpty()) return;
        String url = pathToFileUrl(path);
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(url), null);
        statusLabel.setText("file:// URL copied.");
    }

    private void copyHuntPlanCell() {
        int row = huntPlanTable.getSelectedRow();
        int col = huntPlanTable.getSelectedColumn();
        if (row < 0 || col < 0) return;
        int modelRow = huntPlanTable.convertRowIndexToModel(row);
        Object v = huntPlanModel.getValueAt(modelRow, col);
        if (v != null) {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(v.toString()), null);
            statusLabel.setText("Cell copied.");
        }
    }

    private void copyHuntPlanRow() {
        int row = huntPlanTable.getSelectedRow();
        if (row < 0) return;
        int modelRow = huntPlanTable.convertRowIndexToModel(row);
        StringBuilder sb = new StringBuilder();
        for (int c = 0; c < huntPlanModel.getColumnCount(); c++) {
            if (c > 0) sb.append("\t");
            Object v = huntPlanModel.getValueAt(modelRow, c);
            sb.append(v != null ? v.toString() : "");
        }
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(sb.toString()), null);
        statusLabel.setText("Row copied.");
    }

    private void exportDiscoveredHtmlList() {
        if (discoveredHtmlModel.isEmpty()) {
            statusLabel.setText("No paths to export.");
            return;
        }
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File("unveil-discovered-html.txt"));
        if (chooser.showSaveDialog(mainPanel) != JFileChooser.APPROVE_OPTION) return;
        File f = chooser.getSelectedFile();
        if (f == null) return;
        try {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < discoveredHtmlModel.getSize(); i++) {
                sb.append(discoveredHtmlModel.getElementAt(i)).append("\n");
            }
            Files.writeString(f.toPath(), sb.toString(), StandardCharsets.UTF_8);
            statusLabel.setText("Exported: " + f.getAbsolutePath());
        } catch (IOException ex) {
            statusLabel.setText("Export failed.");
            JOptionPane.showMessageDialog(mainPanel, "Could not save: " + ex.getMessage(), "Export error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void applyDiscoveredAssetsTypeFilter() {
        TableRowSorter<?> sorter = (TableRowSorter<?>) discoveredAssetsTable.getRowSorter();
        if (sorter == null) return;
        String type = (String) discoveredAssetsTypeFilter.getSelectedItem();
        if (type == null || "All".equals(type)) {
            sorter.setRowFilter(null);
        } else {
            sorter.setRowFilter(RowFilter.regexFilter("^" + java.util.regex.Pattern.quote(type) + "$", 1));
        }
    }

    private String getSelectedAssetPath() {
        int row = discoveredAssetsTable.getSelectedRow();
        if (row < 0) return null;
        int modelRow = discoveredAssetsTable.convertRowIndexToModel(row);
        Object v = discoveredAssetsModel.getValueAt(modelRow, 0);
        return v != null ? v.toString() : null;
    }

    private void openSelectedAsset() {
        String path = getSelectedAssetPath();
        if (path == null || path.isEmpty()) {
            statusLabel.setText("Select an asset row.");
            return;
        }
        try {
            File f = new File(path);
            if (f.exists() && Desktop.isDesktopSupported()) {
                Desktop.getDesktop().open(f);
                statusLabel.setText("Opened in default app.");
            } else {
                statusLabel.setText("Open not supported or file missing.");
            }
        } catch (Exception ex) {
            statusLabel.setText("Open failed.");
            logging.logToError("Open asset failed: " + ex.getMessage());
        }
    }

    private void copySelectedAssetPath() {
        String path = getSelectedAssetPath();
        if (path == null || path.isEmpty()) {
            statusLabel.setText("Select an asset row.");
            return;
        }
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(path), null);
        statusLabel.setText("Path copied.");
    }

    private void copySelectedAssetFileUrl() {
        String path = getSelectedAssetPath();
        if (path == null || path.isEmpty()) {
            statusLabel.setText("Select an asset row.");
            return;
        }
        String url = pathToFileUrl(path);
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(url), null);
        statusLabel.setText("file:// URL copied.");
    }

    private void exportDiscoveredAssetsList() {
        if (discoveredAssetsModel.getRowCount() == 0) {
            statusLabel.setText("No assets to export.");
            return;
        }
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File("unveil-discovered-assets.txt"));
        if (chooser.showSaveDialog(mainPanel) != JFileChooser.APPROVE_OPTION) return;
        File f = chooser.getSelectedFile();
        if (f == null) return;
        try {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < discoveredAssetsModel.getRowCount(); i++) {
                Object path = discoveredAssetsModel.getValueAt(i, 0);
                Object type = discoveredAssetsModel.getValueAt(i, 1);
                sb.append(path).append("\t").append(type).append("\n");
            }
            Files.writeString(f.toPath(), sb.toString(), StandardCharsets.UTF_8);
            statusLabel.setText("Exported: " + f.getAbsolutePath());
        } catch (IOException ex) {
            statusLabel.setText("Export failed.");
            JOptionPane.showMessageDialog(mainPanel, "Could not save: " + ex.getMessage(), "Export error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void copyHuntPlanSuggestedSurface() {
        int row = huntPlanTable.getSelectedRow();
        if (row < 0) return;
        int modelRow = huntPlanTable.convertRowIndexToModel(row);
        Object v = huntPlanModel.getValueAt(modelRow, 1); // Suggested surface column
        if (v != null) {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(v.toString()), null);
            statusLabel.setText("Suggested surface copied.");
        }
    }

    private void copyRawJson() {
        String text = rawJsonArea.getText();
        if (text == null || text.isEmpty() || EMPTY_MESSAGE.equals(text.trim())) {
            statusLabel.setText("No report to copy.");
            return;
        }
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
        statusLabel.setText("JSON copied to clipboard.");
    }

    private void saveJson() {
        String content = rawJsonArea.getText();
        if (content == null || content.isEmpty() || EMPTY_MESSAGE.equals(content.trim())) {
            statusLabel.setText("No report to save.");
            return;
        }
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File("unveil-report.json"));
        if (chooser.showSaveDialog(mainPanel) == JFileChooser.APPROVE_OPTION) {
            File f = chooser.getSelectedFile();
            if (f != null) {
                try {
                    Files.writeString(f.toPath(), content, StandardCharsets.UTF_8);
                    statusLabel.setText("Saved: " + f.getAbsolutePath());
                } catch (IOException ex) {
                    statusLabel.setText("Save failed.");
                    JOptionPane.showMessageDialog(mainPanel, "Could not save: " + ex.getMessage(), "Save error", JOptionPane.ERROR_MESSAGE);
                }
            }
        }
    }

    private void saveCompactJson() {
        String content = rawJsonArea.getText();
        if (content == null || content.isEmpty() || EMPTY_MESSAGE.equals(content.trim())) {
            statusLabel.setText("No report to save.");
            return;
        }
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File("unveil-report.json"));
        if (chooser.showSaveDialog(mainPanel) == JFileChooser.APPROVE_OPTION) {
            File f = chooser.getSelectedFile();
            if (f != null) {
                try {
                    String compact = GSON.toJson(JsonParser.parseString(content));
                    Files.writeString(f.toPath(), compact, StandardCharsets.UTF_8);
                    statusLabel.setText("Saved (compact): " + f.getAbsolutePath());
                } catch (Exception ex) {
                    statusLabel.setText("Save failed.");
                    JOptionPane.showMessageDialog(mainPanel, "Could not save: " + ex.getMessage(), "Save error", JOptionPane.ERROR_MESSAGE);
                }
            }
        }
    }

    private void exportHtml() {
        String target = targetField.getText() == null ? "" : targetField.getText().trim();
        if (target.isEmpty()) {
            statusLabel.setText("Enter a path first.");
            return;
        }
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File("unveil-report.html"));
        if (chooser.showSaveDialog(mainPanel) != JFileChooser.APPROVE_OPTION) return;
        File f = chooser.getSelectedFile();
        if (f == null) return;

        statusLabel.setText("Exporting HTML…");
        scanButton.setEnabled(false);
        exportHtmlBtn.setEnabled(false);
        String path = f.getAbsolutePath();
        executor.submit(() -> {
            try {
                List<String> args = buildUnveilArgs(target, null, path);
                ProcessBuilder pb = new ProcessBuilder(args);
                pb.redirectErrorStream(true);
                Process p = pb.start();
                p.getInputStream().readAllBytes();
                int exit = p.waitFor();
                SwingUtilities.invokeLater(() -> {
                    scanButton.setEnabled(true);
                    exportHtmlBtn.setEnabled(true);
                    if (exit == 0) {
                        statusLabel.setText("Exported: " + path);
                    } else {
                        statusLabel.setText("Export failed (exit " + exit + ").");
                    }
                });
            } catch (Exception ex) {
                logging.logToError("Unveil HTML export failed: " + ex.getMessage());
                SwingUtilities.invokeLater(() -> {
                    scanButton.setEnabled(true);
                    exportHtmlBtn.setEnabled(true);
                    statusLabel.setText("Export failed.");
                    JOptionPane.showMessageDialog(mainPanel, "Could not run unveil: " + ex.getMessage(), "Export error", JOptionPane.ERROR_MESSAGE);
                });
            }
        });
    }

    public void extensionUnloaded() {
        executor.shutdown();
    }
}
