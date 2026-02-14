package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.repeater.Repeater;

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
import javax.swing.text.html.HTMLEditorKit;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.Desktop;
import java.awt.event.ActionEvent;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.prefs.Preferences;

/**
 * Unveil tab — path, options (-e, -O, -f), scan, then Summary / Attack graph (visual) / Discovered HTML (view in panel) / Raw JSON and other result views.
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
    private final JCheckBox optCve;
    private final JCheckBox useDaemonCheck;
    private final JTextField daemonUrlField;
    private final JSpinner maxFilesSpinner;
    private final JSpinner maxSizeMbSpinner;
    private final JSpinner maxPerTypeSpinner;
    private final JTextField baselinePathField;
    private final JButton scanButton;
    private final JLabel statusLabel;
    private final JTabbedPane resultsTabs;
    private final JTextArea summaryArea;
    private final JTextArea rawJsonArea;
    private final JPanel resultsToolbar;
    private final JLabel versionLabel;
    private final JTextField proxyHostPortField;
    private final JButton exportHtmlBtn;
    private final DefaultListModel<String> discoveredHtmlModel = new DefaultListModel<>();
    private final JList<String> discoveredHtmlList;
    private final DefaultTableModel discoveredAssetsModel;
    private final JTable discoveredAssetsTable;
    private final JComboBox<String> discoveredAssetsTypeFilter;
    private final DefaultTableModel chainabilityModel;
    private final JTable chainabilityTable;
    private final List<UnveilTab.ExtractedRefEntry> extractedRefsData = new ArrayList<>();
    private final List<Integer> extractedRefsFilteredIndices = new ArrayList<>();
    private final DefaultListModel<String> extractedRefsFileListModel = new DefaultListModel<>();
    private final JList<String> extractedRefsFileList;
    private final JTextField extractedRefsFilterField;
    private final JTextField extractedRefsPathField;
    private final DefaultListModel<String> extractedRefsDetailModel = new DefaultListModel<>();
    private final JList<String> extractedRefsDetailList;
    private final DefaultListModel<String> possibleCvesModel = new DefaultListModel<>();
    private final JList<String> possibleCvesList;
    private final DefaultTableModel checklistModel;
    private final JTable checklistTable;
    private final JTextField checklistFilterField;
    private final DefaultTableModel attackGraphChainsModel;
    private final DefaultTableModel sendableUrlsModel;
    private final JTable sendableUrlsTable;
    private final JButton sendToRepeaterBtn;
    private final List<LiveManipulationSlot> liveSlots = new ArrayList<>();
    private final DefaultListModel<String> liveSlotsListModel = new DefaultListModel<>();
    private final JList<String> liveSlotsList;
    private final JTextArea liveRequestArea;
    private final JTextArea liveResponseArea;
    private int liveSlotsSelectedIndex = -1;
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private static final String PREFS_NODE = "unveil-burp";
    private static final int RECENT_TARGETS_MAX = 5;
    private final List<String> recentTargets = new ArrayList<>();

    private static final class ExtractedRefEntry {
        final String file;
        final List<String> refs;
        ExtractedRefEntry(String file, List<String> refs) {
            this.file = file != null ? file : "";
            this.refs = refs != null ? refs : Collections.emptyList();
        }
        String shortDisplay() {
            if (file.isEmpty()) return "(no path)";
            String[] parts = file.split("/");
            if (parts.length >= 2) return parts[parts.length - 2] + "/" + parts[parts.length - 1];
            return parts[parts.length - 1];
        }
    }

    private static final class LiveManipulationSlot {
        final String url;
        final String source;
        final String label;
        String requestText;
        String responseText;

        LiveManipulationSlot(String url, String source, String label) {
            this.url = url != null ? url : "";
            this.source = source != null ? source : "";
            this.label = label != null ? label : "";
            this.requestText = "";
            this.responseText = "";
        }
    }

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
        JButton resetBtn = new JButton("Reset");
        resetBtn.setToolTipText("Clear all results and refresh the report area");
        resetBtn.addActionListener(e -> resetResults());
        inputPanel.add(resetBtn);

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
        optOffensive.setToolTipText("Offensive surface synthesis (exploit-chain modeling, attack graph)");
        optionsPanel.add(optOffensive);
        this.optForce = new JCheckBox("Force (-f)", false);
        optForce.setToolTipText("Force analysis of unsigned / malformed binaries");
        optionsPanel.add(optForce);
        this.optCve = new JCheckBox("CVE (--cve)", false);
        optCve.setToolTipText("Add possible_cves (hunt queries) to report");
        optionsPanel.add(optCve);

        // Daemon mode
        JPanel daemonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        this.useDaemonCheck = new JCheckBox("Use daemon", false);
        useDaemonCheck.setToolTipText("Call POST /scan instead of CLI (faster repeat scans)");
        daemonPanel.add(useDaemonCheck);
        this.daemonUrlField = new JTextField(28);
        daemonUrlField.setToolTipText("e.g. http://127.0.0.1:8000");
        daemonUrlField.setText("http://127.0.0.1:8000");
        daemonPanel.add(new JLabel("URL:"));
        daemonPanel.add(daemonUrlField);

        // Limits (optional)
        JPanel limitsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        limitsPanel.add(new JLabel("Max files:"));
        this.maxFilesSpinner = new JSpinner(new javax.swing.SpinnerNumberModel(80, 1, 10000, 1));
        maxFilesSpinner.setToolTipText("Leave default or set (CLI --max-files)");
        limitsPanel.add(maxFilesSpinner);
        limitsPanel.add(new JLabel("Max size (MB):"));
        this.maxSizeMbSpinner = new JSpinner(new javax.swing.SpinnerNumberModel(120, 1, 10000, 10));
        limitsPanel.add(maxSizeMbSpinner);
        limitsPanel.add(new JLabel("Max per type:"));
        this.maxPerTypeSpinner = new JSpinner(new javax.swing.SpinnerNumberModel(500, 1, 10000, 50));
        limitsPanel.add(maxPerTypeSpinner);

        // Baseline
        JPanel baselinePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        baselinePanel.add(new JLabel("Baseline (optional):"));
        this.baselinePathField = new JTextField(35);
        baselinePathField.setToolTipText("Path to baseline report JSON for diff");
        baselinePanel.add(baselinePathField);
        JButton baselineBrowseBtn = new JButton("Browse…");
        baselineBrowseBtn.addActionListener(ev -> {
            JFileChooser ch = new JFileChooser();
            ch.setSelectedFile(new File("baseline-report.json"));
            if (ch.showOpenDialog(mainPanel) == JFileChooser.APPROVE_OPTION && ch.getSelectedFile() != null)
                baselinePathField.setText(ch.getSelectedFile().getAbsolutePath());
        });
        baselinePanel.add(baselineBrowseBtn);

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
        String extVer = extensionVersion();
        this.versionLabel = new JLabel("Extension " + extVer + " · CLI: —");
        versionLabel.setForeground(new Color(100, 100, 100));
        versionLabel.setFont(versionLabel.getFont().deriveFont(Font.ITALIC, versionLabel.getFont().getSize2D() - 1));
        unveilPathPanel.add(versionLabel);

        // Proxy / Cert helper (thick client: proxy env + CA cert instructions)
        JPanel proxyCertPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        proxyCertPanel.setBorder(BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(), "Proxy (for thick clients)", 0, 0, null));
        proxyCertPanel.add(new JLabel("Listener:"));
        this.proxyHostPortField = new JTextField(14);
        proxyHostPortField.setToolTipText("Burp proxy listener, e.g. 127.0.0.1:8080");
        proxyHostPortField.setText(detectProxyListener());
        proxyHostPortField.addFocusListener(new java.awt.event.FocusAdapter() {
            @Override
            public void focusLost(java.awt.event.FocusEvent e) {
                savePreferences();
            }
        });
        proxyCertPanel.add(proxyHostPortField);
        JButton copyProxyEnvBtn = new JButton("Copy proxy env");
        copyProxyEnvBtn.setToolTipText("Copy HTTP_PROXY and HTTPS_PROXY for use in terminal or app launcher");
        copyProxyEnvBtn.addActionListener(e -> copyProxyEnv());
        proxyCertPanel.add(copyProxyEnvBtn);
        JButton copyProxyUrlBtn = new JButton("Copy proxy URL");
        copyProxyUrlBtn.setToolTipText("Copy single proxy URL (e.g. http://127.0.0.1:8080) for apps that take one URL");
        copyProxyUrlBtn.addActionListener(e -> copyProxyUrl());
        proxyCertPanel.add(copyProxyUrlBtn);
        JButton copyCaCertInstructionsBtn = new JButton("Copy CA cert instructions");
        copyCaCertInstructionsBtn.setToolTipText("Copy steps to export and install Burp's CA certificate for TLS interception");
        copyCaCertInstructionsBtn.addActionListener(e -> copyCaCertInstructions());
        proxyCertPanel.add(copyCaCertInstructionsBtn);
        JButton openSettingsBtn = new JButton("Open Settings");
        openSettingsBtn.setToolTipText("Open Burp Settings (Proxy listener is under Tools → Proxy → Options)");
        openSettingsBtn.addActionListener(e -> showProxySettingsHint());
        proxyCertPanel.add(openSettingsBtn);

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
        JButton exportSarifBtn = new JButton("Export SARIF…");
        exportSarifBtn.addActionListener(e -> exportSarif());
        resultsToolbar.add(exportSarifBtn);
        resultsToolbar.setVisible(false);

        this.resultsTabs = new JTabbedPane();
        this.summaryArea = new JTextArea(8, 60);
        summaryArea.setEditable(false);
        summaryArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        summaryArea.setLineWrap(true);
        summaryArea.setWrapStyleWord(true);
        summaryArea.setText(EMPTY_MESSAGE);
        resultsTabs.addTab("Summary", new JScrollPane(summaryArea));

        JPanel discoveredHtmlPanel = new JPanel(new BorderLayout(4, 4));
        this.discoveredHtmlList = new JList<>(discoveredHtmlModel);
        discoveredHtmlList.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        discoveredHtmlPanel.add(new JScrollPane(discoveredHtmlList), BorderLayout.CENTER);
        JPanel discoveredHtmlToolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        discoveredHtmlToolbar.add(new JLabel("HTML files found inside the target — open for attacks, redev, or transparency."));
        JButton viewInPanelBtn = new JButton("View in panel");
        viewInPanelBtn.setToolTipText("Render HTML inside Burp (avoids blank browser with file://)");
        viewInPanelBtn.addActionListener(e -> viewSelectedHtmlInPanel());
        discoveredHtmlToolbar.add(viewInPanelBtn);
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
        JMenuItem viewInPanelItem = new JMenuItem("View in panel");
        viewInPanelItem.addActionListener(e -> viewSelectedHtmlInPanel());
        discoveredHtmlMenu.add(viewInPanelItem);
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
        this.discoveredAssetsTypeFilter = new JComboBox<>(new String[] { "All", "html", "xml", "json", "config", "script", "plist", "manifest", "policy", "cert", "data", "env" });
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

        // Chainability
        this.chainabilityModel = new DefaultTableModel(new String[] { "File", "Ref", "In scope", "Matched type" }, 0);
        this.chainabilityTable = new JTable(chainabilityModel);
        chainabilityTable.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        chainabilityTable.setAutoCreateRowSorter(true);
        resultsTabs.addTab("Chainability", new JScrollPane(chainabilityTable));

        // Extracted refs — master/detail: file list (short names) | path + refs list
        this.extractedRefsPathField = new JTextField();
        extractedRefsPathField.setEditable(false);
        extractedRefsPathField.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        this.extractedRefsDetailList = new JList<>(extractedRefsDetailModel);
        extractedRefsDetailList.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        extractedRefsDetailList.setToolTipText("References extracted from the selected file");
        extractedRefsDetailList.setCellRenderer(new DefaultListCellRenderer() {
            @Override
            public java.awt.Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean selected, boolean focus) {
                java.awt.Component c = super.getListCellRendererComponent(list, value, index, selected, focus);
                setToolTipText(value != null ? value.toString() : null);
                return c;
            }
        });
        JPopupMenu extractedRefsDetailMenu = new JPopupMenu();
        JMenuItem copyOneRefItem = new JMenuItem("Copy selected ref");
        copyOneRefItem.addActionListener(e -> {
            String ref = extractedRefsDetailList.getSelectedValue();
            if (ref != null && !ref.isEmpty())
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(ref), null);
        });
        extractedRefsDetailMenu.add(copyOneRefItem);
        extractedRefsDetailList.setComponentPopupMenu(extractedRefsDetailMenu);
        this.extractedRefsFileList = new JList<>(extractedRefsFileListModel);
        extractedRefsFileList.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        extractedRefsFileList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        extractedRefsFileList.setCellRenderer(new DefaultListCellRenderer() {
            @Override
            public java.awt.Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean selected, boolean focus) {
                java.awt.Component c = super.getListCellRendererComponent(list, value, index, selected, focus);
                if (index >= 0 && index < extractedRefsFilteredIndices.size()) {
                    int dataIdx = extractedRefsFilteredIndices.get(index);
                    if (dataIdx < extractedRefsData.size())
                        setToolTipText(extractedRefsData.get(dataIdx).file);
                } else setToolTipText(null);
                return c;
            }
        });
        extractedRefsFileList.addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) return;
            int i = extractedRefsFileList.getSelectedIndex();
            if (i >= 0 && i < extractedRefsFilteredIndices.size()) {
                ExtractedRefEntry entry = extractedRefsData.get(extractedRefsFilteredIndices.get(i));
                extractedRefsPathField.setText(entry.file);
                extractedRefsPathField.setToolTipText(entry.file);
                extractedRefsDetailModel.clear();
                for (String ref : entry.refs) extractedRefsDetailModel.addElement(ref);
            } else {
                extractedRefsPathField.setText("");
                extractedRefsPathField.setToolTipText(null);
                extractedRefsDetailModel.clear();
            }
        });
        this.extractedRefsFilterField = new JTextField(20);
        extractedRefsFilterField.setToolTipText("Filter files by path or ref content");
        extractedRefsFilterField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override public void insertUpdate(javax.swing.event.DocumentEvent e) { applyExtractedRefsFilter(); }
            @Override public void removeUpdate(javax.swing.event.DocumentEvent e) { applyExtractedRefsFilter(); }
            @Override public void changedUpdate(javax.swing.event.DocumentEvent e) { applyExtractedRefsFilter(); }
        });
        JPanel extractedRefsLeft = new JPanel(new BorderLayout(4, 4));
        JPanel extractedRefsFilterPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        extractedRefsFilterPanel.add(new JLabel("Filter:"));
        extractedRefsFilterPanel.add(extractedRefsFilterField);
        extractedRefsLeft.add(extractedRefsFilterPanel, BorderLayout.NORTH);
        extractedRefsLeft.add(new JScrollPane(extractedRefsFileList), BorderLayout.CENTER);
        JPanel extractedRefsRight = new JPanel(new BorderLayout(4, 4));
        JPanel extractedRefsPathPanel = new JPanel(new BorderLayout(4, 0));
        extractedRefsPathPanel.add(new JLabel("Full path:"), BorderLayout.NORTH);
        extractedRefsPathPanel.add(extractedRefsPathField, BorderLayout.CENTER);
        JPanel extractedRefsPathButtons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton copyExtractedRefsPathBtn = new JButton("Copy path");
        copyExtractedRefsPathBtn.addActionListener(e -> {
            String p = extractedRefsPathField.getText();
            if (p != null && !p.isEmpty())
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(p), null);
        });
        extractedRefsPathButtons.add(copyExtractedRefsPathBtn);
        JButton copyExtractedRefsRefsBtn = new JButton("Copy refs");
        copyExtractedRefsRefsBtn.addActionListener(e -> copySelectedFileRefs());
        extractedRefsPathButtons.add(copyExtractedRefsRefsBtn);
        extractedRefsPathPanel.add(extractedRefsPathButtons, BorderLayout.SOUTH);
        extractedRefsRight.add(extractedRefsPathPanel, BorderLayout.NORTH);
        JPanel extractedRefsDetailWrapper = new JPanel(new BorderLayout(0, 4));
        extractedRefsDetailWrapper.add(new JLabel("Refs (one per line):"), BorderLayout.NORTH);
        JScrollPane extractedRefsDetailScroll = new JScrollPane(extractedRefsDetailList);
        extractedRefsDetailWrapper.add(extractedRefsDetailScroll, BorderLayout.CENTER);
        extractedRefsRight.add(extractedRefsDetailWrapper, BorderLayout.CENTER);
        JSplitPane extractedRefsSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, extractedRefsLeft, extractedRefsRight);
        extractedRefsSplit.setResizeWeight(0.35);
        extractedRefsSplit.setDividerLocation(280);
        JPanel extractedRefsPanel = new JPanel(new BorderLayout());
        extractedRefsPanel.add(extractedRefsSplit, BorderLayout.CENTER);
        resultsTabs.addTab("Extracted refs", extractedRefsPanel);

        // Possible CVEs
        this.possibleCvesList = new JList<>(possibleCvesModel);
        possibleCvesList.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JPanel possibleCvesPanel = new JPanel(new BorderLayout(4, 4));
        JPanel possibleCvesToolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        JLabel possibleCvesLabel = new JLabel("Hunt queries / CVE search terms (paste into NVD/CVE database for CVE IDs):");
        possibleCvesLabel.setToolTipText("These are search terms, not CVE numbers. Use at nvd.nist.gov or similar to find CVEs.");
        possibleCvesToolbar.add(possibleCvesLabel);
        JButton copyCvesBtn = new JButton("Copy all");
        copyCvesBtn.addActionListener(e -> copyPossibleCves());
        possibleCvesToolbar.add(copyCvesBtn);
        possibleCvesPanel.add(possibleCvesToolbar, BorderLayout.NORTH);
        possibleCvesPanel.add(new JScrollPane(possibleCvesList), BorderLayout.CENTER);
        resultsTabs.addTab("Possible CVEs", possibleCvesPanel);

        // Checklist (potential secrets / static analysis no-nos)
        this.checklistModel = new DefaultTableModel(new String[] { "File", "Pattern", "Snippet", "Line" }, 0);
        this.checklistTable = new JTable(checklistModel);
        checklistTable.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        checklistTable.setAutoCreateRowSorter(true);
        this.checklistFilterField = new JTextField(18);
        checklistFilterField.setToolTipText("Filter by File, Pattern, or Snippet");
        checklistFilterField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override public void insertUpdate(javax.swing.event.DocumentEvent e) { applyChecklistFilter(); }
            @Override public void removeUpdate(javax.swing.event.DocumentEvent e) { applyChecklistFilter(); }
            @Override public void changedUpdate(javax.swing.event.DocumentEvent e) { applyChecklistFilter(); }
        });
        JPanel checklistPanel = new JPanel(new BorderLayout(4, 4));
        JPanel checklistToolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        checklistToolbar.add(new JLabel("Filter:"));
        checklistToolbar.add(checklistFilterField);
        checklistPanel.add(checklistToolbar, BorderLayout.NORTH);
        checklistPanel.add(new JScrollPane(checklistTable), BorderLayout.CENTER);
        resultsTabs.addTab("Checklist", checklistPanel);

        // Attack graph: visual chains + sendable URLs (one-click Send to Repeater)
        this.attackGraphChainsModel = new DefaultTableModel(
            new String[] { "Missing role", "Surface", "Hunt targets", "Reason", "Matched paths" }, 0);
        this.sendableUrlsModel = new DefaultTableModel(new String[] { "URL", "Source", "Label" }, 0);
        this.sendableUrlsTable = new JTable(sendableUrlsModel);
        sendableUrlsTable.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        sendableUrlsTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        this.sendToRepeaterBtn = new JButton("Send selected to Repeater");
        sendToRepeaterBtn.setToolTipText("Create a Repeater tab for each selected http(s) URL (or all if none selected)");
        sendToRepeaterBtn.addActionListener(e -> sendSelectedToRepeater());
        JPanel attackGraphPanel = new JPanel(new BorderLayout(4, 4));
        JPanel chainsPanel = new JPanel(new BorderLayout());
        chainsPanel.add(new JLabel("Chains: missing role → surface → hunt targets (with matched paths from scan)"), BorderLayout.NORTH);
        chainsPanel.add(new JScrollPane(new AttackGraphPaintPanel(attackGraphChainsModel)), BorderLayout.CENTER);
        JPanel sendablePanel = new JPanel(new BorderLayout(4, 4));
        JPanel sendableToolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        sendableToolbar.add(new JLabel("Sendable URLs (from refs / attack graph):"));
        sendableToolbar.add(sendToRepeaterBtn);
        sendablePanel.add(sendableToolbar, BorderLayout.NORTH);
        sendablePanel.add(new JScrollPane(sendableUrlsTable), BorderLayout.CENTER);
        attackGraphPanel.add(chainsPanel, BorderLayout.NORTH);
        attackGraphPanel.add(sendablePanel, BorderLayout.CENTER);
        resultsTabs.addTab("Attack graph", attackGraphPanel);

        // Live manipulation: per-URL slots with request/response edit and Send (Repeater-grade)
        this.liveRequestArea = new JTextArea(12, 70);
        liveRequestArea.setEditable(true);
        liveRequestArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        liveRequestArea.setLineWrap(false);
        this.liveResponseArea = new JTextArea(12, 70);
        liveResponseArea.setEditable(true);
        liveResponseArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        liveResponseArea.setLineWrap(false);
        this.liveSlotsList = new JList<>(liveSlotsListModel);
        liveSlotsList.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        liveSlotsList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        liveSlotsList.addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) return;
            saveCurrentLiveSlotContent();
            int i = liveSlotsList.getSelectedIndex();
            liveSlotsSelectedIndex = i;
            if (i >= 0 && i < liveSlots.size()) {
                LiveManipulationSlot slot = liveSlots.get(i);
                liveRequestArea.setText(slot.requestText != null ? slot.requestText : "");
                liveResponseArea.setText(slot.responseText != null ? slot.responseText : "");
            } else {
                liveRequestArea.setText("");
                liveResponseArea.setText("");
            }
        });
        JPanel liveLeft = new JPanel(new BorderLayout(4, 4));
        liveLeft.add(new JLabel("Phases (from sendable URLs):"), BorderLayout.NORTH);
        liveLeft.add(new JScrollPane(liveSlotsList), BorderLayout.CENTER);
        JPanel liveRight = new JPanel(new BorderLayout(4, 4));
        JPanel liveRequestPanel = new JPanel(new BorderLayout(2, 2));
        liveRequestPanel.add(new JLabel("Request (edit and Send):"), BorderLayout.NORTH);
        liveRequestPanel.add(new JScrollPane(liveRequestArea), BorderLayout.CENTER);
        JPanel liveResponsePanel = new JPanel(new BorderLayout(2, 2));
        liveResponsePanel.add(new JLabel("Response:"), BorderLayout.NORTH);
        liveResponsePanel.add(new JScrollPane(liveResponseArea), BorderLayout.CENTER);
        JPanel liveButtons = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        JButton liveSendBtn = new JButton("Send");
        liveSendBtn.setToolTipText("Send request and show response (via Burp HTTP client)");
        liveSendBtn.addActionListener(e -> sendLiveRequest());
        liveButtons.add(liveSendBtn);
        JButton liveLoadFromProxyBtn = new JButton("Load from Proxy");
        liveLoadFromProxyBtn.setToolTipText("Fill request from latest matching Proxy history entry");
        liveLoadFromProxyBtn.addActionListener(e -> loadLiveRequestFromProxy());
        liveButtons.add(liveLoadFromProxyBtn);
        JButton liveResetSlotBtn = new JButton("Reset slot");
        liveResetSlotBtn.setToolTipText("Reset this phase to initial request; clear response");
        liveResetSlotBtn.addActionListener(e -> resetCurrentLiveSlot());
        liveButtons.add(liveResetSlotBtn);
        JButton liveRefreshAllBtn = new JButton("Refresh all");
        liveRefreshAllBtn.setToolTipText("Reset all phases to initial requests and clear responses");
        liveRefreshAllBtn.addActionListener(e -> refreshAllLiveSlots());
        liveButtons.add(liveRefreshAllBtn);
        JPanel liveCenterRight = new JPanel(new BorderLayout(4, 4));
        liveCenterRight.add(liveRequestPanel, BorderLayout.NORTH);
        liveCenterRight.add(liveButtons, BorderLayout.CENTER);
        liveCenterRight.add(liveResponsePanel, BorderLayout.SOUTH);
        JSplitPane liveSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, liveLeft, liveCenterRight);
        liveSplit.setResizeWeight(0.25);
        liveSplit.setDividerLocation(200);
        JPanel liveManipulationPanel = new JPanel(new BorderLayout());
        liveManipulationPanel.add(liveSplit, BorderLayout.CENTER);
        resultsTabs.addTab("Live manipulation", liveManipulationPanel);

        this.rawJsonArea = new JTextArea(18, 80);
        rawJsonArea.setEditable(false);
        rawJsonArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        rawJsonArea.setLineWrap(false);
        rawJsonArea.setText(EMPTY_MESSAGE);
        JComponent rawJsonLineNumbers = new LineNumberView(rawJsonArea);
        JScrollPane rawJsonScroll = new JScrollPane(rawJsonArea);
        rawJsonScroll.setRowHeaderView(rawJsonLineNumbers);
        rawJsonArea.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override public void insertUpdate(javax.swing.event.DocumentEvent e) { rawJsonLineNumbers.revalidate(); rawJsonLineNumbers.repaint(); }
            @Override public void removeUpdate(javax.swing.event.DocumentEvent e) { rawJsonLineNumbers.revalidate(); rawJsonLineNumbers.repaint(); }
            @Override public void changedUpdate(javax.swing.event.DocumentEvent e) { rawJsonLineNumbers.revalidate(); rawJsonLineNumbers.repaint(); }
        });
        resultsTabs.addTab("Raw JSON", rawJsonScroll);

        JPanel top = new JPanel(new BorderLayout(0, 10));
        top.add(intro, BorderLayout.NORTH);
        JPanel controls = new JPanel();
        controls.setLayout(new BoxLayout(controls, BoxLayout.PAGE_AXIS));
        controls.add(inputPanel);
        controls.add(optionsPanel);
        controls.add(daemonPanel);
        controls.add(limitsPanel);
        controls.add(baselinePanel);
        controls.add(unveilPathPanel);
        controls.add(proxyCertPanel);
        top.add(controls, BorderLayout.CENTER);

        JPanel center = new JPanel(new BorderLayout(0, 8));
        center.add(resultsToolbar, BorderLayout.NORTH);
        center.add(resultsTabs, BorderLayout.CENTER);
        resultsTabs.setBorder(BorderFactory.createEtchedBorder());

        mainPanel.add(top, BorderLayout.NORTH);
        mainPanel.add(center, BorderLayout.CENTER);

        loadPreferences();
        executor.submit(this::fetchUnveilVersion);
    }

    private void loadPreferences() {
        try {
            Preferences prefs = Preferences.userRoot().node(PREFS_NODE);
            String exe = prefs.get("unveilExe", "");
            if (!exe.isEmpty()) unveilExeField.setText(exe);
            String daemonUrl = prefs.get("daemonUrl", "http://127.0.0.1:8000");
            daemonUrlField.setText(daemonUrl);
            useDaemonCheck.setSelected(prefs.getBoolean("useDaemon", false));
            optExtended.setSelected(prefs.getBoolean("optExtended", false));
            optOffensive.setSelected(prefs.getBoolean("optOffensive", false));
            optForce.setSelected(prefs.getBoolean("optForce", false));
            optCve.setSelected(prefs.getBoolean("optCve", false));
            maxFilesSpinner.setValue(prefs.getInt("maxFiles", 80));
            maxSizeMbSpinner.setValue(prefs.getInt("maxSizeMb", 120));
            maxPerTypeSpinner.setValue(prefs.getInt("maxPerType", 500));
            String baseline = prefs.get("baselinePath", "");
            if (!baseline.isEmpty()) baselinePathField.setText(baseline);
            String proxyHostPort = prefs.get("proxyHostPort", "");
            if (!proxyHostPort.isEmpty()) proxyHostPortField.setText(proxyHostPort);
        } catch (Exception e) {
            logging.logToError("Load preferences: " + e.getMessage());
        }
    }

    private void savePreferences() {
        try {
            Preferences prefs = Preferences.userRoot().node(PREFS_NODE);
            String exe = unveilExeField.getText();
            prefs.put("unveilExe", exe != null ? exe.trim() : "");
            prefs.put("daemonUrl", daemonUrlField.getText() != null ? daemonUrlField.getText().trim() : "http://127.0.0.1:8000");
            prefs.putBoolean("useDaemon", useDaemonCheck.isSelected());
            prefs.putBoolean("optExtended", optExtended.isSelected());
            prefs.putBoolean("optOffensive", optOffensive.isSelected());
            prefs.putBoolean("optForce", optForce.isSelected());
            prefs.putBoolean("optCve", optCve.isSelected());
            prefs.putInt("maxFiles", ((Number) maxFilesSpinner.getValue()).intValue());
            prefs.putInt("maxSizeMb", ((Number) maxSizeMbSpinner.getValue()).intValue());
            prefs.putInt("maxPerType", ((Number) maxPerTypeSpinner.getValue()).intValue());
            String baseline = baselinePathField.getText();
            prefs.put("baselinePath", baseline != null ? baseline.trim() : "");
            String proxyHostPort = proxyHostPortField.getText();
            prefs.put("proxyHostPort", proxyHostPort != null ? proxyHostPort.trim() : "");
        } catch (Exception e) {
            logging.logToError("Save preferences: " + e.getMessage());
        }
    }

    private void fetchUnveilVersion() {
        try {
            String exe = resolveUnveilPath();
            ProcessBuilder pb = new ProcessBuilder(exe, "--version");
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
            p.waitFor();
            String version = "—";
            if (!out.isEmpty()) {
                String[] lines = out.split("\\r?\\n");
                for (int i = lines.length - 1; i >= 0; i--) {
                    String line = lines[i].trim();
                    if (line.contains("RADAR") && line.contains("v")) {
                        version = line;
                        break;
                    }
                }
                if ("—".equals(version) && lines.length > 0)
                    version = lines[lines.length - 1].trim();
            }
            String finalVersion = version;
            String extVer = extensionVersion();
            SwingUtilities.invokeLater(() -> versionLabel.setText("Extension " + extVer + " · CLI: " + finalVersion));
        } catch (Exception e) {
            SwingUtilities.invokeLater(() -> versionLabel.setText("Extension " + extensionVersion() + " · CLI: not found"));
        }
    }

    private static String extensionVersion() {
        String v = UnveilTab.class.getPackage().getImplementationVersion();
        return v != null ? v : "?";
    }

    public JComponent getTabComponent() {
        return mainPanel;
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
        rawJsonArea.setText("");
        resultsToolbar.setVisible(false);
        scanButton.setEnabled(false);
        if (useDaemonCheck.isSelected()) {
            executor.submit(() -> runUnveilViaDaemon(target));
        } else {
            executor.submit(() -> runUnveil(target));
        }
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
        rawJsonArea.setText("");
        resultsToolbar.setVisible(false);
        scanButton.setEnabled(false);
        if (useDaemonCheck.isSelected()) {
            executor.submit(() -> runUnveilViaDaemon(last));
        } else {
            executor.submit(() -> runUnveil(last));
        }
    }

    private void resetResults() {
        summaryArea.setText(EMPTY_MESSAGE);
        summaryArea.setCaretPosition(0);
        rawJsonArea.setText(EMPTY_MESSAGE);
        rawJsonArea.setCaretPosition(0);
        resultsToolbar.setVisible(false);
        discoveredHtmlModel.clear();
        discoveredAssetsModel.setRowCount(0);
        applyDiscoveredAssetsTypeFilter();
        chainabilityModel.setRowCount(0);
        extractedRefsData.clear();
        extractedRefsFilteredIndices.clear();
        extractedRefsFileListModel.clear();
        extractedRefsPathField.setText("");
        extractedRefsPathField.setToolTipText(null);
        extractedRefsDetailModel.clear();
        extractedRefsFilterField.setText("");
        possibleCvesModel.clear();
        checklistModel.setRowCount(0);
        checklistFilterField.setText("");
        attackGraphChainsModel.setRowCount(0);
        sendableUrlsModel.setRowCount(0);
        liveSlots.clear();
        liveSlotsListModel.clear();
        liveSlotsSelectedIndex = -1;
        liveRequestArea.setText("");
        liveResponseArea.setText("");
        statusLabel.setText("Results cleared.");
    }

    private void saveCurrentLiveSlotContent() {
        if (liveSlotsSelectedIndex >= 0 && liveSlotsSelectedIndex < liveSlots.size()) {
            LiveManipulationSlot slot = liveSlots.get(liveSlotsSelectedIndex);
            slot.requestText = liveRequestArea.getText();
            slot.responseText = liveResponseArea.getText();
        }
    }

    private void sendLiveRequest() {
        saveCurrentLiveSlotContent();
        String requestText = liveRequestArea.getText();
        if (requestText == null || requestText.trim().isEmpty()) {
            statusLabel.setText("Request is empty.");
            return;
        }
        try {
            HttpRequest request = HttpRequest.httpRequest(requestText);
            Http http = api.http();
            HttpRequestResponse resp = http.sendRequest(request);
            if (resp != null && resp.response() != null) {
                String responseStr = resp.response().toString();
                liveResponseArea.setText(responseStr);
                if (liveSlotsSelectedIndex >= 0 && liveSlotsSelectedIndex < liveSlots.size())
                    liveSlots.get(liveSlotsSelectedIndex).responseText = responseStr;
                statusLabel.setText("Response received.");
            } else {
                liveResponseArea.setText("(no response)");
                statusLabel.setText("No response.");
            }
        } catch (Exception ex) {
            logging.logToError("Live Send: " + ex.getMessage());
            liveResponseArea.setText("Error: " + ex.getMessage());
            statusLabel.setText("Send failed.");
        }
    }

    private void loadLiveRequestFromProxy() {
        if (liveSlotsSelectedIndex < 0 || liveSlotsSelectedIndex >= liveSlots.size()) {
            statusLabel.setText("Select a phase first.");
            return;
        }
        LiveManipulationSlot slot = liveSlots.get(liveSlotsSelectedIndex);
        try {
            var history = api.proxy().history();
            if (history == null) {
                statusLabel.setText("Proxy history not available.");
                return;
            }
            String targetUrl = slot.url;
            for (int i = history.size() - 1; i >= 0; i--) {
                var item = history.get(i);
                if (item != null) {
                    HttpRequest req = item.finalRequest();
                    if (req != null) {
                        String u = item.url();
                        if (u == null) u = req.url();
                        if (u != null && targetUrl != null && (u.startsWith(targetUrl.replaceFirst("/$", "")) || targetUrl.startsWith(u.replaceFirst("/$", "")))) {
                            liveRequestArea.setText(req.toString());
                            slot.requestText = liveRequestArea.getText();
                            statusLabel.setText("Loaded from Proxy history.");
                            return;
                        }
                    }
                }
            }
            statusLabel.setText("No matching request in Proxy history.");
        } catch (Exception ex) {
            logging.logToError("Load from Proxy: " + ex.getMessage());
            statusLabel.setText("Load from Proxy failed.");
        }
    }

    private void resetCurrentLiveSlot() {
        if (liveSlotsSelectedIndex >= 0 && liveSlotsSelectedIndex < liveSlots.size()) {
            LiveManipulationSlot slot = liveSlots.get(liveSlotsSelectedIndex);
            slot.requestText = "";
            slot.responseText = "";
            try {
                HttpRequest req = HttpRequest.httpRequestFromUrl(slot.url);
                slot.requestText = req != null ? req.toString() : "GET " + slot.url + " HTTP/1.1\r\n\r\n";
            } catch (Exception ex) {
                slot.requestText = "GET " + slot.url + " HTTP/1.1\r\nHost: " + slot.url.replaceFirst("^https?://([^/]+).*", "$1") + "\r\n\r\n";
            }
            liveRequestArea.setText(slot.requestText);
            liveResponseArea.setText("");
            statusLabel.setText("Slot reset.");
        }
    }

    private void refreshAllLiveSlots() {
        saveCurrentLiveSlotContent();
        for (LiveManipulationSlot slot : liveSlots) {
            slot.requestText = "";
            slot.responseText = "";
            try {
                HttpRequest req = HttpRequest.httpRequestFromUrl(slot.url);
                slot.requestText = req != null ? req.toString() : "GET " + slot.url + " HTTP/1.1\r\n\r\n";
            } catch (Exception ex) {
                slot.requestText = "GET " + slot.url + " HTTP/1.1\r\nHost: " + slot.url.replaceFirst("^https?://([^/]+).*", "$1") + "\r\n\r\n";
            }
        }
        if (liveSlotsSelectedIndex >= 0 && liveSlotsSelectedIndex < liveSlots.size()) {
            LiveManipulationSlot s = liveSlots.get(liveSlotsSelectedIndex);
            liveRequestArea.setText(s.requestText);
            liveResponseArea.setText("");
        }
        statusLabel.setText("All phases refreshed.");
    }

    private void runUnveilViaDaemon(String target) {
        String urlStr = daemonUrlField.getText() != null ? daemonUrlField.getText().trim() : "";
        if (urlStr.isEmpty()) {
            onUnveilError("Daemon URL is empty.", "Set URL or use CLI.", false);
            return;
        }
        String base = urlStr.endsWith("/") ? urlStr : urlStr + "/";
        try {
            URL url = new URL(base + "scan");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setDoOutput(true);
            conn.setConnectTimeout(30000);
            conn.setReadTimeout(300000);
            JsonObject body = new JsonObject();
            body.addProperty("target", target);
            body.addProperty("extended", optExtended.isSelected());
            body.addProperty("offensive", optOffensive.isSelected());
            body.addProperty("max_files", ((Number) maxFilesSpinner.getValue()).intValue());
            body.addProperty("max_size_mb", ((Number) maxSizeMbSpinner.getValue()).intValue());
            body.addProperty("max_per_type", ((Number) maxPerTypeSpinner.getValue()).intValue());
            try (OutputStream os = conn.getOutputStream()) {
                os.write(body.toString().getBytes(StandardCharsets.UTF_8));
            }
            int code = conn.getResponseCode();
            String responseBody = code >= 200 && code < 300
                ? new String(conn.getInputStream().readAllBytes(), StandardCharsets.UTF_8)
                : new String(conn.getErrorStream() != null ? conn.getErrorStream().readAllBytes() : new byte[0], StandardCharsets.UTF_8);
            String finalResult = responseBody.trim();
            SwingUtilities.invokeLater(() -> {
                scanButton.setEnabled(true);
                if (code >= 200 && code < 300 && !finalResult.isEmpty()) {
                    statusLabel.setText("Done (daemon).");
                    recentTargets.remove(target);
                    recentTargets.add(0, target);
                    while (recentTargets.size() > RECENT_TARGETS_MAX) recentTargets.remove(recentTargets.size() - 1);
                    applyReport(finalResult);
                    resultsToolbar.setVisible(true);
                    savePreferences();
                } else {
                    statusLabel.setText("Daemon error.");
                    summaryArea.setText("Daemon returned " + code + ".\n\n" + (finalResult.isEmpty() ? "No body." : finalResult));
                    resultsToolbar.setVisible(false);
                }
            });
        } catch (Exception ex) {
            logging.logToError("Unveil daemon failed: " + ex.getMessage());
            String msg = ex.getMessage();
            SwingUtilities.invokeLater(() -> {
                scanButton.setEnabled(true);
                statusLabel.setText("Error.");
                summaryArea.setText("Could not call daemon.\n\n" + (msg != null ? msg : ""));
                resultsToolbar.setVisible(false);
            });
        }
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
        if (optCve.isSelected()) args.add("--cve");
        Object mf = maxFilesSpinner.getValue();
        if (mf != null && ((Number) mf).intValue() != 80) {
            args.add("--max-files");
            args.add(String.valueOf(((Number) mf).intValue()));
        }
        Object msm = maxSizeMbSpinner.getValue();
        if (msm != null && ((Number) msm).intValue() != 120) {
            args.add("--max-size-mb");
            args.add(String.valueOf(((Number) msm).intValue()));
        }
        Object mpt = maxPerTypeSpinner.getValue();
        if (mpt != null && ((Number) mpt).intValue() != 500) {
            args.add("--max-per-type");
            args.add(String.valueOf(((Number) mpt).intValue()));
        }
        String baseline = baselinePathField.getText() != null ? baselinePathField.getText().trim() : "";
        if (!baseline.isEmpty()) {
            File bf = new File(baseline);
            if (bf.isFile()) {
                args.add("--baseline");
                args.add(bf.getAbsolutePath());
            }
        }
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
                    savePreferences();
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

            // Specifications (PE/Mach-O/.app main binary — always show section so user knows it exists)
            summary.append("Specifications\n");
            JsonObject specs = report.has("specifications") ? report.getAsJsonObject("specifications") : null;
            if (specs != null && specs.size() > 0) {
                String[] order = new String[] {
                    "type", "path", "bundle", "physical_size", "machine", "characteristics", "image_size",
                    "code_size", "initialized_data_size", "linker_version", "subsystem", "dll_characteristics",
                    "file_version", "product_version", "FileDescription", "ProductName", "LegalCopyright",
                    "OriginalFilename", "InternalName", "stack_reserve", "stack_commit", "heap_reserve", "heap_commit",
                    "file_type", "format", "cpu_type", "libraries_count"
                };
                java.util.Set<String> seen = new java.util.HashSet<>();
                for (String key : order) {
                    if (specs.has(key)) {
                        summary.append("  ").append(key).append(": ").append(str(specs.get(key))).append("\n");
                        seen.add(key);
                    }
                }
                for (String key : specs.keySet()) {
                    if (!seen.contains(key) && specs.get(key) != null && !specs.get(key).isJsonNull())
                        summary.append("  ").append(key).append(": ").append(str(specs.get(key))).append("\n");
                }
            } else {
                summary.append("  (none — use latest Unveil CLI for .app binary specs)\n");
            }
            summary.append("\n");

            // What it's made of (general: assets first, then detected frameworks)
            summary.append("What it's made of\n");
            if (report.has("discovered_assets")) {
                JsonObject da = report.getAsJsonObject("discovered_assets");
                if (da != null && da.size() > 0) {
                    List<String> counts = new ArrayList<>();
                    for (String type : new String[] { "script", "html", "plist", "config", "json", "manifest", "xml", "policy", "cert", "data", "env" }) {
                        if (da.has(type)) {
                            JsonArray arr = da.getAsJsonArray(type);
                            int n = arr != null ? arr.size() : 0;
                            if (n > 0) counts.add(n + " " + type);
                        }
                    }
                    if (!counts.isEmpty()) summary.append("  Assets: ").append(String.join(", ", counts)).append("\n");
                }
            }
            if (report.has("electron_info")) {
                JsonObject ei = report.getAsJsonObject("electron_info");
                if (ei != null && ei.size() > 0) {
                    String ev = ei.has("electron_version") ? str(ei.get("electron_version")) : null;
                    summary.append("  Frameworks: Electron").append(ev != null && !ev.isEmpty() ? " " + ev : "").append("\n");
                    for (String key : ei.keySet()) {
                        if ("electron_version".equals(key)) continue;
                        JsonElement v = ei.get(key);
                        summary.append("    ").append(key).append(": ").append(v.isJsonPrimitive() ? v.getAsString() : v.toString()).append("\n");
                    }
                } else summary.append("  Frameworks: none detected\n");
            } else summary.append("  Frameworks: none detected\n");
            summary.append("\n");

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
                        summary.append("  Attack families (taxonomy): ");
                        List<String> list = new ArrayList<>();
                        for (JsonElement el : arr) list.add(el.getAsString());
                        summary.append(String.join(", ", list)).append("\n");
                    }
                }
                if (report.has("attack_graph")) {
                    JsonObject ag = report.getAsJsonObject("attack_graph");
                    if (ag != null && ag.has("chains")) {
                        JsonArray chains = ag.getAsJsonArray("chains");
                        summary.append("\nAttack graph chains: ").append(chains != null ? chains.size() : 0).append("\n");
                    }
                }
            }
            if (report.has("chainability")) {
                JsonArray ca = report.getAsJsonArray("chainability");
                int inScope = 0;
                if (ca != null) {
                    for (JsonElement el : ca) {
                        if (el.isJsonObject() && el.getAsJsonObject().has("in_scope") && el.getAsJsonObject().get("in_scope").getAsBoolean())
                            inScope++;
                    }
                    summary.append("Chainability: ").append(ca.size()).append(" refs, ").append(inScope).append(" in scope\n");
                }
            }
            if (report.has("possible_cves")) {
                JsonArray pc = report.getAsJsonArray("possible_cves");
                summary.append("Possible CVE queries: ").append(pc != null ? pc.size() : 0).append("\n");
            }
            if (report.has("diff")) {
                JsonObject diff = report.getAsJsonObject("diff");
                if (diff != null) {
                    summary.append("\n--- Baseline diff ---\n");
                    if (diff.has("added_findings")) {
                        JsonArray a = diff.getAsJsonArray("added_findings");
                        summary.append("Added findings: ").append(a != null ? a.size() : 0).append("\n");
                    }
                    if (diff.has("removed_findings")) {
                        JsonArray r = diff.getAsJsonArray("removed_findings");
                        summary.append("Removed findings: ").append(r != null ? r.size() : 0).append("\n");
                    }
                    if (diff.has("verdict_changed")) {
                        summary.append("Verdict changed: ").append(diff.get("verdict_changed").getAsBoolean()).append("\n");
                    }
                }
            }

            summaryArea.setText(summary.toString());
            summaryArea.setCaretPosition(0);

            discoveredHtmlModel.clear();
            if (report.has("discovered_html")) {
                JsonArray arr = report.getAsJsonArray("discovered_html");
                if (arr != null) {
                    java.util.Set<String> seenHtml = new java.util.LinkedHashSet<>();
                    for (JsonElement el : arr) {
                        if (el.isJsonPrimitive()) {
                            String path = el.getAsString();
                            if (path != null && !path.isEmpty() && seenHtml.add(path))
                                discoveredHtmlModel.addElement(path);
                        }
                    }
                }
            }
            discoveredAssetsModel.setRowCount(0);
            if (report.has("discovered_assets")) {
                JsonObject assets = report.getAsJsonObject("discovered_assets");
                if (assets != null) {
                    java.util.Set<String> seenAsset = new java.util.HashSet<>();
                    for (String type : assets.keySet()) {
                        JsonArray paths = assets.getAsJsonArray(type);
                        if (paths != null) {
                            for (JsonElement el : paths) {
                                if (el.isJsonPrimitive()) {
                                    String path = el.getAsString();
                                    if (seenAsset.add(path + "\t" + type)) {
                                        discoveredAssetsModel.addRow(new Object[] { path, type });
                                    }
                                }
                            }
                        }
                    }
                }
            }
            applyDiscoveredAssetsTypeFilter();

            chainabilityModel.setRowCount(0);
            if (report.has("chainability")) {
                JsonArray ca = report.getAsJsonArray("chainability");
                if (ca != null) {
                    for (JsonElement el : ca) {
                        JsonObject row = el.getAsJsonObject();
                        chainabilityModel.addRow(new Object[] {
                            str(row.get("file")),
                            str(row.get("ref")),
                            row.has("in_scope") && row.get("in_scope").getAsBoolean() ? "Yes" : "No",
                            str(row.get("matched_type"))
                        });
                    }
                }
            }
            extractedRefsData.clear();
            if (report.has("extracted_refs")) {
                JsonArray er = report.getAsJsonArray("extracted_refs");
                if (er != null) {
                    java.util.Set<String> seenRef = new java.util.HashSet<>();
                    for (JsonElement el : er) {
                        JsonObject o = el.getAsJsonObject();
                        String file = str(o.get("file"));
                        JsonArray refsArr = o.has("refs") ? o.getAsJsonArray("refs") : null;
                        List<String> refsList = new ArrayList<>();
                        if (refsArr != null) {
                            for (int i = 0; i < refsArr.size(); i++)
                                refsList.add(refsArr.get(i).getAsString());
                        }
                        String key = file + "\t" + String.join("\t", refsList);
                        if (seenRef.add(key))
                            extractedRefsData.add(new ExtractedRefEntry(file, refsList));
                    }
                }
            }
            applyExtractedRefsFilter();
            extractedRefsPathField.setText("");
            extractedRefsDetailModel.clear();
            possibleCvesModel.clear();
            if (report.has("possible_cves")) {
                JsonArray pc = report.getAsJsonArray("possible_cves");
                if (pc != null) {
                    for (JsonElement el : pc) {
                        if (el.isJsonPrimitive()) possibleCvesModel.addElement(el.getAsString());
                    }
                }
            }
            if (possibleCvesModel.isEmpty() && verdict != null && verdict.has("hunt_queries")) {
                JsonArray hq = verdict.getAsJsonArray("hunt_queries");
                if (hq != null) {
                    for (JsonElement el : hq) {
                        if (el.isJsonPrimitive()) possibleCvesModel.addElement(el.getAsString());
                    }
                }
            }
            checklistModel.setRowCount(0);
            if (report.has("checklist_findings")) {
                JsonArray cf = report.getAsJsonArray("checklist_findings");
                if (cf != null) {
                    for (JsonElement el : cf) {
                        if (el.isJsonObject()) {
                            JsonObject row = el.getAsJsonObject();
                            checklistModel.addRow(new Object[] {
                                str(row.get("file")),
                                str(row.get("pattern")),
                                str(row.get("snippet")),
                                row.has("line") ? row.get("line").getAsInt() : ""
                            });
                        }
                    }
                }
            }
            checklistFilterField.setText("");
            applyChecklistFilter();
            attackGraphChainsModel.setRowCount(0);
            sendableUrlsModel.setRowCount(0);
            liveSlots.clear();
            liveSlotsListModel.clear();
            liveSlotsSelectedIndex = -1;
            if (report.has("attack_graph")) {
                JsonObject ag = report.getAsJsonObject("attack_graph");
                if (ag != null) {
                    if (ag.has("chains")) {
                        JsonArray chains = ag.getAsJsonArray("chains");
                        if (chains != null) {
                            for (JsonElement el : chains) {
                                if (el.isJsonObject()) {
                                    JsonObject row = el.getAsJsonObject();
                                    String matchedPaths = "";
                                    if (row.has("matched_paths") && row.get("matched_paths").isJsonArray()) {
                                        JsonArray mp = row.getAsJsonArray("matched_paths");
                                        StringBuilder sb = new StringBuilder();
                                        for (JsonElement pe : mp) {
                                            if (pe.isJsonPrimitive()) {
                                                if (sb.length() > 0) sb.append("\n");
                                                sb.append(pe.getAsString());
                                            }
                                        }
                                        matchedPaths = sb.toString();
                                    }
                                    attackGraphChainsModel.addRow(new Object[] {
                                        str(row.get("missing_role")),
                                        str(row.get("suggested_surface")),
                                        str(row.get("hunt_targets")),
                                        str(row.get("reason")),
                                        matchedPaths
                                    });
                                }
                            }
                        }
                    }
                    if (ag.has("sendable_urls")) {
                        JsonArray urls = ag.getAsJsonArray("sendable_urls");
                        if (urls != null) {
                            int phase = 1;
                            for (JsonElement el : urls) {
                                if (el.isJsonObject()) {
                                    JsonObject row = el.getAsJsonObject();
                                    String url = str(row.get("url"));
                                    String source = str(row.get("source"));
                                    String label = str(row.get("label"));
                                    sendableUrlsModel.addRow(new Object[] { url, source, label });
                                    if (url != null && (url.startsWith("http://") || url.startsWith("https://"))) {
                                        LiveManipulationSlot slot = new LiveManipulationSlot(url, source, label);
                                        try {
                                            HttpRequest req = HttpRequest.httpRequestFromUrl(url);
                                            slot.requestText = req != null ? req.toString() : "GET " + url + " HTTP/1.1\r\nHost: " + url.replaceFirst("^https?://([^/]+).*", "$1") + "\r\n\r\n";
                                        } catch (Exception ex) {
                                            slot.requestText = "GET " + url + " HTTP/1.1\r\nHost: " + url.replaceFirst("^https?://([^/]+).*", "$1") + "\r\n\r\n";
                                        }
                                        liveSlots.add(slot);
                                        liveSlotsListModel.addElement("Phase " + phase + ": " + (label != null && !label.isEmpty() ? label : url));
                                        phase++;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if (liveSlotsSelectedIndex >= 0 && liveSlotsSelectedIndex < liveSlots.size()) {
                LiveManipulationSlot s = liveSlots.get(liveSlotsSelectedIndex);
                liveRequestArea.setText(s.requestText != null ? s.requestText : "");
                liveResponseArea.setText(s.responseText != null ? s.responseText : "");
            }
            addFindingsToTarget(report);
        } catch (Exception e) {
            logging.logToError("Unveil report parse error: " + e.getMessage());
            summaryArea.setText("Report received but parsing failed.\n\nSee Raw JSON tab.\n\n" + e.getMessage());
        }
    }

    private void addFindingsToTarget(JsonObject report) {
        try {
            JsonObject metadata = report.has("metadata") ? report.getAsJsonObject("metadata") : null;
            String target = metadata != null && metadata.has("target") ? metadata.get("target").getAsString() : null;
            if (target == null || target.isEmpty()) return;
            String baseUrl = pathToFileUrl(new File(target).getAbsolutePath());
            JsonObject verdict = report.has("verdict") ? report.getAsJsonObject("verdict") : null;
            String band = verdict != null && verdict.has("exploitability_band") ? str(verdict.get("exploitability_band")) : "UNKNOWN";
            int chainCount = 0;
            if (report.has("attack_graph")) {
                JsonObject ag = report.getAsJsonObject("attack_graph");
                if (ag != null && ag.has("chains")) {
                    JsonArray chains = ag.getAsJsonArray("chains");
                    if (chains != null) chainCount = chains.size();
                }
            }
            JsonArray checklist = report.has("checklist_findings") ? report.getAsJsonArray("checklist_findings") : null;
            int checklistCount = checklist != null ? checklist.size() : 0;
            StringBuilder detail = new StringBuilder();
            detail.append("Exploitability band: ").append(band);
            if (chainCount > 0) detail.append("; attack graph chains: ").append(chainCount);
            if (checklistCount > 0) detail.append("; checklist findings: ").append(checklistCount);
            detail.append(". See Unveil tab for full report.");
            AuditIssueSeverity severity = severityFromBand(band);
            AuditIssue summaryIssue = AuditIssue.auditIssue(
                "Unveil scan result",
                detail.toString(),
                "Review attack surfaces and checklist in the Unveil extension tab.",
                baseUrl,
                severity,
                AuditIssueConfidence.CERTAIN,
                "Unveil static analysis of application/binary.",
                "Address findings in the Unveil report.",
                severity,
                Collections.emptyList()
            );
            api.siteMap().add(summaryIssue);
            final int maxChecklistInTarget = 30;
            if (checklist != null) {
                for (int i = 0; i < Math.min(checklist.size(), maxChecklistInTarget); i++) {
                    JsonElement el = checklist.get(i);
                    if (!el.isJsonObject()) continue;
                    JsonObject c = el.getAsJsonObject();
                    String file = str(c.get("file"));
                    String pattern = str(c.get("pattern"));
                    String snippet = str(c.get("snippet"));
                    if (file.isEmpty()) continue;
                    String fileUrl = pathToFileUrl(new File(file).getAbsolutePath());
                    AuditIssueSeverity sev = pattern.contains("password") || pattern.contains("secret") || pattern.contains("key") ? AuditIssueSeverity.HIGH : AuditIssueSeverity.MEDIUM;
                    AuditIssue issue = AuditIssue.auditIssue(
                        "Unveil: " + (pattern.isEmpty() ? "checklist" : pattern),
                        snippet.isEmpty() ? "Potential secret or checklist item in " + file : snippet,
                        "Remove or externalize secrets; fix static analysis no-nos.",
                        fileUrl,
                        sev,
                        AuditIssueConfidence.TENTATIVE,
                        "Static analysis checklist / potential hardcoded credential.",
                        "See Unveil Checklist tab.",
                        sev,
                        Collections.emptyList()
                    );
                    api.siteMap().add(issue);
                }
            }
        } catch (Exception e) {
            logging.logToError("Unveil add to Target failed: " + e.getMessage());
        }
    }

    private static AuditIssueSeverity severityFromBand(String band) {
        if (band == null) return AuditIssueSeverity.MEDIUM;
        switch (band.toUpperCase()) {
            case "HIGH": return AuditIssueSeverity.HIGH;
            case "MEDIUM": return AuditIssueSeverity.MEDIUM;
            case "LOW": return AuditIssueSeverity.LOW;
            default: return AuditIssueSeverity.MEDIUM;
        }
    }

    private void sendSelectedToRepeater() {
        int[] rows = sendableUrlsTable.getSelectedRows();
        List<String> urls = new ArrayList<>();
        if (rows != null && rows.length > 0) {
            for (int viewRow : rows) {
                int modelRow = sendableUrlsTable.convertRowIndexToModel(viewRow);
                Object urlObj = sendableUrlsModel.getValueAt(modelRow, 0);
                Object labelObj = sendableUrlsModel.getValueAt(modelRow, 2);
                if (urlObj != null) {
                    String u = urlObj.toString().trim();
                    if (u.startsWith("http://") || u.startsWith("https://")) urls.add(u);
                }
            }
        } else {
            for (int i = 0; i < sendableUrlsModel.getRowCount(); i++) {
                Object urlObj = sendableUrlsModel.getValueAt(i, 0);
                if (urlObj != null) {
                    String u = urlObj.toString().trim();
                    if (u.startsWith("http://") || u.startsWith("https://")) urls.add(u);
                }
            }
        }
        if (urls.isEmpty()) {
            statusLabel.setText("No http(s) URLs to send.");
            return;
        }
        Repeater repeater = api.repeater();
        int sent = 0;
        for (int i = 0; i < urls.size(); i++) {
            String url = urls.get(i);
            try {
                HttpRequest request = HttpRequest.httpRequestFromUrl(url);
                String tabName = "Unveil " + (i + 1);
                repeater.sendToRepeater(request, tabName);
                sent++;
            } catch (Exception e) {
                logging.logToError("Send to Repeater failed for " + url + ": " + e.getMessage());
            }
        }
        statusLabel.setText("Sent " + sent + " request(s) to Repeater.");
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

    private void viewSelectedHtmlInPanel() {
        String path = discoveredHtmlList.getSelectedValue();
        if (path == null || path.isEmpty()) {
            statusLabel.setText("Select an HTML file first.");
            return;
        }
        File f = new File(path);
        if (!f.exists() || !f.isFile()) {
            statusLabel.setText("File not found.");
            return;
        }
        try {
            String html = new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
            JEditorPane editor = new JEditorPane();
            editor.setContentType("text/html");
            editor.setEditorKit(new HTMLEditorKit());
            editor.setBackground(Color.WHITE);
            editor.setForeground(Color.BLACK);
            editor.setText(html);
            editor.setEditable(false);
            editor.setCaretPosition(0);
            JScrollPane scroll = new JScrollPane(editor);
            scroll.getViewport().setBackground(Color.WHITE);
            scroll.setPreferredSize(new Dimension(800, 600));
            JDialog dialog = new JDialog((Frame) null, "HTML: " + f.getName(), false);
            dialog.getContentPane().add(scroll, BorderLayout.CENTER);
            dialog.pack();
            dialog.setLocationRelativeTo(mainPanel);
            dialog.setVisible(true);
            statusLabel.setText("Rendering in panel.");
        } catch (Exception ex) {
            statusLabel.setText("Could not load HTML.");
            logging.logToError("View HTML in panel failed: " + ex.getMessage());
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

    private void applyExtractedRefsFilter() {
        String q = extractedRefsFilterField.getText();
        if (q == null) q = "";
        q = q.trim().toLowerCase();
        extractedRefsFilteredIndices.clear();
        extractedRefsFileListModel.clear();
        for (int i = 0; i < extractedRefsData.size(); i++) {
            ExtractedRefEntry e = extractedRefsData.get(i);
            boolean match = q.isEmpty()
                || (e.file != null && e.file.toLowerCase().contains(q));
            if (!match && e.refs != null) {
                for (String ref : e.refs) {
                    if (ref != null && ref.toLowerCase().contains(q)) { match = true; break; }
                }
            }
            if (match) {
                extractedRefsFilteredIndices.add(i);
                String display = e.shortDisplay() + " (" + e.refs.size() + " refs)";
                extractedRefsFileListModel.addElement(display);
            }
        }
    }

    private void copySelectedFileRefs() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < extractedRefsDetailModel.getSize(); i++) {
            Object v = extractedRefsDetailModel.getElementAt(i);
            if (v != null) sb.append(v.toString()).append("\n");
        }
        if (sb.length() > 0) {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(sb.toString().trim()), null);
            statusLabel.setText("Refs copied.");
        }
    }

    private void applyChecklistFilter() {
        TableRowSorter<?> sorter = (TableRowSorter<?>) checklistTable.getRowSorter();
        if (sorter == null) return;
        String q = checklistFilterField.getText();
        if (q == null) q = "";
        q = q.trim();
        if (q.isEmpty()) {
            sorter.setRowFilter(null);
        } else {
            String search = "(?i)" + java.util.regex.Pattern.quote(q);
            sorter.setRowFilter(RowFilter.regexFilter(search, 0, 1, 2));
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

    private String detectProxyListener() {
        try {
            Object burpSuite = api.burpSuite();
            if (burpSuite == null) return "127.0.0.1:8080";
            java.lang.reflect.Method m = burpSuite.getClass().getMethod("exportProjectOptionsAsJson", String.class);
            if (m == null) return "127.0.0.1:8080";
            String json = (String) m.invoke(burpSuite, "proxy");
            if (json != null && !json.isEmpty()) {
                JsonObject root = JsonParser.parseString(json).getAsJsonObject();
                JsonObject proxy = root.has("proxy") ? root.getAsJsonObject("proxy") : null;
                if (proxy != null && proxy.has("request_listeners")) {
                    JsonArray listeners = proxy.getAsJsonArray("request_listeners");
                    if (listeners != null && listeners.size() > 0) {
                        JsonObject first = listeners.get(0).getAsJsonObject();
                        if (first.has("listener_port")) {
                            int port = first.get("listener_port").getAsInt();
                            String host = "127.0.0.1";
                            if (first.has("listen_mode")) {
                                String mode = first.get("listen_mode").getAsString();
                                if (mode != null && mode.contains("all_interfaces")) host = "0.0.0.0";
                            }
                            return host + ":" + port;
                        }
                    }
                }
            }
        } catch (Throwable t) {
            logging.logToError("Proxy config read: " + t.getMessage());
        }
        return "127.0.0.1:8080";
    }

    private void copyProxyEnv() {
        String hp = proxyHostPortField.getText();
        if (hp == null) hp = "";
        hp = hp.trim();
        if (hp.isEmpty()) hp = "127.0.0.1:8080";
        String url = "http://" + hp;
        String env = "HTTP_PROXY=" + url + "\nHTTPS_PROXY=" + url + "\nhttp_proxy=" + url + "\nhttps_proxy=" + url;
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(env), null);
        statusLabel.setText("Proxy env copied. Set in shell or thick client launcher.");
    }

    private void copyProxyUrl() {
        String hp = proxyHostPortField.getText();
        if (hp == null) hp = "";
        hp = hp.trim();
        if (hp.isEmpty()) hp = "127.0.0.1:8080";
        String url = "http://" + hp;
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(url), null);
        statusLabel.setText("Proxy URL copied.");
    }

    private void copyCaCertInstructions() {
        String instructions =
            "Burp CA certificate (for thick client TLS interception):\n\n"
            + "1. In Burp: Proxy → Options → Proxy Listeners → Select listener → Import / export CA certificate.\n"
            + "2. Export Certificate (DER or PEM). Save the file.\n"
            + "3. Install the certificate as trusted in your OS or app:\n"
            + "   - Windows: certutil -addstore Root <path> or double-click and install to Trusted Root CA.\n"
            + "   - macOS: Keychain Access → File → Import Items → add to System keychain, then set to \"Always Trust\".\n"
            + "   - Linux: copy to /usr/local/share/ca-certificates/ and run update-ca-certificates.\n"
            + "4. Point the thick client at Burp proxy (host:port above). Many apps use HTTP_PROXY/HTTPS_PROXY env vars.";
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(instructions), null);
        statusLabel.setText("CA cert instructions copied to clipboard.");
    }

    private void showProxySettingsHint() {
        JOptionPane.showMessageDialog(mainPanel,
            "To change the proxy listener:\n\n"
            + "• Burp menu: Settings (or Proxy → Options)\n"
            + "• Proxy → Options → Proxy Listeners\n\n"
            + "Update the host:port in the field above to match your listener.",
            "Proxy settings",
            JOptionPane.INFORMATION_MESSAGE);
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

    private void copyPossibleCves() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < possibleCvesModel.getSize(); i++) {
            if (i > 0) sb.append("\n");
            sb.append(possibleCvesModel.getElementAt(i));
        }
        if (sb.length() == 0) {
            statusLabel.setText("No CVE queries to copy.");
            return;
        }
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(sb.toString()), null);
        statusLabel.setText("Possible CVE queries copied.");
    }

    private void exportSarif() {
        String target = targetField.getText() == null ? "" : targetField.getText().trim();
        if (target.isEmpty()) {
            statusLabel.setText("Enter a path first.");
            return;
        }
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File("unveil-report.sarif.json"));
        if (chooser.showSaveDialog(mainPanel) != JFileChooser.APPROVE_OPTION) return;
        File f = chooser.getSelectedFile();
        if (f == null) return;
        statusLabel.setText("Exporting SARIF…");
        scanButton.setEnabled(false);
        String outPath = f.getAbsolutePath();
        executor.submit(() -> {
            try {
                List<String> args = new ArrayList<>();
                args.add(resolveUnveilPath());
                args.add("-C"); args.add(target);
                args.add("-q"); args.add("-xs"); args.add(outPath);
                if (optExtended.isSelected()) args.add("-e");
                if (optOffensive.isSelected()) args.add("-O");
                if (optForce.isSelected()) args.add("-f");
                if (optCve.isSelected()) args.add("--cve");
                ProcessBuilder pb = new ProcessBuilder(args);
                pb.redirectErrorStream(true);
                Process p = pb.start();
                p.getInputStream().readAllBytes();
                int exit = p.waitFor();
                SwingUtilities.invokeLater(() -> {
                    scanButton.setEnabled(true);
                    statusLabel.setText(exit == 0 ? "SARIF exported: " + outPath : "SARIF export failed (exit " + exit + ").");
                });
            } catch (Exception ex) {
                logging.logToError("SARIF export failed: " + ex.getMessage());
                SwingUtilities.invokeLater(() -> {
                    scanButton.setEnabled(true);
                    statusLabel.setText("Export failed.");
                });
            }
        });
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

    /** Line numbers for Raw JSON text area. */
    private static final class LineNumberView extends JComponent {
        private final JTextArea textArea;
        private static final int MARGIN = 4;

        LineNumberView(JTextArea textArea) {
            this.textArea = textArea;
            setFont(textArea.getFont());
            setBackground(UIManager.getColor("Panel.background"));
            if (getBackground() == null) setBackground(new Color(240, 240, 240));
        }

        @Override
        public Dimension getPreferredSize() {
            int lineCount = Math.max(1, textArea.getLineCount());
            FontMetrics fm = getFontMetrics(getFont());
            int lineHeight = fm.getHeight();
            int width = fm.stringWidth(String.valueOf(lineCount)) + MARGIN * 2;
            int height = lineCount * lineHeight;
            return new Dimension(width, height);
        }

        @Override
        protected void paintComponent(Graphics g) {
            super.paintComponent(g);
            FontMetrics fm = g.getFontMetrics();
            int lineHeight = fm.getHeight();
            int ascent = fm.getAscent();
            int lineCount = Math.max(1, textArea.getLineCount());
            int width = getWidth();
            g.setColor(getForeground() != null ? getForeground() : Color.GRAY);
            for (int i = 1; i <= lineCount; i++) {
                String num = String.valueOf(i);
                g.drawString(num, width - MARGIN - fm.stringWidth(num), (i - 1) * lineHeight + ascent);
            }
        }
    }

    /** Paints attack graph chains as Role → Surface → Targets (with matched paths). */
    private static final class AttackGraphPaintPanel extends JPanel {
        private static final int ROW_HEIGHT = 88;
        private static final int BOX_W = 140;
        private static final int BOX_H = 28;
        private static final int PAD = 12;
        private static final int ARROW_LEN = 24;

        private final DefaultTableModel model;
        private final boolean darkTheme;

        AttackGraphPaintPanel(DefaultTableModel model) {
            this.model = model;
            Color bg = UIManager.getColor("Panel.background");
            if (bg == null) bg = new Color(240, 240, 240);
            setBackground(bg);
            this.darkTheme = isDark(bg);
        }

        private static boolean isDark(Color c) {
            if (c == null) return false;
            double brightness = (c.getRed() * 0.299 + c.getGreen() * 0.587 + c.getBlue() * 0.114) / 255;
            return brightness < 0.45;
        }

        @Override
        public Dimension getPreferredSize() {
            int rows = model.getRowCount();
            int w = PAD * 2 + BOX_W * 3 + ARROW_LEN * 2 + 200;
            int h = rows == 0 ? ROW_HEIGHT : PAD * 2 + rows * ROW_HEIGHT;
            return new Dimension(w, h);
        }

        @Override
        protected void paintComponent(Graphics g) {
            super.paintComponent(g);
            Graphics2D g2 = (Graphics2D) g;
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            int rows = model.getRowCount();
            if (rows == 0) {
                g2.setColor(foregroundColor());
                g2.drawString("No chains. Run a scan to see the attack graph.", PAD, PAD + 20);
                return;
            }
            int y = PAD;
            for (int r = 0; r < rows; r++) {
                String role = objStr(model.getValueAt(r, 0));
                String surface = objStr(model.getValueAt(r, 1));
                String targets = objStr(model.getValueAt(r, 2));
                String reason = objStr(model.getValueAt(r, 3));
                String paths = objStr(model.getValueAt(r, 4));

                int x = PAD;
                drawBox(g2, x, y, BOX_W, BOX_H, role, true, darkTheme);
                x += BOX_W + ARROW_LEN;
                drawArrow(g2, x - ARROW_LEN, y + BOX_H / 2, x, y + BOX_H / 2, darkTheme);
                drawBox(g2, x, y, BOX_W, BOX_H, surface, true, darkTheme);
                x += BOX_W + ARROW_LEN;
                drawArrow(g2, x - ARROW_LEN, y + BOX_H / 2, x, y + BOX_H / 2, darkTheme);
                drawBox(g2, x, y, BOX_W + 180, BOX_H, truncate(targets, 35), false, darkTheme);

                if (reason != null && !reason.isEmpty()) {
                    g2.setFont(g2.getFont().deriveFont(10f));
                    g2.setColor(secondaryColor());
                    String shortReason = truncate(reason, 60);
                    g2.drawString(shortReason, PAD, y + BOX_H + 14);
                    g2.setFont(g2.getFont().deriveFont(12f));
                    g2.setColor(foregroundColor());
                }
                if (paths != null && !paths.isEmpty()) {
                    g2.setFont(g2.getFont().deriveFont(10f));
                    g2.setColor(secondaryColor());
                    String firstLine = paths.contains("\n") ? paths.substring(0, paths.indexOf('\n')) : paths;
                    g2.drawString("Paths: " + truncate(firstLine, 70), PAD, y + BOX_H + 28);
                    g2.setFont(g2.getFont().deriveFont(12f));
                    g2.setColor(foregroundColor());
                }
                y += ROW_HEIGHT;
            }
        }

        private Color foregroundColor() {
            if (darkTheme) {
                Color c = UIManager.getColor("Label.foreground");
                if (c != null && !isDark(c)) return c;
                return Color.WHITE;
            }
            Color c = UIManager.getColor("Label.foreground");
            return c != null ? c : Color.BLACK;
        }

        private Color secondaryColor() {
            if (darkTheme) return new Color(180, 180, 180);
            return getForeground().darker();
        }

        private static void drawBox(Graphics2D g2, int x, int y, int w, int h, String text, boolean bold, boolean darkTheme) {
            Color boxFill = darkTheme ? Color.BLACK : (UIManager.getColor("Panel.background") != null ? UIManager.getColor("Panel.background").darker() : new Color(220, 220, 220));
            g2.setColor(boxFill);
            g2.fillRoundRect(x, y, w, h, 6, 6);
            Color edge = darkTheme ? Color.WHITE : (UIManager.getColor("Label.foreground") != null ? UIManager.getColor("Label.foreground") : Color.BLACK);
            g2.setColor(edge);
            g2.drawRoundRect(x, y, w, h, 6, 6);
            if (text != null && !text.isEmpty()) {
                g2.setColor(edge);
                Font f = g2.getFont();
                if (bold) g2.setFont(f.deriveFont(Font.BOLD));
                FontMetrics fm = g2.getFontMetrics();
                int tw = fm.stringWidth(text);
                if (tw > w - 6) text = truncate(text, Math.max(1, (w - 6) / Math.max(1, fm.charWidth('m'))));
                g2.drawString(text, x + (w - fm.stringWidth(text)) / 2, y + h / 2 + fm.getAscent() / 2 - 2);
                g2.setFont(f);
            }
        }

        private static void drawArrow(Graphics2D g2, int x1, int y1, int x2, int y2, boolean darkTheme) {
            g2.setColor(darkTheme ? Color.WHITE : (UIManager.getColor("Label.foreground") != null ? UIManager.getColor("Label.foreground") : Color.BLACK));
            g2.drawLine(x1, y1, x2, y2);
            int dx = x2 - x1;
            int dy = y2 - y1;
            double len = Math.sqrt(dx * dx + dy * dy);
            if (len < 1) return;
            int ax = (int) (x2 - 8 * dx / len);
            int ay = (int) (y2 - 8 * dy / len);
            g2.drawLine(x2, y2, ax + (int)(6 * dy / len), ay - (int)(6 * dx / len));
            g2.drawLine(x2, y2, ax - (int)(6 * dy / len), ay + (int)(6 * dx / len));
        }

        private static String objStr(Object o) {
            return o == null ? "" : o.toString().trim();
        }

        private static String truncate(String s, int maxLen) {
            if (s == null) return "";
            if (s.length() <= maxLen) return s;
            return s.substring(0, Math.max(0, maxLen - 3)) + "...";
        }
    }

    public void extensionUnloaded() {
        executor.shutdown();
    }
}
