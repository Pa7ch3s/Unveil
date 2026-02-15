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
import java.net.InetSocketAddress;
import java.net.Proxy;
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
    private final JCheckBox optCveLookup;
    private final JCheckBox useDaemonCheck;
    private final JCheckBox optProxyBackend;
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
    private final JTextField chainabilityFilterField;
    private final JComboBox<String> chainabilityScopeFilter;
    private final JLabel chainabilitySummaryLabel;
    private final DefaultTableModel interestingStringsModel;
    private final JTable interestingStringsTable;
    private final JScrollPane interestingStringsScroll;
    private final JTextArea interestingStringsCustomFilterField;
    private final JPanel summaryCardsPanel;
    private final CardLayout summaryCardLayout;
    private final JPanel discoveryCardsPanel;
    private final CardLayout discoveryCardLayout;
    private final JPanel findingsCardsPanel;
    private final CardLayout findingsCardLayout;
    private final DefaultTableModel permissionFindingsModel;
    private final JTable permissionFindingsTable;
    private final JScrollPane permissionFindingsScroll;
    private final DefaultTableModel certFindingsModel;
    private final JTable certFindingsTable;
    private final JScrollPane certFindingsScroll;
    private final DefaultTableModel dotnetFindingsModel;
    private final JTable dotnetFindingsTable;
    private final JScrollPane dotnetFindingsScroll;
    private final DefaultTableModel cveLookupModel;
    private final JTable cveLookupTable;
    private final JScrollPane cveLookupScroll;
    private final DefaultTableModel instrumentationHintsModel;
    private final JTable instrumentationHintsTable;
    private final JScrollPane instrumentationHintsScroll;
    private final DefaultListModel<String> pathsToWatchModel = new DefaultListModel<>();
    private final JList<String> pathsToWatchList;
    private final JScrollPane pathsToWatchScroll;
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
    private final JCheckBox checklistTlsPinningOnlyCheck;
    private final DefaultTableModel attackGraphChainsModel;
    private final List<List<PoCPayloadEntry>> attackGraphPayloadsByRow = new ArrayList<>();
    private final DefaultTableModel sendableUrlsModel;
    private final JTable sendableUrlsTable;
    private final JScrollPane attackGraphScrollPane;
    private final JButton sendToRepeaterBtn;
    private final List<LiveManipulationSlot> liveSlots = new ArrayList<>();
    private final DefaultListModel<String> liveSlotsListModel = new DefaultListModel<>();
    private final JList<String> liveSlotsList;
    private final JTextArea liveRequestArea;
    private final JTextArea liveResponseArea;
    private int liveSlotsSelectedIndex = -1;
    private final DefaultTableModel thickClientFindingsModel;
    private final JTable thickClientFindingsTable;
    private final DefaultTableModel payloadLibraryModel;
    private final JTable payloadLibraryTable;
    private final JTextArea payloadDetailArea;
    private final JComboBox<String> payloadCategoryFilter;
    private final List<String> payloadLibraryPayloads = new ArrayList<>();
    private final List<String> payloadLibraryDescriptions = new ArrayList<>();
    private final List<Object[]> payloadLibraryFullData = new ArrayList<>();
    private final DefaultTableModel updateRefsModel;
    private final JTable updateRefsTable;
    private final DefaultTableModel credentialHintsModel;
    private final JTable credentialHintsTable;
    private final DefaultTableModel dbSummaryModel;
    private final JTable dbSummaryTable;
    private final DefaultListModel<String> importSummaryListModel = new DefaultListModel<>();
    private final JList<String> importSummaryList;
    private final DefaultTableModel packedEntropyModel;
    private final JTable packedEntropyTable;
    private final DefaultTableModel nonHttpRefsModel;
    private final JTable nonHttpRefsTable;
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

    private static final class PoCPayloadEntry {
        final String name;
        final String description;
        final String type;
        final String payload;
        final String reference;
        PoCPayloadEntry(String name, String description, String type, String payload, String reference) {
            this.name = name != null ? name : "";
            this.description = description != null ? description : "";
            this.type = type != null ? type : "";
            this.payload = payload != null ? payload : "";
            this.reference = reference != null ? reference : "";
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

        JLabel intro = new JLabel("Thick-client attack surface: path to app/binary, then Scan.");
        intro.setBorder(new EmptyBorder(0, 0, 8, 0));

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
        this.optCveLookup = new JCheckBox("CVE lookup (NVD)", false);
        optCveLookup.setToolTipText("Query NVD API for CVEs (set NVD_API_KEY for higher rate limit)");
        optionsPanel.add(optCveLookup);

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
        JButton copyLaunchCmdBtn = new JButton("Copy launch command");
        copyLaunchCmdBtn.setToolTipText("Copy proxy env and run command (open/start with target path) for one-command proxied launch");
        copyLaunchCmdBtn.addActionListener(e -> copyLaunchCommand());
        proxyCertPanel.add(copyLaunchCmdBtn);
        JButton copyCaCertInstructionsBtn = new JButton("Copy CA cert instructions");
        copyCaCertInstructionsBtn.setToolTipText("Copy steps to export and install Burp's CA certificate for TLS interception");
        copyCaCertInstructionsBtn.addActionListener(e -> copyCaCertInstructions());
        proxyCertPanel.add(copyCaCertInstructionsBtn);
        JButton openSettingsBtn = new JButton("Open Settings");
        openSettingsBtn.setToolTipText("Open Burp Settings (Proxy listener is under Tools → Proxy → Options)");
        openSettingsBtn.addActionListener(e -> showProxySettingsHint());
        proxyCertPanel.add(openSettingsBtn);
        this.optProxyBackend = new JCheckBox("Send backend traffic through proxy", false);
        optProxyBackend.setToolTipText("When enabled, daemon requests and CLI outbound traffic (e.g. CVE lookup) go through Burp proxy so they appear in Proxy history.");
        proxyCertPanel.add(optProxyBackend);
        JPanel proxyWrap = new JPanel(new BorderLayout(4, 4));
        proxyWrap.add(proxyCertPanel, BorderLayout.NORTH);
        JLabel nonHttpNote = new JLabel("Non-HTTP refs (ws://, wss://, raw ports) are in the report; use Burp for WebSocket/proxy where applicable.");
        nonHttpNote.setForeground(Color.GRAY);
        nonHttpNote.setFont(nonHttpNote.getFont().deriveFont(11f));
        proxyWrap.add(nonHttpNote, BorderLayout.SOUTH);

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
        JButton exportFindingsCsvBtn = new JButton("Export findings CSV…");
        exportFindingsCsvBtn.setToolTipText("Export unified findings table (from current report) to CSV");
        exportFindingsCsvBtn.addActionListener(e -> exportFindings(false));
        resultsToolbar.add(exportFindingsCsvBtn);
        JButton exportFindingsMdBtn = new JButton("Export findings MD…");
        exportFindingsMdBtn.setToolTipText("Export unified findings table (from current report) to Markdown");
        exportFindingsMdBtn.addActionListener(e -> exportFindings(true));
        resultsToolbar.add(exportFindingsMdBtn);
        resultsToolbar.setVisible(false);

        this.resultsTabs = new JTabbedPane();
        this.summaryArea = new JTextArea(8, 60);
        summaryArea.setEditable(false);
        summaryArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        summaryArea.setLineWrap(true);
        summaryArea.setWrapStyleWord(true);
        summaryArea.setText(EMPTY_MESSAGE);
        // CVE hunt queries in Summary (no separate tab)
        this.possibleCvesList = new JList<>(possibleCvesModel);
        possibleCvesList.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JPanel cveQueriesToolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        JLabel cveQueriesLabel = new JLabel("CVE hunt queries (paste into NVD/CVE database for CVE IDs):");
        cveQueriesLabel.setToolTipText("These are search terms, not CVE numbers. Use at nvd.nist.gov or similar to find CVEs.");
        cveQueriesToolbar.add(cveQueriesLabel);
        JButton copyCvesBtn = new JButton("Copy all");
        copyCvesBtn.addActionListener(e -> copyPossibleCves());
        cveQueriesToolbar.add(copyCvesBtn);
        JPanel cveQueriesPanel = new JPanel(new BorderLayout(4, 4));
        cveQueriesPanel.add(cveQueriesToolbar, BorderLayout.NORTH);
        cveQueriesPanel.add(new JScrollPane(possibleCvesList), BorderLayout.CENTER);
        JSplitPane summarySplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(summaryArea), cveQueriesPanel);
        summarySplit.setResizeWeight(0.6);
        summarySplit.setOneTouchExpandable(true);
        this.summaryCardLayout = new CardLayout();
        this.summaryCardsPanel = new JPanel(summaryCardLayout);
        summaryCardsPanel.add(summarySplit, "Main");
        JComboBox<String> summaryTypeCombo = new JComboBox<>(new String[] { "Main", "DB summary", "Import summary", "Packed/entropy" });
        summaryTypeCombo.setToolTipText("Switch summary view");
        summaryTypeCombo.addActionListener(e -> summaryCardLayout.show(summaryCardsPanel, (String) summaryTypeCombo.getSelectedItem()));
        JPanel summaryWrapper = new JPanel(new BorderLayout(4, 4));
        summaryWrapper.add(summaryTypeCombo, BorderLayout.NORTH);
        summaryWrapper.add(summaryCardsPanel, BorderLayout.CENTER);
        resultsTabs.addTab("Summary", summaryWrapper);

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

        // Chainability — file→ref links; filter, summary, tooltips, actions for testers
        this.chainabilityModel = new DefaultTableModel(new String[] { "File", "Ref", "In scope", "Matched type", "Confidence" }, 0);
        this.chainabilityTable = new JTable(chainabilityModel);
        chainabilityTable.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        chainabilityTable.setAutoCreateRowSorter(true);
        chainabilityTable.setRowHeight(Math.max(20, chainabilityTable.getRowHeight()));
        chainabilityTable.setDefaultRenderer(String.class, new javax.swing.table.DefaultTableCellRenderer() {
            @Override
            public java.awt.Component getTableCellRendererComponent(JTable t, Object value, boolean selected, boolean focus, int row, int col) {
                java.awt.Component c = super.getTableCellRendererComponent(t, value, selected, focus, row, col);
                if (col == 2 && value != null) {
                    String v = value.toString();
                    if ("Yes".equals(v)) {
                        c.setForeground(selected ? c.getForeground() : new Color(40, 160, 80));
                    } else {
                        c.setForeground(selected ? c.getForeground() : new Color(120, 120, 120));
                    }
                }
                return c;
            }
        });
        chainabilityTable.addMouseMotionListener(new java.awt.event.MouseMotionAdapter() {
            @Override
            public void mouseMoved(java.awt.event.MouseEvent e) {
                int col = chainabilityTable.columnAtPoint(e.getPoint());
                int row = chainabilityTable.rowAtPoint(e.getPoint());
                if (row >= 0 && col >= 0) {
                    Object v = chainabilityTable.getValueAt(row, col);
                    chainabilityTable.setToolTipText(v != null ? v.toString() : null);
                } else {
                    chainabilityTable.setToolTipText(null);
                }
            }
        });
        JPopupMenu chainabilityMenu = new JPopupMenu();
        JMenuItem chainabilityCopyPathItem = new JMenuItem("Copy path (File)");
        chainabilityCopyPathItem.addActionListener(e -> copyChainabilityCell(0));
        chainabilityMenu.add(chainabilityCopyPathItem);
        JMenuItem copyRefItem = new JMenuItem("Copy ref");
        copyRefItem.addActionListener(e -> copyChainabilityCell(1));
        chainabilityMenu.add(copyRefItem);
        JMenuItem openUrlItem = new JMenuItem("Open ref as URL");
        openUrlItem.addActionListener(e -> openChainabilityRefAsUrl());
        chainabilityMenu.add(openUrlItem);
        JMenuItem openFileItem = new JMenuItem("Open file (if exists)");
        openFileItem.addActionListener(e -> openChainabilityFile());
        chainabilityMenu.add(openFileItem);
        chainabilityTable.setComponentPopupMenu(chainabilityMenu);
        JScrollPane chainabilityScroll = new JScrollPane(chainabilityTable);
        chainabilityScroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        chainabilityScroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        chainabilityScroll.setBorder(new EmptyBorder(0, 0, 0, 0));
        JPanel chainabilityPanel = new JPanel(new BorderLayout(4, 4));
        chainabilityPanel.setBorder(new EmptyBorder(6, 6, 6, 6));
        JPanel chainabilityToolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        chainabilityToolbar.add(new JLabel("File → Ref (thick-client links)."));
        this.chainabilityFilterField = new JTextField(16);
        chainabilityFilterField.setToolTipText("Filter by path or ref text");
        chainabilityFilterField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override public void insertUpdate(javax.swing.event.DocumentEvent e) { applyChainabilityFilter(); }
            @Override public void removeUpdate(javax.swing.event.DocumentEvent e) { applyChainabilityFilter(); }
            @Override public void changedUpdate(javax.swing.event.DocumentEvent e) { applyChainabilityFilter(); }
        });
        chainabilityToolbar.add(new JLabel("Filter:"));
        chainabilityToolbar.add(chainabilityFilterField);
        this.chainabilityScopeFilter = new JComboBox<>(new String[] { "All", "In scope", "Out of scope" });
        chainabilityScopeFilter.setToolTipText("Filter by scope");
        chainabilityScopeFilter.addActionListener(e -> applyChainabilityFilter());
        chainabilityToolbar.add(chainabilityScopeFilter);
        this.chainabilitySummaryLabel = new JLabel("—");
        chainabilitySummaryLabel.setForeground(Color.GRAY);
        chainabilitySummaryLabel.setFont(chainabilitySummaryLabel.getFont().deriveFont(11f));
        chainabilityToolbar.add(chainabilitySummaryLabel);
        chainabilityPanel.add(chainabilityToolbar, BorderLayout.NORTH);
        chainabilityPanel.add(chainabilityScroll, BorderLayout.CENTER);
        resultsTabs.addTab("Chainability", chainabilityPanel);

        // Interesting strings (File | String) + custom strings filter
        this.interestingStringsModel = new DefaultTableModel(new String[] { "File", "String" }, 0);
        this.interestingStringsTable = new JTable(interestingStringsModel);
        interestingStringsTable.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        interestingStringsTable.setAutoCreateRowSorter(true);
        interestingStringsTable.setRowHeight(Math.max(20, interestingStringsTable.getRowHeight()));
        this.interestingStringsScroll = new JScrollPane(interestingStringsTable);
        interestingStringsScroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        interestingStringsScroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        this.interestingStringsCustomFilterField = new JTextArea(3, 40);
        interestingStringsCustomFilterField.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        interestingStringsCustomFilterField.setLineWrap(true);
        interestingStringsCustomFilterField.setToolTipText("One string per line. Show only rows whose String column contains any of these (case-insensitive). Leave empty to show all.");
        interestingStringsCustomFilterField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override public void insertUpdate(javax.swing.event.DocumentEvent e) { applyInterestingStringsCustomFilter(); }
            @Override public void removeUpdate(javax.swing.event.DocumentEvent e) { applyInterestingStringsCustomFilter(); }
            @Override public void changedUpdate(javax.swing.event.DocumentEvent e) { applyInterestingStringsCustomFilter(); }
        });
        JPanel interestingStringsNorth = new JPanel(new BorderLayout(4, 4));
        interestingStringsNorth.add(new JLabel("Custom strings (one per line) — show only strings containing any of these:"), BorderLayout.NORTH);
        interestingStringsNorth.add(new JScrollPane(interestingStringsCustomFilterField), BorderLayout.CENTER);
        JPanel interestingStringsPanel = new JPanel(new BorderLayout(4, 4));
        interestingStringsPanel.setBorder(new EmptyBorder(6, 6, 6, 6));
        interestingStringsPanel.add(interestingStringsNorth, BorderLayout.NORTH);
        interestingStringsPanel.add(interestingStringsScroll, BorderLayout.CENTER);

        // Permission findings (Path | Finding | Detail)
        this.permissionFindingsModel = new DefaultTableModel(new String[] { "Path", "Finding", "Detail" }, 0);
        this.permissionFindingsTable = new JTable(permissionFindingsModel);
        permissionFindingsTable.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        permissionFindingsTable.setAutoCreateRowSorter(true);
        this.permissionFindingsScroll = new JScrollPane(permissionFindingsTable);
        permissionFindingsScroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        permissionFindingsScroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        JPanel permissionFindingsPanel = new JPanel(new BorderLayout(4, 4));
        permissionFindingsPanel.setBorder(new EmptyBorder(6, 6, 6, 6));
        permissionFindingsPanel.add(permissionFindingsScroll, BorderLayout.CENTER);

        // Cert findings (Path | Subject | Expired | Self-signed)
        this.certFindingsModel = new DefaultTableModel(new String[] { "Path", "Subject", "Expired", "Self-signed" }, 0);
        this.certFindingsTable = new JTable(certFindingsModel);
        certFindingsTable.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        certFindingsTable.setAutoCreateRowSorter(true);
        this.certFindingsScroll = new JScrollPane(certFindingsTable);
        certFindingsScroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        certFindingsScroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        JPanel certFindingsPanel = new JPanel(new BorderLayout(4, 4));
        certFindingsPanel.setBorder(new EmptyBorder(6, 6, 6, 6));
        certFindingsPanel.add(certFindingsScroll, BorderLayout.CENTER);

        // Dotnet findings (Path | Assembly | Version | Serialization ref | Hints)
        this.dotnetFindingsModel = new DefaultTableModel(
            new String[] { "Path", "Assembly", "Version", "Serialization ref", "Hints" }, 0);
        this.dotnetFindingsTable = new JTable(dotnetFindingsModel);
        dotnetFindingsTable.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        dotnetFindingsTable.setAutoCreateRowSorter(true);
        this.dotnetFindingsScroll = new JScrollPane(dotnetFindingsTable);
        dotnetFindingsScroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        dotnetFindingsScroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        JPanel dotnetFindingsPanel = new JPanel(new BorderLayout(4, 4));
        dotnetFindingsPanel.setBorder(new EmptyBorder(6, 6, 6, 6));
        dotnetFindingsPanel.add(dotnetFindingsScroll, BorderLayout.CENTER);

        // CVE lookup (Query | CVE ID | Score | Published | Summary)
        this.cveLookupModel = new DefaultTableModel(
            new String[] { "Query", "CVE ID", "Score", "Published", "Summary" }, 0);
        this.cveLookupTable = new JTable(cveLookupModel);
        cveLookupTable.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        cveLookupTable.setAutoCreateRowSorter(true);
        cveLookupTable.setRowHeight(Math.max(20, cveLookupTable.getRowHeight()));
        JPopupMenu cveLookupMenu = new JPopupMenu();
        JMenuItem openCveLinkItem = new JMenuItem("Open NVD link");
        openCveLinkItem.addActionListener(e -> {
            int row = cveLookupTable.getSelectedRow();
            if (row >= 0) {
                int modelRow = cveLookupTable.convertRowIndexToModel(row);
                Object idObj = cveLookupModel.getValueAt(modelRow, 1);
                if (idObj != null && !idObj.toString().isEmpty()) {
                    String url = "https://nvd.nist.gov/vuln/detail/" + idObj.toString();
                    try { Desktop.getDesktop().browse(new java.net.URI(url)); } catch (Exception ex) { /* ignore */ }
                }
            }
        });
        cveLookupMenu.add(openCveLinkItem);
        cveLookupTable.setComponentPopupMenu(cveLookupMenu);
        this.cveLookupScroll = new JScrollPane(cveLookupTable);
        cveLookupScroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        cveLookupScroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        JPanel cveLookupPanel = new JPanel(new BorderLayout(4, 4));
        cveLookupPanel.setBorder(new EmptyBorder(6, 6, 6, 6));
        cveLookupPanel.add(cveLookupScroll, BorderLayout.CENTER);

        // Instrumentation hints (Surface | Component | Suggestion | Frida/script hint)
        this.instrumentationHintsModel = new DefaultTableModel(
            new String[] { "Surface", "Component", "Suggestion", "Frida/script hint" }, 0);
        this.instrumentationHintsTable = new JTable(instrumentationHintsModel);
        instrumentationHintsTable.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        instrumentationHintsTable.setAutoCreateRowSorter(true);
        instrumentationHintsTable.setRowHeight(Math.max(20, instrumentationHintsTable.getRowHeight()));
        this.instrumentationHintsScroll = new JScrollPane(instrumentationHintsTable);
        JPanel instrumentationHintsPanel = new JPanel(new BorderLayout(4, 4));
        instrumentationHintsPanel.setBorder(new EmptyBorder(6, 6, 6, 6));
        instrumentationHintsPanel.add(instrumentationHintsScroll, BorderLayout.CENTER);
        resultsTabs.addTab("Instrumentation hints", instrumentationHintsPanel);

        // Paths to watch (process monitor correlation)
        this.pathsToWatchList = new JList<>(pathsToWatchModel);
        pathsToWatchList.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        this.pathsToWatchScroll = new JScrollPane(pathsToWatchList);
        JPanel pathsToWatchPanel = new JPanel(new BorderLayout(4, 4));
        pathsToWatchPanel.setBorder(new EmptyBorder(6, 6, 6, 6));
        JPanel pathsToWatchNorth = new JPanel(new BorderLayout(4, 4));
        JLabel pathsToWatchNote = new JLabel("Run ProcMon (Windows) or fs_usage (macOS) and filter for these paths to correlate static findings with runtime behavior.");
        pathsToWatchNote.setForeground(Color.GRAY);
        pathsToWatchNote.setFont(pathsToWatchNote.getFont().deriveFont(11f));
        pathsToWatchNorth.add(pathsToWatchNote, BorderLayout.NORTH);
        JPanel pathsToWatchBtnRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        JButton pathsToWatchCopyBtn = new JButton("Copy all paths");
        pathsToWatchCopyBtn.addActionListener(e -> {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < pathsToWatchModel.getSize(); i++) {
                if (sb.length() > 0) sb.append("\n");
                sb.append(pathsToWatchModel.getElementAt(i));
            }
            if (sb.length() > 0)
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(sb.toString()), null);
            statusLabel.setText("Paths copied.");
        });
        pathsToWatchBtnRow.add(pathsToWatchCopyBtn);
        JButton copyProcMonBtn = new JButton("Copy for ProcMon");
        copyProcMonBtn.setToolTipText("Copy paths as ProcMon include filter (Path contains; paste one per line)");
        copyProcMonBtn.addActionListener(e -> copyPathsToWatchForProcMon());
        pathsToWatchBtnRow.add(copyProcMonBtn);
        JButton copyFsUsageBtn = new JButton("Copy fs_usage one-liner");
        copyFsUsageBtn.setToolTipText("Copy macOS fs_usage -f path command (first 50 paths)");
        copyFsUsageBtn.addActionListener(e -> copyPathsToWatchFsUsage());
        pathsToWatchBtnRow.add(copyFsUsageBtn);
        pathsToWatchNorth.add(pathsToWatchBtnRow, BorderLayout.SOUTH);
        pathsToWatchPanel.add(pathsToWatchNorth, BorderLayout.NORTH);
        pathsToWatchPanel.add(pathsToWatchScroll, BorderLayout.CENTER);

        // Update refs (update/installer URLs and paths from scan)
        this.updateRefsModel = new DefaultTableModel(new String[] { "File", "Ref", "Tags" }, 0);
        this.updateRefsTable = new JTable(updateRefsModel);
        updateRefsTable.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        updateRefsTable.setAutoCreateRowSorter(true);
        JPanel updateRefsPanel = new JPanel(new BorderLayout(4, 4));
        JLabel updateRefsNote = new JLabel("Refs tagged as possible update URL, installer path, or update over HTTP. Prioritize for abuse testing.");
        updateRefsNote.setForeground(Color.GRAY);
        updateRefsPanel.add(updateRefsNote, BorderLayout.NORTH);
        updateRefsPanel.add(new JScrollPane(updateRefsTable), BorderLayout.CENTER);

        // Credential/storage hints (Keychain, CredMan, DPAPI, safeStorage)
        this.credentialHintsModel = new DefaultTableModel(new String[] { "Hint", "Path", "Suggestion" }, 0);
        this.credentialHintsTable = new JTable(credentialHintsModel);
        credentialHintsTable.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        credentialHintsTable.setAutoCreateRowSorter(true);
        JPanel credentialHintsPanel = new JPanel(new BorderLayout(4, 4));
        credentialHintsPanel.add(new JLabel("Credential and storage hints inferred from imports/config (Keychain, CredMan, DPAPI, Electron safeStorage)."), BorderLayout.NORTH);
        credentialHintsPanel.add(new JScrollPane(credentialHintsTable), BorderLayout.CENTER);

        // DB summary (.db/.sqlite table names and possible credentials hint)
        this.dbSummaryModel = new DefaultTableModel(new String[] { "Path", "Tables", "Possible credentials hint" }, 0);
        this.dbSummaryTable = new JTable(dbSummaryModel);
        dbSummaryTable.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        dbSummaryTable.setAutoCreateRowSorter(true);
        JPanel dbSummaryPanel = new JPanel(new BorderLayout(4, 4));
        dbSummaryPanel.add(new JLabel("Discovered .db/.sqlite: table names and hint if name suggests credentials."), BorderLayout.NORTH);
        dbSummaryPanel.add(new JScrollPane(dbSummaryTable), BorderLayout.CENTER);
        summaryCardsPanel.add(dbSummaryPanel, "DB summary");

        // Import summary (unique DLLs/symbols — "does it load something weird?")
        this.importSummaryList = new JList<>(importSummaryListModel);
        importSummaryList.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JPanel importSummaryPanel = new JPanel(new BorderLayout(4, 4));
        importSummaryPanel.add(new JLabel("Unique imported libraries/symbols from binaries (answer: does it load something weird?)."), BorderLayout.NORTH);
        importSummaryPanel.add(new JScrollPane(importSummaryList), BorderLayout.CENTER);
        summaryCardsPanel.add(importSummaryPanel, "Import summary");

        // Packed/entropy (high-entropy files — what to unpack or skip)
        this.packedEntropyModel = new DefaultTableModel(new String[] { "Path", "Entropy" }, 0);
        this.packedEntropyTable = new JTable(packedEntropyModel);
        packedEntropyTable.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        packedEntropyTable.setAutoCreateRowSorter(true);
        JPanel packedEntropyPanel = new JPanel(new BorderLayout(4, 4));
        packedEntropyPanel.add(new JLabel("High-entropy files (likely packed/compressed); consider unpacking or skipping for static analysis."), BorderLayout.NORTH);
        packedEntropyPanel.add(new JScrollPane(packedEntropyTable), BorderLayout.CENTER);
        summaryCardsPanel.add(packedEntropyPanel, "Packed/entropy");

        // Non-HTTP refs (ws://, wss://, raw ports — use Burp for WebSocket)
        this.nonHttpRefsModel = new DefaultTableModel(new String[] { "File", "Ref", "Tag" }, 0);
        this.nonHttpRefsTable = new JTable(nonHttpRefsModel);
        nonHttpRefsTable.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        nonHttpRefsTable.setAutoCreateRowSorter(true);
        JPanel nonHttpRefsPanel = new JPanel(new BorderLayout(4, 4));
        nonHttpRefsPanel.add(new JLabel("Non-HTTP refs (ws://, wss://, raw ports). Use Burp listener + proxy for WebSocket/non-HTTP where applicable."), BorderLayout.NORTH);
        nonHttpRefsPanel.add(new JScrollPane(nonHttpRefsTable), BorderLayout.CENTER);

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

        // Discovery tab: single tab with dropdown (Discovered HTML | Assets | Update refs | Credential hints | Non-HTTP refs | Extracted refs | Paths to watch | Interesting strings)
        this.discoveryCardLayout = new CardLayout();
        this.discoveryCardsPanel = new JPanel(discoveryCardLayout);
        discoveryCardsPanel.add(discoveredHtmlPanel, "Discovered HTML");
        discoveryCardsPanel.add(discoveredAssetsPanel, "Discovered assets");
        discoveryCardsPanel.add(updateRefsPanel, "Update refs");
        discoveryCardsPanel.add(credentialHintsPanel, "Credential hints");
        discoveryCardsPanel.add(nonHttpRefsPanel, "Non-HTTP refs");
        discoveryCardsPanel.add(extractedRefsPanel, "Extracted refs");
        discoveryCardsPanel.add(pathsToWatchPanel, "Paths to watch");
        discoveryCardsPanel.add(interestingStringsPanel, "Interesting strings");
        String[] discoveryTypes = new String[] { "Discovered HTML", "Discovered assets", "Update refs", "Credential hints", "Non-HTTP refs", "Extracted refs", "Paths to watch", "Interesting strings" };
        JComboBox<String> discoveryTypeCombo = new JComboBox<>(discoveryTypes);
        discoveryTypeCombo.setToolTipText("Switch discovery view");
        discoveryTypeCombo.addActionListener(e -> discoveryCardLayout.show(discoveryCardsPanel, (String) discoveryTypeCombo.getSelectedItem()));
        JPanel discoveryWrapper = new JPanel(new BorderLayout(4, 4));
        discoveryWrapper.add(discoveryTypeCombo, BorderLayout.NORTH);
        discoveryWrapper.add(discoveryCardsPanel, BorderLayout.CENTER);
        resultsTabs.insertTab("Discovery", null, discoveryWrapper, null, 1);

        // Checklist (potential secrets / static analysis no-nos)
        this.checklistModel = new DefaultTableModel(new String[] { "File", "Pattern", "Snippet", "Line", "Severity" }, 0);
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
        this.checklistTlsPinningOnlyCheck = new JCheckBox("TLS/Pinning only", false);
        checklistTlsPinningOnlyCheck.setToolTipText("Show only cert_pinning, ats_insecure_exception, insecure_cleartext");
        checklistTlsPinningOnlyCheck.addActionListener(e -> applyChecklistFilter());
        checklistToolbar.add(checklistTlsPinningOnlyCheck);
        JButton copyEvidenceBtn = new JButton("Copy evidence");
        copyEvidenceBtn.setToolTipText("Copy Path and Snippet of selected row for report evidence");
        copyEvidenceBtn.addActionListener(e -> copyChecklistEvidence());
        checklistToolbar.add(copyEvidenceBtn);
        checklistPanel.add(checklistToolbar, BorderLayout.NORTH);
        checklistPanel.add(new JScrollPane(checklistTable), BorderLayout.CENTER);
        resultsTabs.addTab("Checklist", checklistPanel);

        // Attack graph: visual chains + sendable URLs (one-click Send to Repeater)
        this.attackGraphChainsModel = new DefaultTableModel(
            new String[] { "Vulnerable component", "Hunt targets", "Reason", "Matched paths", "Confidence" }, 0);
        this.sendableUrlsModel = new DefaultTableModel(new String[] { "URL", "Source", "Label" }, 0);
        this.sendableUrlsTable = new JTable(sendableUrlsModel);
        sendableUrlsTable.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        sendableUrlsTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        this.sendToRepeaterBtn = new JButton("Send selected to Repeater");
        sendToRepeaterBtn.setToolTipText("Create a Repeater tab for each selected http(s) URL (or all if none selected)");
        sendToRepeaterBtn.addActionListener(e -> sendSelectedToRepeater());
        JPanel attackGraphPanel = new JPanel(new BorderLayout(4, 4));
        attackGraphPanel.setBorder(new EmptyBorder(6, 6, 6, 6));
        JPanel chainsPanel = new JPanel(new BorderLayout());
        chainsPanel.setBorder(new EmptyBorder(4, 8, 8, 8));
        JPanel chainsHeader = new JPanel(new BorderLayout(4, 2));
        chainsHeader.add(new JLabel("Chains: vulnerable component → what to hunt (paths from scan). Use \"View PoC payloads\" to confirm exploitation."), BorderLayout.NORTH);
        JLabel chainsLegend = new JLabel("First column = component/surface found; use View PoC payloads per chain to confirm exploitation.");
        chainsLegend.setFont(chainsLegend.getFont().deriveFont(10f));
        chainsLegend.setForeground(Color.GRAY);
        chainsLegend.setToolTipText("Select a row and click View PoC payloads for preconfigured steps or payloads to confirm the attack surface.");
        chainsHeader.add(chainsLegend, BorderLayout.CENTER);
        JPanel chainsBtnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        JButton viewPocPayloadsBtn = new JButton("View PoC payloads");
        viewPocPayloadsBtn.setToolTipText("Show preconfigured payloads for the selected chain to confirm basic exploitation");
        viewPocPayloadsBtn.addActionListener(e -> showPocPayloadsForSelectedChain());
        chainsBtnPanel.add(viewPocPayloadsBtn);
        chainsHeader.add(chainsBtnPanel, BorderLayout.SOUTH);
        chainsPanel.add(chainsHeader, BorderLayout.NORTH);
        this.attackGraphScrollPane = new JScrollPane(new AttackGraphPaintPanel(attackGraphChainsModel));
        attackGraphScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        attackGraphScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        attackGraphScrollPane.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));
        // Smoother scroll: one row per wheel tick, larger block for PgUp/PgDn
        JScrollBar vBar = attackGraphScrollPane.getVerticalScrollBar();
        vBar.setUnitIncrement(24);
        vBar.setBlockIncrement(200);
        JScrollBar hBar = attackGraphScrollPane.getHorizontalScrollBar();
        hBar.setUnitIncrement(24);
        hBar.setBlockIncrement(120);
        chainsPanel.add(attackGraphScrollPane, BorderLayout.CENTER);
        chainsPanel.setMinimumSize(new Dimension(200, 160));
        JPanel sendablePanel = new JPanel(new BorderLayout(4, 4));
        JPanel sendableToolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        sendableToolbar.add(new JLabel("Sendable URLs (from refs / attack graph):"));
        sendableToolbar.add(sendToRepeaterBtn);
        sendablePanel.add(sendableToolbar, BorderLayout.NORTH);
        sendablePanel.add(new JScrollPane(sendableUrlsTable), BorderLayout.CENTER);
        sendablePanel.setMinimumSize(new Dimension(200, 120));
        JSplitPane attackGraphSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, chainsPanel, sendablePanel);
        attackGraphSplit.setResizeWeight(0.65);
        attackGraphSplit.setOneTouchExpandable(true);
        attackGraphSplit.setDividerLocation(0.65);
        attackGraphPanel.add(attackGraphSplit, BorderLayout.CENTER);
        resultsTabs.addTab("Attack graph", attackGraphPanel);

        // Thick client findings: dynamic results from scan (Electron, Qt, .NET, chains, etc.)
        this.thickClientFindingsModel = new DefaultTableModel(
            new String[] { "Category", "Title", "Summary", "Hunt suggestion", "Artifacts" }, 0);
        this.thickClientFindingsTable = new JTable(thickClientFindingsModel);
        thickClientFindingsTable.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        thickClientFindingsTable.setAutoCreateRowSorter(true);
        thickClientFindingsTable.setRowHeight(Math.max(20, thickClientFindingsTable.getRowHeight()));
        JPanel thickClientFindingsPanel = new JPanel(new BorderLayout(4, 4));
        thickClientFindingsPanel.setBorder(new EmptyBorder(6, 6, 6, 6));
        JLabel tcfLabel = new JLabel("What was found in this scan (thick-client terms). Use Attack graph + Payloads tab to confirm exploitation.");
        tcfLabel.setForeground(Color.GRAY);
        tcfLabel.setFont(tcfLabel.getFont().deriveFont(11f));
        thickClientFindingsPanel.add(tcfLabel, BorderLayout.NORTH);
        thickClientFindingsPanel.add(new JScrollPane(thickClientFindingsTable), BorderLayout.CENTER);

        // Consolidated Findings tab (Thick client | Permission | Cert | Dotnet | CVE lookup)
        this.findingsCardLayout = new CardLayout();
        this.findingsCardsPanel = new JPanel(findingsCardLayout);
        findingsCardsPanel.add(thickClientFindingsPanel, "Thick client findings");
        findingsCardsPanel.add(permissionFindingsPanel, "Permission findings");
        findingsCardsPanel.add(certFindingsPanel, "Cert findings");
        findingsCardsPanel.add(dotnetFindingsPanel, "Dotnet findings");
        findingsCardsPanel.add(cveLookupPanel, "CVE lookup");
        JComboBox<String> findingsTypeCombo = new JComboBox<>(new String[] {
            "Thick client findings", "Permission findings", "Cert findings", "Dotnet findings", "CVE lookup"
        });
        findingsTypeCombo.setToolTipText("Switch findings type");
        findingsTypeCombo.addActionListener(e -> findingsCardLayout.show(findingsCardsPanel, (String) findingsTypeCombo.getSelectedItem()));
        JPanel findingsWrapper = new JPanel(new BorderLayout(4, 4));
        findingsWrapper.add(findingsTypeCombo, BorderLayout.NORTH);
        findingsWrapper.add(findingsCardsPanel, BorderLayout.CENTER);
        resultsTabs.addTab("Findings", findingsWrapper);

        // Payloads (HackBar-style): browse by category, copy payload
        this.payloadDetailArea = new JTextArea(8, 60);
        payloadDetailArea.setEditable(false);
        payloadDetailArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        payloadDetailArea.setLineWrap(true);
        this.payloadLibraryModel = new DefaultTableModel(
            new String[] { "Name", "Category", "Type", "Reference" }, 0);
        this.payloadLibraryTable = new JTable(payloadLibraryModel);
        payloadLibraryTable.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        payloadLibraryTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        payloadLibraryTable.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) return;
            int row = payloadLibraryTable.getSelectedRow();
            if (row < 0) { payloadDetailArea.setText(""); return; }
            int modelRow = payloadLibraryTable.convertRowIndexToModel(row);
            String payload = modelRow < payloadLibraryPayloads.size() ? payloadLibraryPayloads.get(modelRow) : "";
            String desc = modelRow < payloadLibraryDescriptions.size() ? payloadLibraryDescriptions.get(modelRow) : "";
            payloadDetailArea.setText((desc.isEmpty() ? "" : desc + "\n\n--- Payload ---\n\n") + payload);
        });
        this.payloadCategoryFilter = new JComboBox<>(new String[] { "All", "Electron", "Qt", ".NET", "Persistence", "Network", "JAR", "Other" });
        payloadCategoryFilter.addActionListener(e -> applyPayloadLibraryFilter());
        JPanel payloadLibraryToolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        payloadLibraryToolbar.add(new JLabel("Category:"));
        payloadLibraryToolbar.add(payloadCategoryFilter);
        JButton copyPayloadBtn = new JButton("Copy payload");
        copyPayloadBtn.addActionListener(e -> {
            String sel = payloadDetailArea.getSelectedText();
            String text = (sel != null && !sel.isEmpty()) ? sel : payloadDetailArea.getText();
            if (text != null && !text.isEmpty()) {
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new java.awt.datatransfer.StringSelection(text), null);
                statusLabel.setText("Payload copied to clipboard.");
            }
        });
        payloadLibraryToolbar.add(copyPayloadBtn);
        JPanel payloadLibraryPanel = new JPanel(new BorderLayout(4, 4));
        payloadLibraryPanel.setBorder(new EmptyBorder(6, 6, 6, 6));
        payloadLibraryPanel.add(payloadLibraryToolbar, BorderLayout.NORTH);
        JSplitPane payloadSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
            new JScrollPane(payloadLibraryTable),
            new JScrollPane(payloadDetailArea));
        payloadSplit.setResizeWeight(0.5);
        payloadSplit.setOneTouchExpandable(true);
        payloadLibraryPanel.add(payloadSplit, BorderLayout.CENTER);
        JLabel payloadLibLabel = new JLabel("Thick-client payload library (HackBar-style). Select a row to view; copy and use with your target.");
        payloadLibLabel.setForeground(Color.GRAY);
        payloadLibLabel.setFont(payloadLibLabel.getFont().deriveFont(11f));
        payloadLibraryPanel.add(payloadLibLabel, BorderLayout.SOUTH);
        resultsTabs.addTab("Payloads", payloadLibraryPanel);

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
        liveSlotsList.setToolTipText("HTTP(S) endpoints the app may load or call; select one to edit and send.");
        liveRequestArea.setToolTipText("Outgoing request; edit to test interception or server (thick-client traffic).");
        liveResponseArea.setToolTipText("Response / result from the last Send.");
        JPanel liveLeft = new JPanel(new BorderLayout(4, 4));
        JLabel liveEndpointsLabel = new JLabel("Endpoints (from app refs)");
        liveEndpointsLabel.setToolTipText("URLs discovered from the thick-client binary; modify and send to test proxy or server.");
        liveLeft.add(liveEndpointsLabel, BorderLayout.NORTH);
        liveLeft.add(new JScrollPane(liveSlotsList), BorderLayout.CENTER);
        JPanel liveRight = new JPanel(new BorderLayout(4, 4));
        JPanel liveRequestPanel = new JPanel(new BorderLayout(2, 2));
        JLabel liveRequestLabel = new JLabel("Outgoing request / payload");
        liveRequestLabel.setToolTipText("Edit and send to test interception or server (thick-client equivalent of Repeater).");
        liveRequestPanel.add(liveRequestLabel, BorderLayout.NORTH);
        liveRequestPanel.add(new JScrollPane(liveRequestArea), BorderLayout.CENTER);
        JPanel liveResponsePanel = new JPanel(new BorderLayout(2, 2));
        JLabel liveResponseLabel = new JLabel("Response / result");
        liveResponseLabel.setToolTipText("Result from last Send.");
        liveResponsePanel.add(liveResponseLabel, BorderLayout.NORTH);
        liveResponsePanel.add(new JScrollPane(liveResponseArea), BorderLayout.CENTER);
        JPanel liveButtons = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        JButton liveSendBtn = new JButton("Send");
        liveSendBtn.setToolTipText("Send request and show response (thick-client traffic via Burp)");
        liveSendBtn.addActionListener(e -> sendLiveRequest());
        liveButtons.add(liveSendBtn);
        JButton liveLoadFromProxyBtn = new JButton("Load from Proxy");
        liveLoadFromProxyBtn.setToolTipText("Fill request from latest matching Proxy history entry");
        liveLoadFromProxyBtn.addActionListener(e -> loadLiveRequestFromProxy());
        liveButtons.add(liveLoadFromProxyBtn);
        JButton liveBulkImportFromProxyBtn = new JButton("Bulk import from Proxy");
        liveBulkImportFromProxyBtn.setToolTipText("Import last N requests from Proxy history (optionally filter by host) into Live slots");
        liveBulkImportFromProxyBtn.addActionListener(e -> bulkImportFromProxy());
        liveButtons.add(liveBulkImportFromProxyBtn);
        JButton liveResetSlotBtn = new JButton("Reset slot");
        liveResetSlotBtn.setToolTipText("Reset this slot to initial request; clear response");
        liveResetSlotBtn.addActionListener(e -> resetCurrentLiveSlot());
        liveButtons.add(liveResetSlotBtn);
        JButton liveRefreshAllBtn = new JButton("Refresh all");
        liveRefreshAllBtn.setToolTipText("Reset all slots to initial requests and clear responses");
        liveRefreshAllBtn.addActionListener(e -> refreshAllLiveSlots());
        liveButtons.add(liveRefreshAllBtn);
        JPanel liveCenterRight = new JPanel(new BorderLayout(4, 4));
        liveCenterRight.add(liveRequestPanel, BorderLayout.NORTH);
        liveCenterRight.add(liveButtons, BorderLayout.CENTER);
        liveCenterRight.add(liveResponsePanel, BorderLayout.SOUTH);
        JSplitPane liveSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, liveLeft, liveCenterRight);
        liveSplit.setResizeWeight(0.25);
        liveSplit.setDividerLocation(200);
        JPanel liveManipulationPanel = new JPanel(new BorderLayout(4, 4));
        JLabel liveHint = new JLabel("Thick-client: endpoints the app may call; edit payload and Send to test proxy or server.");
        liveHint.setForeground(Color.GRAY);
        liveHint.setFont(liveHint.getFont().deriveFont(11f));
        liveManipulationPanel.add(liveHint, BorderLayout.NORTH);
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

        // Upper section: consolidated into sub-tabs to reduce clutter
        JPanel scanTab = new JPanel();
        scanTab.setLayout(new BoxLayout(scanTab, BoxLayout.PAGE_AXIS));
        scanTab.add(intro);
        scanTab.add(inputPanel);
        scanTab.add(optionsPanel);
        JPanel statusRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        statusRow.add(statusLabel);
        statusRow.add(versionLabel);
        scanTab.add(statusRow);

        JPanel advancedTab = new JPanel();
        advancedTab.setLayout(new BoxLayout(advancedTab, BoxLayout.PAGE_AXIS));
        advancedTab.add(daemonPanel);
        advancedTab.add(limitsPanel);
        advancedTab.add(baselinePanel);
        advancedTab.add(unveilPathPanel);
        advancedTab.add(proxyWrap);

        JTabbedPane controlsTabs = new JTabbedPane();
        controlsTabs.addTab("Scan", scanTab);
        controlsTabs.addTab("Advanced", advancedTab);

        JPanel controlsWrapper = new JPanel(new BorderLayout(0, 4));
        controlsWrapper.add(controlsTabs, BorderLayout.CENTER);
        controlsWrapper.setMinimumSize(new Dimension(400, 120));

        // Lower section: results (toolbar + tabs) — resizable vertically
        JPanel resultsWrapper = new JPanel(new BorderLayout(0, 8));
        resultsWrapper.add(resultsToolbar, BorderLayout.NORTH);
        resultsWrapper.add(resultsTabs, BorderLayout.CENTER);
        resultsTabs.setBorder(BorderFactory.createEtchedBorder());
        resultsWrapper.setMinimumSize(new Dimension(400, 200));

        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, controlsWrapper, resultsWrapper);
        mainSplit.setResizeWeight(0.22);
        mainSplit.setOneTouchExpandable(true);
        mainSplit.setDividerLocation(0.22);

        mainPanel.add(mainSplit, BorderLayout.CENTER);

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
            optCveLookup.setSelected(prefs.getBoolean("optCveLookup", false));
            maxFilesSpinner.setValue(prefs.getInt("maxFiles", 80));
            maxSizeMbSpinner.setValue(prefs.getInt("maxSizeMb", 120));
            maxPerTypeSpinner.setValue(prefs.getInt("maxPerType", 500));
            String baseline = prefs.get("baselinePath", "");
            if (!baseline.isEmpty()) baselinePathField.setText(baseline);
            String proxyHostPort = prefs.get("proxyHostPort", "");
            if (!proxyHostPort.isEmpty()) proxyHostPortField.setText(proxyHostPort);
            optProxyBackend.setSelected(prefs.getBoolean("optProxyBackend", false));
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
            prefs.putBoolean("optCveLookup", optCveLookup.isSelected());
            prefs.putInt("maxFiles", ((Number) maxFilesSpinner.getValue()).intValue());
            prefs.putInt("maxSizeMb", ((Number) maxSizeMbSpinner.getValue()).intValue());
            prefs.putInt("maxPerType", ((Number) maxPerTypeSpinner.getValue()).intValue());
            String baseline = baselinePathField.getText();
            prefs.put("baselinePath", baseline != null ? baseline.trim() : "");
            String proxyHostPort = proxyHostPortField.getText();
            prefs.put("proxyHostPort", proxyHostPort != null ? proxyHostPort.trim() : "");
            prefs.putBoolean("optProxyBackend", optProxyBackend.isSelected());
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
        if (!useDaemonCheck.isSelected()) {
            java.io.File pathFile = new java.io.File(target);
            if (!pathFile.exists()) {
                statusLabel.setText("Path does not exist.");
                summaryArea.setText("Target path does not exist:\n\n" + target + "\n\nEnter a valid path or use Browse…");
                return;
            }
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
        interestingStringsModel.setRowCount(0);
        permissionFindingsModel.setRowCount(0);
        certFindingsModel.setRowCount(0);
        dotnetFindingsModel.setRowCount(0);
        cveLookupModel.setRowCount(0);
        instrumentationHintsModel.setRowCount(0);
        pathsToWatchModel.clear();
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
        if (interestingStringsCustomFilterField != null) interestingStringsCustomFilterField.setText("");
        thickClientFindingsModel.setRowCount(0);
        payloadLibraryModel.setRowCount(0);
        payloadLibraryFullData.clear();
        payloadLibraryPayloads.clear();
        payloadLibraryDescriptions.clear();
        attackGraphChainsModel.setRowCount(0);
        attackGraphPayloadsByRow.clear();
        sendableUrlsModel.setRowCount(0);
        liveSlots.clear();
        liveSlotsListModel.clear();
        if (updateRefsModel != null) updateRefsModel.setRowCount(0);
        if (credentialHintsModel != null) credentialHintsModel.setRowCount(0);
        if (dbSummaryModel != null) dbSummaryModel.setRowCount(0);
        if (importSummaryListModel != null) importSummaryListModel.clear();
        if (packedEntropyModel != null) packedEntropyModel.setRowCount(0);
        if (nonHttpRefsModel != null) nonHttpRefsModel.setRowCount(0);
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

    private void bulkImportFromProxy() {
        JTextField hostField = new JTextField(30);
        hostField.setToolTipText("Leave empty to use all hosts; otherwise only requests whose URL contains this host");
        JSpinner maxSpinner = new JSpinner(new javax.swing.SpinnerNumberModel(50, 1, 500, 10));
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        JPanel hostRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        hostRow.add(new JLabel("Host (optional):"));
        hostRow.add(hostField);
        panel.add(hostRow);
        JPanel maxRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        maxRow.add(new JLabel("Max requests:"));
        maxRow.add(maxSpinner);
        panel.add(maxRow);
        int ok = JOptionPane.showConfirmDialog(mainPanel, panel, "Bulk import from Proxy", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (ok != JOptionPane.OK_OPTION) return;
        String hostFilter = (hostField.getText() != null ? hostField.getText().trim() : "").toLowerCase();
        int maxRequests = ((Number) maxSpinner.getValue()).intValue();
        try {
            var history = api.proxy().history();
            if (history == null || history.isEmpty()) {
                statusLabel.setText("Proxy history is empty.");
                return;
            }
            saveCurrentLiveSlotContent();
            liveSlots.clear();
            liveSlotsListModel.clear();
            liveSlotsSelectedIndex = -1;
            int phase = 1;
            for (int i = history.size() - 1; i >= 0 && phase <= maxRequests; i--) {
                var item = history.get(i);
                if (item == null) continue;
                String u = item.url();
                if (u == null && item.finalRequest() != null) u = item.finalRequest().url();
                if (u == null || !u.startsWith("http")) continue;
                if (!hostFilter.isEmpty() && !u.toLowerCase().contains(hostFilter)) continue;
                String reqText = item.finalRequest() != null ? item.finalRequest().toString() : "";
                LiveManipulationSlot slot = new LiveManipulationSlot(u, "Proxy", "Import " + phase);
                slot.requestText = reqText != null ? reqText : "";
                slot.responseText = "";
                liveSlots.add(slot);
                liveSlotsListModel.addElement("Phase " + phase + ": " + (u.length() > 60 ? u.substring(0, 57) + "..." : u));
                phase++;
            }
            if (liveSlots.isEmpty()) {
                statusLabel.setText("No matching requests in Proxy history.");
                return;
            }
            liveSlotsSelectedIndex = 0;
            liveSlotsList.setSelectedIndex(0);
            if (!liveSlots.isEmpty()) {
                LiveManipulationSlot s = liveSlots.get(0);
                liveRequestArea.setText(s.requestText != null ? s.requestText : "");
                liveResponseArea.setText(s.responseText != null ? s.responseText : "");
            }
            statusLabel.setText("Imported " + liveSlots.size() + " requests from Proxy history.");
        } catch (Exception ex) {
            logging.logToError("Bulk import from Proxy: " + ex.getMessage());
            statusLabel.setText("Bulk import failed.");
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
            HttpURLConnection conn;
            if (optProxyBackend.isSelected()) {
                Proxy proxy = parseProxyFromField();
                conn = proxy != null ? (HttpURLConnection) url.openConnection(proxy) : (HttpURLConnection) url.openConnection();
            } else {
                conn = (HttpURLConnection) url.openConnection();
            }
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
            body.addProperty("cve_lookup", optCveLookup.isSelected());
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
                summaryArea.setText("Could not call daemon.\n\n" + (msg != null ? msg : "")
                    + "\n\nCheck that the daemon is running (e.g. run 'unveil' or 'python -m unveil.daemon') and the URL is correct.");
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

    /**
     * Build CLI argument list for unveil. Pass null for any output path you don't need.
     * SARIF export uses this so limits/baseline/options are consistent with scan.
     */
    private List<String> buildUnveilArgs(String target, String jsonPath, String htmlPath, String sarifPath) {
        List<String> args = new ArrayList<>();
        args.add(resolveUnveilPath());
        args.add("-C");
        args.add(target);
        args.add("-q");
        if (optExtended.isSelected()) args.add("-e");
        if (optOffensive.isSelected()) args.add("-O");
        if (optForce.isSelected()) args.add("-f");
        if (optCve.isSelected()) args.add("--cve");
        if (optCveLookup.isSelected()) args.add("--cve-lookup");
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
        if (sarifPath != null && !sarifPath.isEmpty()) {
            args.add("-xs");
            args.add(sarifPath);
        }
        return args;
    }

    private List<String> buildUnveilArgs(String target, String jsonPath, String htmlPath) {
        return buildUnveilArgs(target, jsonPath, htmlPath, null);
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
            String proxyUrl = getProxyUrlForEnv();
            if (proxyUrl != null) {
                pb.environment().put("HTTP_PROXY", proxyUrl);
                pb.environment().put("HTTPS_PROXY", proxyUrl);
                pb.environment().put("http_proxy", proxyUrl);
                pb.environment().put("https_proxy", proxyUrl);
            }
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
            int exitCode = exit;
            SwingUtilities.invokeLater(() -> {
                scanButton.setEnabled(true);
                if (exitCode != 0) {
                    boolean cmdNotFound = (exitCode == 127);
                    String installHint = "Unveil CLI not found. Install: pipx install git+https://github.com/Pa7ch3s/Unveil.git\n\n"
                        + "If already installed, set \"Unveil executable (optional)\" to the full path (e.g. from 'which unveil').";
                    boolean appliedErrorReport = false;
                    if (!finalResult.isEmpty() && !cmdNotFound) {
                        try {
                            JsonObject parsed = JsonParser.parseString(finalResult).getAsJsonObject();
                            if (parsed.has("metadata") && parsed.getAsJsonObject("metadata").has("error")) {
                                applyReport(finalResult);
                                resultsToolbar.setVisible(true);
                                statusLabel.setText("Error.");
                                appliedErrorReport = true;
                            }
                        } catch (Exception ignored) {}
                    }
                    if (!appliedErrorReport) {
                        statusLabel.setText("Scan failed.");
                        String body = cmdNotFound ? installHint : (finalResult.isEmpty() ? "Check options or unveil CLI." : finalResult);
                        if (cmdNotFound && !finalResult.isEmpty()) body = installHint + "\n\n" + finalResult;
                        summaryArea.setText("Unveil exited with code " + exitCode + ".\n\n" + body);
                        resultsToolbar.setVisible(false);
                    }
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
            if (metadata != null && metadata.has("error")) {
                String err = metadata.get("error").getAsString();
                summary.append("Error: ").append(err != null ? err : "").append("\n\n");
            }

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
                if (report.has("suggested_order")) {
                    JsonArray so = report.getAsJsonArray("suggested_order");
                    if (so != null && so.size() > 0) {
                        summary.append("\nSuggested order (test first):\n");
                        int max = Math.min(so.size(), 15);
                        for (int i = 0; i < max; i++) {
                            JsonElement el = so.get(i);
                            String title = "";
                            if (el.isJsonObject() && el.getAsJsonObject().has("Title"))
                                title = el.getAsJsonObject().get("Title").getAsString();
                            if (title == null) title = "";
                            summary.append("  ").append(i + 1).append(". ").append(title).append("\n");
                        }
                        if (so.size() > 15) summary.append("  … and ").append(so.size() - 15).append(" more.\n");
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
            if (report.has("interesting_strings")) {
                JsonArray isArr = report.getAsJsonArray("interesting_strings");
                int totalStr = 0;
                if (isArr != null) {
                    for (JsonElement el : isArr) {
                        if (el.isJsonObject() && el.getAsJsonObject().has("strings")) {
                            JsonArray s = el.getAsJsonObject().getAsJsonArray("strings");
                            if (s != null) totalStr += s.size();
                        }
                    }
                    summary.append("Interesting strings: ").append(totalStr).append(" (from ").append(isArr.size()).append(" files)\n");
                }
            }
            if (report.has("permission_findings")) {
                JsonArray pf = report.getAsJsonArray("permission_findings");
                summary.append("Permission findings: ").append(pf != null ? pf.size() : 0).append("\n");
            }
            if (report.has("cert_findings")) {
                JsonArray cf = report.getAsJsonArray("cert_findings");
                int expired = 0, selfSigned = 0;
                if (cf != null) {
                    for (JsonElement el : cf) {
                        if (el.isJsonObject()) {
                            JsonObject o = el.getAsJsonObject();
                            if (o.has("expired") && o.get("expired").getAsBoolean()) expired++;
                            if (o.has("self_signed") && o.get("self_signed").getAsBoolean()) selfSigned++;
                        }
                    }
                    summary.append("Cert findings: ").append(cf.size()).append(" (").append(expired).append(" expired, ").append(selfSigned).append(" self-signed)\n");
                }
            }
            if (report.has("dotnet_findings")) {
                JsonArray df = report.getAsJsonArray("dotnet_findings");
                summary.append("Dotnet findings: ").append(df != null ? df.size() : 0).append("\n");
            }
            if (report.has("instrumentation_hints")) {
                JsonArray ih = report.getAsJsonArray("instrumentation_hints");
                summary.append("Instrumentation hints: ").append(ih != null ? ih.size() : 0).append("\n");
            }
            if (report.has("paths_to_watch")) {
                JsonArray pw = report.getAsJsonArray("paths_to_watch");
                summary.append("Paths to watch: ").append(pw != null ? pw.size() : 0).append("\n");
            }
            if (report.has("tls_pinning_hints")) {
                JsonArray tph = report.getAsJsonArray("tls_pinning_hints");
                summary.append("TLS/Pinning hints: ").append(tph != null ? tph.size() : 0).append("\n");
            }
            if (report.has("update_refs")) {
                JsonArray ur = report.getAsJsonArray("update_refs");
                summary.append("Update/installer refs: ").append(ur != null ? ur.size() : 0).append("\n");
            }
            if (report.has("credential_hints")) {
                JsonArray ch = report.getAsJsonArray("credential_hints");
                summary.append("Credential/storage hints: ").append(ch != null ? ch.size() : 0).append("\n");
            }
            if (report.has("db_summary")) {
                JsonArray ds = report.getAsJsonArray("db_summary");
                summary.append("DB summary: ").append(ds != null ? ds.size() : 0).append(" DB(s)\n");
            }
            if (report.has("apk_manifest")) {
                JsonObject am = report.getAsJsonObject("apk_manifest");
                if (am != null && am.size() > 0) {
                    summary.append("\nAPK manifest\n");
                    if (am.has("package")) summary.append("  package: ").append(str(am.get("package"))).append("\n");
                    if (am.has("debuggable") && am.get("debuggable").getAsBoolean()) summary.append("  debuggable: true\n");
                    if (am.has("dangerous_or_sensitive_permissions")) {
                        JsonArray perms = am.getAsJsonArray("dangerous_or_sensitive_permissions");
                        if (perms != null && perms.size() > 0)
                            summary.append("  dangerous/sensitive permissions: ").append(perms.size()).append("\n");
                    }
                    if (am.has("note") && !str(am.get("note")).isEmpty()) summary.append("  note: ").append(str(am.get("note"))).append("\n");
                }
            }
            if (report.has("import_summary")) {
                JsonObject im = report.getAsJsonObject("import_summary");
                if (im != null && im.has("libraries")) {
                    int n = im.getAsJsonArray("libraries").size();
                    summary.append("Import summary: ").append(n).append(" libraries\n");
                }
            }
            if (report.has("packed_entropy")) {
                JsonArray pe = report.getAsJsonArray("packed_entropy");
                summary.append("Packed/entropy: ").append(pe != null ? pe.size() : 0).append(" files\n");
            }
            if (report.has("non_http_refs")) {
                JsonArray nhr = report.getAsJsonArray("non_http_refs");
                summary.append("Non-HTTP refs: ").append(nhr != null ? nhr.size() : 0).append("\n");
            }
            if (report.has("cve_lookup") && !report.get("cve_lookup").isJsonNull()) {
                JsonObject cl = report.getAsJsonObject("cve_lookup");
                if (cl != null && cl.has("queries")) {
                    JsonArray q = cl.getAsJsonArray("queries");
                    int totalCves = 0;
                    if (q != null) {
                        for (JsonElement el : q) {
                            if (el.isJsonObject() && el.getAsJsonObject().has("cves")) {
                                totalCves += el.getAsJsonObject().getAsJsonArray("cves").size();
                            }
                        }
                        summary.append("CVE lookup: ").append(q.size()).append(" queries, ").append(totalCves).append(" CVEs\n");
                    }
                }
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
            int chainabilityInScope = 0;
            if (report.has("chainability")) {
                JsonArray ca = report.getAsJsonArray("chainability");
                if (ca != null) {
                    for (JsonElement el : ca) {
                        JsonObject row = el.getAsJsonObject();
                        boolean inScope = row.has("in_scope") && row.get("in_scope").getAsBoolean();
                        if (inScope) chainabilityInScope++;
                        chainabilityModel.addRow(new Object[] {
                            str(row.get("file")),
                            str(row.get("ref")),
                            inScope ? "Yes" : "No",
                            str(row.get("matched_type")),
                            str(row.get("confidence"))
                        });
                    }
                }
            }
            chainabilitySummaryLabel.setText(chainabilityModel.getRowCount() + " rows · " + chainabilityInScope + " in scope");
            chainabilityFilterField.setText("");
            chainabilityScopeFilter.setSelectedIndex(0);
            applyChainabilityFilter();
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
            interestingStringsModel.setRowCount(0);
            if (report.has("interesting_strings")) {
                JsonArray isArr = report.getAsJsonArray("interesting_strings");
                if (isArr != null) {
                    for (JsonElement el : isArr) {
                        if (el.isJsonObject()) {
                            JsonObject o = el.getAsJsonObject();
                            String file = str(o.get("file"));
                            if (file == null) file = "";
                            if (o.has("strings") && o.get("strings").isJsonArray()) {
                                for (JsonElement sEl : o.getAsJsonArray("strings")) {
                                    String s = sEl != null && sEl.isJsonPrimitive() ? sEl.getAsString() : "";
                                    interestingStringsModel.addRow(new Object[] { file, s });
                                }
                            }
                        }
                    }
                }
            }
            permissionFindingsModel.setRowCount(0);
            if (report.has("permission_findings")) {
                JsonArray pf = report.getAsJsonArray("permission_findings");
                if (pf != null) {
                    for (JsonElement el : pf) {
                        if (el.isJsonObject()) {
                            JsonObject o = el.getAsJsonObject();
                            permissionFindingsModel.addRow(new Object[] {
                                str(o.get("path")),
                                str(o.get("finding")),
                                str(o.get("detail"))
                            });
                        }
                    }
                }
            }
            certFindingsModel.setRowCount(0);
            if (report.has("cert_findings")) {
                JsonArray cf = report.getAsJsonArray("cert_findings");
                if (cf != null) {
                    for (JsonElement el : cf) {
                        if (el.isJsonObject()) {
                            JsonObject o = el.getAsJsonObject();
                            String path = str(o.get("path"));
                            String subject = o.has("error") ? str(o.get("error")) : str(o.get("subject"));
                            String expired = o.has("error") ? "" : (o.has("expired") && o.get("expired").getAsBoolean() ? "Yes" : "No");
                            String selfSigned = o.has("error") ? "" : (o.has("self_signed") && o.get("self_signed").getAsBoolean() ? "Yes" : "No");
                            certFindingsModel.addRow(new Object[] { path, subject, expired, selfSigned });
                        }
                    }
                }
            }
            dotnetFindingsModel.setRowCount(0);
            if (report.has("dotnet_findings")) {
                JsonArray df = report.getAsJsonArray("dotnet_findings");
                if (df != null) {
                    for (JsonElement el : df) {
                        if (el.isJsonObject()) {
                            JsonObject o = el.getAsJsonObject();
                            String path = str(o.get("path"));
                            String asm = str(o.get("assembly_name"));
                            String ver = str(o.get("version"));
                            String serRef = (o.has("refs_serialization") && o.get("refs_serialization").getAsBoolean()) ? "Yes" : "No";
                            StringBuilder hints = new StringBuilder();
                            if (o.has("dangerous_hints") && o.get("dangerous_hints").isJsonArray()) {
                                JsonArray h = o.getAsJsonArray("dangerous_hints");
                                for (int i = 0; i < h.size(); i++) {
                                    if (i > 0) hints.append("; ");
                                    hints.append(str(h.get(i)));
                                }
                            }
                            dotnetFindingsModel.addRow(new Object[] { path, asm, ver, serRef, hints.toString() });
                        }
                    }
                }
            }
            cveLookupModel.setRowCount(0);
            if (report.has("cve_lookup") && !report.get("cve_lookup").isJsonNull()) {
                JsonObject cl = report.getAsJsonObject("cve_lookup");
                if (cl != null && cl.has("queries")) {
                    JsonArray queries = cl.getAsJsonArray("queries");
                    if (queries != null) {
                        for (JsonElement qEl : queries) {
                            if (!qEl.isJsonObject()) continue;
                            JsonObject qo = qEl.getAsJsonObject();
                            String query = str(qo.get("query"));
                            if (query == null) query = "";
                            JsonArray cves = qo.has("cves") ? qo.getAsJsonArray("cves") : null;
                            if (cves != null) {
                                for (JsonElement cEl : cves) {
                                    if (!cEl.isJsonObject()) continue;
                                    JsonObject cve = cEl.getAsJsonObject();
                                    String id = str(cve.get("id"));
                                    Object score = cve.has("score") && !cve.get("score").isJsonNull() ? cve.get("score").getAsDouble() : "";
                                    String published = str(cve.get("published"));
                                    String cveSummary = str(cve.get("summary"));
                                    if (cveSummary != null && cveSummary.length() > 200) cveSummary = cveSummary.substring(0, 197) + "...";
                                    cveLookupModel.addRow(new Object[] { query, id != null ? id : "", score, published != null ? published : "", cveSummary != null ? cveSummary : "" });
                                }
                            }
                        }
                    }
                }
            }
            instrumentationHintsModel.setRowCount(0);
            if (report.has("instrumentation_hints")) {
                JsonArray ih = report.getAsJsonArray("instrumentation_hints");
                if (ih != null) {
                    for (JsonElement el : ih) {
                        if (el.isJsonObject()) {
                            JsonObject o = el.getAsJsonObject();
                            instrumentationHintsModel.addRow(new Object[] {
                                str(o.get("surface")),
                                str(o.get("component_label")),
                                str(o.get("suggestion")),
                                str(o.get("frida_hint"))
                            });
                        }
                    }
                }
            }
            pathsToWatchModel.clear();
            if (report.has("paths_to_watch")) {
                JsonArray pw = report.getAsJsonArray("paths_to_watch");
                if (pw != null) {
                    for (JsonElement el : pw) {
                        if (el.isJsonPrimitive())
                            pathsToWatchModel.addElement(el.getAsString());
                    }
                }
            }
            updateRefsModel.setRowCount(0);
            if (report.has("update_refs")) {
                JsonArray ur = report.getAsJsonArray("update_refs");
                if (ur != null) {
                    for (JsonElement el : ur) {
                        if (el.isJsonObject()) {
                            JsonObject o = el.getAsJsonObject();
                            String tagsStr = "";
                            if (o.has("tags") && o.get("tags").isJsonArray()) {
                                JsonArray tags = o.getAsJsonArray("tags");
                                List<String> t = new ArrayList<>();
                                for (JsonElement te : tags) {
                                    if (te.isJsonPrimitive()) t.add(te.getAsString());
                                }
                                tagsStr = String.join(", ", t);
                            }
                            updateRefsModel.addRow(new Object[] {
                                str(o.get("file")),
                                str(o.get("ref")),
                                tagsStr
                            });
                        }
                    }
                }
            }
            credentialHintsModel.setRowCount(0);
            if (report.has("credential_hints")) {
                JsonArray ch = report.getAsJsonArray("credential_hints");
                if (ch != null) {
                    for (JsonElement el : ch) {
                        if (el.isJsonObject()) {
                            JsonObject o = el.getAsJsonObject();
                            credentialHintsModel.addRow(new Object[] {
                                str(o.get("hint")),
                                str(o.get("path")),
                                str(o.get("suggestion"))
                            });
                        }
                    }
                }
            }
            dbSummaryModel.setRowCount(0);
            if (report.has("db_summary")) {
                JsonArray ds = report.getAsJsonArray("db_summary");
                if (ds != null) {
                    for (JsonElement el : ds) {
                        if (el.isJsonObject()) {
                            JsonObject o = el.getAsJsonObject();
                            JsonArray tables = o.has("tables") && o.get("tables").isJsonArray() ? o.getAsJsonArray("tables") : null;
                            String tablesStr = "";
                            if (tables != null) {
                                List<String> t = new ArrayList<>();
                                for (JsonElement te : tables) {
                                    if (te.isJsonPrimitive()) t.add(te.getAsString());
                                }
                                tablesStr = String.join(", ", t);
                            }
                            dbSummaryModel.addRow(new Object[] {
                                str(o.get("path")),
                                tablesStr,
                                str(o.get("possible_credentials_hint"))
                            });
                        }
                    }
                }
            }
            importSummaryListModel.clear();
            if (report.has("import_summary")) {
                JsonObject im = report.getAsJsonObject("import_summary");
                if (im != null && im.has("libraries")) {
                    JsonArray libs = im.getAsJsonArray("libraries");
                    if (libs != null) {
                        for (JsonElement el : libs) {
                            if (el.isJsonPrimitive())
                                importSummaryListModel.addElement(el.getAsString());
                        }
                    }
                }
            }
            packedEntropyModel.setRowCount(0);
            if (report.has("packed_entropy")) {
                JsonArray pe = report.getAsJsonArray("packed_entropy");
                if (pe != null) {
                    for (JsonElement el : pe) {
                        if (el.isJsonObject()) {
                            JsonObject o = el.getAsJsonObject();
                            packedEntropyModel.addRow(new Object[] {
                                str(o.get("path")),
                                str(o.get("entropy"))
                            });
                        }
                    }
                }
            }
            nonHttpRefsModel.setRowCount(0);
            if (report.has("non_http_refs")) {
                JsonArray nhr = report.getAsJsonArray("non_http_refs");
                if (nhr != null) {
                    for (JsonElement el : nhr) {
                        if (el.isJsonObject()) {
                            JsonObject o = el.getAsJsonObject();
                            nonHttpRefsModel.addRow(new Object[] {
                                str(o.get("file")),
                                str(o.get("ref")),
                                str(o.get("tag"))
                            });
                        }
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
                                row.has("line") ? row.get("line").getAsInt() : "",
                                str(row.get("severity"))
                            });
                        }
                    }
                }
            }
        checklistFilterField.setText("");
        if (checklistTlsPinningOnlyCheck != null) checklistTlsPinningOnlyCheck.setSelected(false);
        applyChecklistFilter();
        chainabilityFilterField.setText("");
        chainabilityScopeFilter.setSelectedIndex(0);
        chainabilitySummaryLabel.setText("—");
        applyChainabilityFilter();
        attackGraphChainsModel.setRowCount(0);
            attackGraphPayloadsByRow.clear();
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
                                    String componentLabel = str(row.get("component_label"));
                                    if (componentLabel == null || componentLabel.isEmpty()) componentLabel = str(row.get("suggested_surface"));
                                    if (componentLabel == null || componentLabel.isEmpty()) componentLabel = str(row.get("missing_role_label"));
                                    String confidence = str(row.get("confidence"));
                                    if (confidence == null || confidence.isEmpty()) confidence = "—";
                                    attackGraphChainsModel.addRow(new Object[] {
                                        componentLabel,
                                        str(row.get("hunt_targets")),
                                        str(row.get("reason")),
                                        matchedPaths,
                                        confidence
                                    });
                                    List<PoCPayloadEntry> payloads = new ArrayList<>();
                                    if (row.has("suggested_payloads") && row.get("suggested_payloads").isJsonArray()) {
                                        for (JsonElement pe : row.getAsJsonArray("suggested_payloads")) {
                                            if (pe.isJsonObject()) {
                                                JsonObject p = pe.getAsJsonObject();
                                                payloads.add(new PoCPayloadEntry(
                                                    str(p.get("name")), str(p.get("description")),
                                                    str(p.get("type")), str(p.get("payload")), str(p.get("reference"))));
                                            }
                                        }
                                    }
                                    attackGraphPayloadsByRow.add(payloads);
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
            attackGraphScrollPane.revalidate();
            attackGraphScrollPane.repaint();
            if (liveSlotsSelectedIndex >= 0 && liveSlotsSelectedIndex < liveSlots.size()) {
                LiveManipulationSlot s = liveSlots.get(liveSlotsSelectedIndex);
                liveRequestArea.setText(s.requestText != null ? s.requestText : "");
                liveResponseArea.setText(s.responseText != null ? s.responseText : "");
            }
            thickClientFindingsModel.setRowCount(0);
            if (report.has("thick_client_findings")) {
                JsonArray tcf = report.getAsJsonArray("thick_client_findings");
                if (tcf != null) {
                    for (JsonElement el : tcf) {
                        if (el.isJsonObject()) {
                            JsonObject o = el.getAsJsonObject();
                            String category = str(o.get("category"));
                            String title = str(o.get("title"));
                            String tcfSummary = str(o.get("summary"));
                            String hunt = str(o.get("hunt_suggestion"));
                            String artifacts = "";
                            if (o.has("artifacts") && o.get("artifacts").isJsonArray()) {
                                JsonArray arr = o.getAsJsonArray("artifacts");
                                StringBuilder sb = new StringBuilder();
                                for (int i = 0; i < Math.min(5, arr.size()); i++) {
                                    if (i > 0) sb.append("; ");
                                    sb.append(arr.get(i).isJsonPrimitive() ? arr.get(i).getAsString() : "");
                                }
                                if (arr.size() > 5) sb.append("...");
                                artifacts = sb.toString();
                            }
                            thickClientFindingsModel.addRow(new Object[] { category, title, tcfSummary, hunt, artifacts });
                        }
                    }
                }
            }
            payloadLibraryFullData.clear();
            payloadLibraryPayloads.clear();
            payloadLibraryDescriptions.clear();
            payloadLibraryModel.setRowCount(0);
            if (report.has("payload_library")) {
                JsonArray pl = report.getAsJsonArray("payload_library");
                if (pl != null) {
                    for (JsonElement el : pl) {
                        if (el.isJsonObject()) {
                            JsonObject o = el.getAsJsonObject();
                            String name = str(o.get("name"));
                            String category = str(o.get("category"));
                            String type = str(o.get("type"));
                            String reference = str(o.get("reference"));
                            String payload = str(o.get("payload"));
                            String description = str(o.get("description"));
                            payloadLibraryFullData.add(new Object[] { name, category, type, reference, payload, description });
                        }
                    }
                }
            }
            applyPayloadLibraryFilter();
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

    private void showPocPayloadsForSelectedChain() {
        int n = attackGraphChainsModel.getRowCount();
        if (n == 0) {
            statusLabel.setText("Run a scan first to see chains and PoC payloads.");
            return;
        }
        JDialog dialog = new JDialog((java.awt.Frame) null, "Preconfigured PoC payloads — confirm exploitation", false);
        dialog.setLayout(new BorderLayout(8, 8));
        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT));
        top.add(new JLabel("Chain (vulnerable component):"));
        String[] chainLabels = new String[n];
        for (int i = 0; i < n; i++) {
            Object o = attackGraphChainsModel.getValueAt(i, 0);
            chainLabels[i] = (i + 1) + ". " + (o != null ? o.toString() : "");
        }
        JComboBox<String> chainCombo = new JComboBox<>(chainLabels);
        chainCombo.setPreferredSize(new Dimension(380, 24));
        top.add(chainCombo);
        dialog.add(top, BorderLayout.NORTH);
        JTextArea payloadArea = new JTextArea(14, 60);
        payloadArea.setEditable(false);
        payloadArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        payloadArea.setLineWrap(true);
        payloadArea.setWrapStyleWord(true);
        JScrollPane payloadScroll = new JScrollPane(payloadArea);
        JButton copyBtn = new JButton("Copy to clipboard");
        copyBtn.addActionListener(e -> {
            String t = payloadArea.getText();
            if (t != null && !t.isEmpty())
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(t), null);
        });
        JPanel center = new JPanel(new BorderLayout(4, 4));
        center.add(payloadScroll, BorderLayout.CENTER);
        center.add(copyBtn, BorderLayout.SOUTH);
        dialog.add(center, BorderLayout.CENTER);
        java.util.function.Consumer<Integer> update = idx -> {
            StringBuilder sb = new StringBuilder();
            if (idx >= 0 && idx < attackGraphPayloadsByRow.size()) {
                List<PoCPayloadEntry> list = attackGraphPayloadsByRow.get(idx);
                if (list.isEmpty()) sb.append("No preconfigured payloads for this chain.");
                else for (PoCPayloadEntry p : list) {
                    sb.append("--- ").append(p.name).append(" ---\n");
                    if (!p.description.isEmpty()) sb.append(p.description).append("\n");
                    if (!p.type.isEmpty()) sb.append("Type: ").append(p.type).append("\n");
                    if (!p.reference.isEmpty()) sb.append("Ref: ").append(p.reference).append("\n");
                    sb.append("\n").append(p.payload).append("\n\n");
                }
            }
            payloadArea.setText(sb.toString());
            payloadArea.setCaretPosition(0);
        };
        chainCombo.addActionListener(e -> update.accept(chainCombo.getSelectedIndex()));
        update.accept(0);
        dialog.pack();
        dialog.setSize(Math.min(700, dialog.getWidth()), Math.min(520, dialog.getHeight()));
        dialog.setLocationRelativeTo(null);
        dialog.setVisible(true);
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

    private void copyChecklistEvidence() {
        int viewRow = checklistTable.getSelectedRow();
        if (viewRow < 0) {
            statusLabel.setText("Select a checklist row first.");
            return;
        }
        int modelRow = checklistTable.convertRowIndexToModel(viewRow);
        Object pathObj = checklistModel.getValueAt(modelRow, 0);
        Object snippetObj = checklistModel.getValueAt(modelRow, 2);
        String path = pathObj != null ? pathObj.toString() : "";
        String snippet = snippetObj != null ? snippetObj.toString() : "";
        String evidence = "Path: " + path + "\nSnippet: " + snippet;
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(evidence), null);
        statusLabel.setText("Evidence copied (path + snippet).");
    }

    private void applyInterestingStringsCustomFilter() {
        TableRowSorter<?> sorter = (TableRowSorter<?>) interestingStringsTable.getRowSorter();
        if (sorter == null) return;
        String text = interestingStringsCustomFilterField != null ? interestingStringsCustomFilterField.getText() : "";
        if (text == null) text = "";
        String[] lines = text.split("\\n");
        java.util.List<String> terms = new ArrayList<>();
        for (String line : lines) {
            String t = line.trim();
            if (!t.isEmpty()) terms.add(t.toLowerCase());
        }
        if (terms.isEmpty()) {
            sorter.setRowFilter(null);
            return;
        }
        StringBuilder regex = new StringBuilder("(?i)");
        for (int i = 0; i < terms.size(); i++) {
            if (i > 0) regex.append("|");
            regex.append(".*").append(java.util.regex.Pattern.quote(terms.get(i))).append(".*");
        }
        sorter.setRowFilter(RowFilter.regexFilter(regex.toString(), 1));
    }

    private void applyChecklistFilter() {
        TableRowSorter<?> sorter = (TableRowSorter<?>) checklistTable.getRowSorter();
        if (sorter == null) return;
        String q = checklistFilterField.getText();
        if (q == null) q = "";
        q = q.trim();
        java.util.List<RowFilter<Object, Object>> filters = new ArrayList<>();
        if (!q.isEmpty()) {
            String search = "(?i)" + java.util.regex.Pattern.quote(q);
            filters.add(RowFilter.regexFilter(search, 0, 1, 2));
        }
        if (checklistTlsPinningOnlyCheck != null && checklistTlsPinningOnlyCheck.isSelected()) {
            filters.add(RowFilter.regexFilter("(?i)cert_pinning|ats_insecure_exception|insecure_cleartext", 1));
        }
        if (filters.isEmpty()) {
            sorter.setRowFilter(null);
        } else {
            sorter.setRowFilter(RowFilter.andFilter(filters));
        }
    }

    private void applyChainabilityFilter() {
        TableRowSorter<?> sorter = (TableRowSorter<?>) chainabilityTable.getRowSorter();
        if (sorter == null) return;
        String q = chainabilityFilterField.getText() != null ? chainabilityFilterField.getText().trim() : "";
        String scope = chainabilityScopeFilter.getSelectedItem() != null ? chainabilityScopeFilter.getSelectedItem().toString() : "All";
        java.util.List<RowFilter<Object, Object>> filters = new ArrayList<>();
        if (!q.isEmpty()) {
            String search = "(?i)" + java.util.regex.Pattern.quote(q);
            filters.add(RowFilter.regexFilter(search, 0, 1));
        }
        if ("In scope".equals(scope)) {
            filters.add(RowFilter.regexFilter("^Yes$", 2));
        } else if ("Out of scope".equals(scope)) {
            filters.add(RowFilter.regexFilter("^No$", 2));
        }
        if (filters.isEmpty()) {
            sorter.setRowFilter(null);
        } else {
            sorter.setRowFilter(RowFilter.andFilter(filters));
        }
    }

    private void applyPayloadLibraryFilter() {
        String cat = payloadCategoryFilter.getSelectedItem() != null ? payloadCategoryFilter.getSelectedItem().toString() : "All";
        payloadLibraryModel.setRowCount(0);
        payloadLibraryPayloads.clear();
        payloadLibraryDescriptions.clear();
        for (Object[] row : payloadLibraryFullData) {
            if (row == null || row.length < 6) continue;
            String rowCat = row[1] != null ? row[1].toString() : "";
            if (!"All".equals(cat) && !cat.equals(rowCat)) continue;
            payloadLibraryModel.addRow(new Object[] { row[0], row[1], row[2], row[3] });
            payloadLibraryPayloads.add(row[4] != null ? row[4].toString() : "");
            payloadLibraryDescriptions.add(row[5] != null ? row[5].toString() : "");
        }
    }

    private String chainabilityValueAt(int modelRow, int col) {
        if (modelRow < 0 || modelRow >= chainabilityModel.getRowCount() || col < 0 || col >= 5) return null;
        Object v = chainabilityModel.getValueAt(modelRow, col);
        return v != null ? v.toString().trim() : null;
    }

    private void copyChainabilityCell(int col) {
        int viewRow = chainabilityTable.getSelectedRow();
        if (viewRow < 0) { statusLabel.setText("Select a row."); return; }
        int modelRow = chainabilityTable.convertRowIndexToModel(viewRow);
        String s = chainabilityValueAt(modelRow, col);
        if (s != null && !s.isEmpty()) {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(s), null);
            statusLabel.setText(col == 0 ? "Path copied." : "Ref copied.");
        }
    }

    private void openChainabilityRefAsUrl() {
        int viewRow = chainabilityTable.getSelectedRow();
        if (viewRow < 0) { statusLabel.setText("Select a row."); return; }
        int modelRow = chainabilityTable.convertRowIndexToModel(viewRow);
        String ref = chainabilityValueAt(modelRow, 1);
        if (ref == null || !(ref.startsWith("http://") || ref.startsWith("https://"))) {
            statusLabel.setText("Ref is not a URL.");
            return;
        }
        try {
            if (Desktop.isDesktopSupported()) {
                Desktop.getDesktop().browse(new java.net.URI(ref));
                statusLabel.setText("Opened in browser.");
            }
        } catch (Exception ex) {
            statusLabel.setText("Could not open URL.");
        }
    }

    private void openChainabilityFile() {
        int viewRow = chainabilityTable.getSelectedRow();
        if (viewRow < 0) { statusLabel.setText("Select a row."); return; }
        int modelRow = chainabilityTable.convertRowIndexToModel(viewRow);
        String path = chainabilityValueAt(modelRow, 0);
        if (path == null || path.isEmpty()) { statusLabel.setText("No path."); return; }
        java.io.File f = new java.io.File(path);
        if (!f.exists() || !f.isFile()) { statusLabel.setText("File not found or not a file."); return; }
        try {
            if (Desktop.isDesktopSupported()) {
                Desktop.getDesktop().open(f);
                statusLabel.setText("Opened in default app.");
            }
        } catch (Exception ex) {
            statusLabel.setText("Open failed.");
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
        // Do not use reflection on Burp internals (exportProjectOptionsAsJson etc.) — the API
        // is not part of Montoya and breaks across Burp versions. Use default; user can set manually.
        return "127.0.0.1:8080";
    }

    /** Parse proxy host:port from field; return Proxy for use with URL.openConnection(proxy), or null if invalid. */
    private Proxy parseProxyFromField() {
        String hp = proxyHostPortField.getText();
        if (hp == null) hp = "";
        hp = hp.trim();
        if (hp.isEmpty()) hp = "127.0.0.1:8080";
        int colon = hp.lastIndexOf(':');
        String host = colon > 0 ? hp.substring(0, colon).trim() : "127.0.0.1";
        int port = 8080;
        try {
            port = Integer.parseInt(colon >= 0 ? hp.substring(colon + 1).trim() : hp);
        } catch (NumberFormatException e) {
            return null;
        }
        if (port <= 0 || port > 65535) return null;
        return new Proxy(Proxy.Type.HTTP, new InetSocketAddress(host, port));
    }

    /** Proxy URL for env (e.g. http://127.0.0.1:8080), or null if proxy backend disabled or invalid. */
    private String getProxyUrlForEnv() {
        if (!optProxyBackend.isSelected()) return null;
        String hp = proxyHostPortField.getText();
        if (hp == null) hp = "";
        hp = hp.trim();
        if (hp.isEmpty()) hp = "127.0.0.1:8080";
        int colon = hp.lastIndexOf(':');
        try {
            int port = Integer.parseInt(colon >= 0 ? hp.substring(colon + 1).trim() : hp);
            if (port <= 0 || port > 65535) return null;
        } catch (NumberFormatException e) {
            return null;
        }
        return hp.startsWith("http://") || hp.startsWith("https://") ? hp : "http://" + hp;
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

    private void copyLaunchCommand() {
        String hp = proxyHostPortField.getText();
        if (hp == null) hp = "";
        hp = hp.trim();
        if (hp.isEmpty()) hp = "127.0.0.1:8080";
        String url = "http://" + hp;
        String target = targetField.getText() != null ? targetField.getText().trim() : "";
        StringBuilder sb = new StringBuilder();
        sb.append("export HTTP_PROXY=").append(url).append("\n");
        sb.append("export HTTPS_PROXY=").append(url).append("\n");
        sb.append("export http_proxy=").append(url).append("\n");
        sb.append("export https_proxy=").append(url).append("\n");
        if (!target.isEmpty()) {
            sb.append("# Then run your app:\n");
            sb.append("#   macOS: open \"").append(target).append("\"\n");
            sb.append("#   Windows: start \"\" \"").append(target).append("\"\n");
        }
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(sb.toString()), null);
        statusLabel.setText("Launch command copied (proxy + run hint).");
    }

    private void copyPathsToWatchForProcMon() {
        StringBuilder sb = new StringBuilder();
        sb.append("# ProcMon: add as path include filter (Path contains), one per line\n");
        for (int i = 0; i < pathsToWatchModel.getSize(); i++) {
            sb.append(pathsToWatchModel.getElementAt(i)).append("\n");
        }
        if (pathsToWatchModel.getSize() > 0) {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(sb.toString().trim()), null);
            statusLabel.setText("ProcMon filter paths copied.");
        } else statusLabel.setText("No paths to watch.");
    }

    private void copyPathsToWatchFsUsage() {
        int n = pathsToWatchModel.getSize();
        if (n == 0) {
            statusLabel.setText("No paths to watch.");
            return;
        }
        int max = Math.min(50, n);
        StringBuilder sb = new StringBuilder();
        sb.append("fs_usage -f path");
        for (int i = 0; i < max; i++) {
            String p = pathsToWatchModel.getElementAt(i);
            if (p != null && !p.isEmpty()) {
                if (p.indexOf(' ') >= 0 || p.indexOf("'") >= 0) {
                    sb.append(" '").append(p.replace("'", "'\"'\"'")).append("'");
                } else {
                    sb.append(" ").append(p);
                }
            }
        }
        if (n > max) sb.append("\n# ... and ").append(n - max).append(" more (use Copy all paths for full list)");
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(sb.toString()), null);
        statusLabel.setText("fs_usage one-liner copied.");
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
                List<String> args = buildUnveilArgs(target, null, null, outPath);
                ProcessBuilder pb = new ProcessBuilder(args);
                pb.redirectErrorStream(true);
                String proxyUrl = getProxyUrlForEnv();
                if (proxyUrl != null) {
                    pb.environment().put("HTTP_PROXY", proxyUrl);
                    pb.environment().put("HTTPS_PROXY", proxyUrl);
                    pb.environment().put("http_proxy", proxyUrl);
                    pb.environment().put("https_proxy", proxyUrl);
                }
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

    /** Export unified findings table from current report JSON to CSV or Markdown. */
    private void exportFindings(boolean asMd) {
        String jsonText = rawJsonArea.getText();
        if (jsonText == null || jsonText.trim().isEmpty()) {
            statusLabel.setText("No report loaded. Run a scan first.");
            return;
        }
        List<String[]> rows;
        try {
            JsonObject report = JsonParser.parseString(jsonText).getAsJsonObject();
            rows = buildFindingsRowsFromReport(report);
        } catch (Exception e) {
            logging.logToError("Export findings parse error: " + e.getMessage());
            statusLabel.setText("Invalid report JSON.");
            return;
        }
        if (rows.isEmpty()) {
            statusLabel.setText("No findings to export.");
            return;
        }
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File(asMd ? "unveil-findings.md" : "unveil-findings.csv"));
        if (chooser.showSaveDialog(mainPanel) != JFileChooser.APPROVE_OPTION) return;
        File f = chooser.getSelectedFile();
        if (f == null) return;
        try {
            String[] headers = new String[] { "Title", "Severity", "Category", "Path", "Snippet", "CWE", "Recommendation", "Source" };
            if (asMd) {
                StringBuilder sb = new StringBuilder();
                sb.append("| Title | Severity | Category | Path | Snippet | CWE | Recommendation |\n");
                sb.append("|-------|----------|----------|------|---------|-----|-----------------|\n");
                for (String[] row : rows) {
                    String t = escapeMd((row.length > 0 ? row[0] : "").substring(0, Math.min(60, (row.length > 0 ? row[0] : "").length())));
                    String sev = row.length > 1 ? row[1] : "";
                    String cat = escapeMd((row.length > 2 ? row[2] : "").substring(0, Math.min(20, (row.length > 2 ? row[2] : "").length())));
                    String path = escapeMd((row.length > 3 ? row[3] : "").substring(0, Math.min(50, (row.length > 3 ? row[3] : "").length())));
                    String snip = escapeMd((row.length > 4 ? row[4] : "").replace("\n", " ").substring(0, Math.min(80, (row.length > 4 ? row[4] : "").length())));
                    String cwe = row.length > 5 ? row[5] : "";
                    String rec = escapeMd((row.length > 6 ? row[6] : "").replace("\n", " ").substring(0, Math.min(80, (row.length > 6 ? row[6] : "").length())));
                    sb.append("| ").append(t).append(" | ").append(sev).append(" | ").append(cat).append(" | ").append(path).append(" | ").append(snip).append(" | ").append(cwe).append(" | ").append(rec).append(" |\n");
                }
                Files.write(f.toPath(), sb.toString().getBytes(StandardCharsets.UTF_8));
            } else {
                StringBuilder sb = new StringBuilder();
                sb.append(String.join(",", headers)).append("\n");
                for (String[] row : rows) {
                    List<String> cells = new ArrayList<>();
                    for (int i = 0; i < headers.length; i++) {
                        String cell = (i < row.length && row[i] != null) ? row[i] : "";
                        cells.add(escapeCsv(cell));
                    }
                    sb.append(String.join(",", cells)).append("\n");
                }
                Files.write(f.toPath(), sb.toString().getBytes(StandardCharsets.UTF_8));
            }
            statusLabel.setText("Findings exported: " + f.getAbsolutePath());
        } catch (IOException e) {
            logging.logToError("Export findings write error: " + e.getMessage());
            statusLabel.setText("Write failed.");
        }
    }

    private static String escapeCsv(String s) {
        if (s == null) return "\"\"";
        if (s.contains("\"") || s.contains(",") || s.contains("\n") || s.contains("\r")) {
            return "\"" + s.replace("\"", "\"\"") + "\"";
        }
        return s;
    }

    private static String escapeMd(String s) {
        if (s == null) return "";
        return s.replace("|", "\\|");
    }

    /** Build findings rows from report: use suggested_order if present, else checklist + thick_client + chains. */
    private List<String[]> buildFindingsRowsFromReport(JsonObject report) {
        List<String[]> out = new ArrayList<>();
        String[] cols = new String[] { "Title", "Severity", "Category", "Path", "Snippet", "CWE", "Recommendation", "Source" };
        if (report.has("suggested_order")) {
            JsonArray so = report.getAsJsonArray("suggested_order");
            if (so != null) {
                for (JsonElement el : so) {
                    if (el.isJsonObject()) {
                        JsonObject row = el.getAsJsonObject();
                        out.add(new String[] {
                            str(row.get("Title")), str(row.get("Severity")), str(row.get("Category")),
                            str(row.get("Path")), str(row.get("Snippet")), str(row.get("CWE")),
                            str(row.get("Recommendation")), str(row.get("Source"))
                        });
                    }
                }
                if (!out.isEmpty()) return out;
            }
        }
        if (report.has("checklist_findings")) {
            JsonArray cf = report.getAsJsonArray("checklist_findings");
            if (cf != null) {
                for (JsonElement el : cf) {
                    if (el.isJsonObject()) {
                        JsonObject c = el.getAsJsonObject();
                        out.add(new String[] {
                            "Checklist: " + str(c.get("pattern")), str(c.get("severity")), "Checklist",
                            str(c.get("file")), str(c.get("snippet")), "", "Verify in config; remove or restrict if in production.", "checklist"
                        });
                    }
                }
            }
        }
        if (report.has("thick_client_findings")) {
            JsonArray tcf = report.getAsJsonArray("thick_client_findings");
            if (tcf != null) {
                for (JsonElement el : tcf) {
                    if (el.isJsonObject()) {
                        JsonObject t = el.getAsJsonObject();
                        JsonArray arts = t.has("artifacts") ? t.getAsJsonArray("artifacts") : null;
                        String path = (arts != null && arts.size() > 0 && arts.get(0).isJsonPrimitive()) ? arts.get(0).getAsString() : "";
                        String sum = str(t.get("summary"));
                        out.add(new String[] {
                            str(t.get("title")), str(t.get("severity")), str(t.get("category")),
                            path, sum.length() > 400 ? sum.substring(0, 400) : sum,
                            "", str(t.get("hunt_suggestion")), "thick_client"
                        });
                    }
                }
            }
        }
        if (report.has("attack_graph")) {
            JsonObject ag = report.getAsJsonObject("attack_graph");
            if (ag != null && ag.has("chains")) {
                JsonArray chains = ag.getAsJsonArray("chains");
                if (chains != null) {
                    for (JsonElement el : chains) {
                        if (el.isJsonObject()) {
                            JsonObject ch = el.getAsJsonObject();
                            if (!ch.has("matched_paths") || !ch.get("matched_paths").isJsonArray() || ch.getAsJsonArray("matched_paths").size() == 0) continue;
                            String role = str(ch.get("missing_role_label"));
                            if (role == null || role.isEmpty()) role = str(ch.get("missing_role"));
                            String surface = str(ch.get("component_label"));
                            if (surface == null || surface.isEmpty()) surface = str(ch.get("suggested_surface"));
                            JsonArray mp = ch.getAsJsonArray("matched_paths");
                            String path = (mp.size() > 0 && mp.get(0).isJsonPrimitive()) ? mp.get(0).getAsString() : "";
                            out.add(new String[] {
                                "Chain: " + role + " — " + surface, "High", "Attack graph", path,
                                mp.size() + " path(s) matched. Hunt: " + str(ch.get("hunt_targets")),
                                "", str(ch.get("reason")), "attack_graph"
                            });
                        }
                    }
                }
            }
        }
        return out;
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
                String proxyUrl = getProxyUrlForEnv();
                if (proxyUrl != null) {
                    pb.environment().put("HTTP_PROXY", proxyUrl);
                    pb.environment().put("HTTPS_PROXY", proxyUrl);
                    pb.environment().put("http_proxy", proxyUrl);
                    pb.environment().put("https_proxy", proxyUrl);
                }
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

    /** Paints attack graph chains as Role → Surface → Targets (with matched paths). Upgraded card-style rows. */
    private static final class AttackGraphPaintPanel extends JPanel {
        private static final int ROW_HEIGHT = 92;
        private static final int ROLE_BOX_W = 200;
        private static final int BOX_W = 144;
        private static final int BOX_H = 30;
        private static final int PAD = 16;
        private static final int ROW_PAD = 8;
        private static final int ARROW_LEN = 26;
        private static final int CARD_ARC = 10;

        private final DefaultTableModel model;
        private final boolean darkTheme;
        private final Color cardBg;

        AttackGraphPaintPanel(DefaultTableModel model) {
            this.model = model;
            Color bg = UIManager.getColor("Panel.background");
            if (bg == null) bg = new Color(240, 240, 240);
            setBackground(bg);
            this.darkTheme = isDark(bg);
            this.cardBg = darkTheme ? new Color(48, 48, 52) : new Color(248, 248, 250);
        }

        private static boolean isDark(Color c) {
            if (c == null) return false;
            double brightness = (c.getRed() * 0.299 + c.getGreen() * 0.587 + c.getBlue() * 0.114) / 255;
            return brightness < 0.45;
        }

        @Override
        public Dimension getPreferredSize() {
            int rows = model != null ? model.getRowCount() : 0;
            int w = PAD * 2 + ROLE_BOX_W + BOX_W + ARROW_LEN + 240;
            int h = rows <= 0 ? ROW_HEIGHT : Math.min(Integer.MAX_VALUE - PAD * 2, PAD * 2 + rows * (ROW_HEIGHT + ROW_PAD));
            return new Dimension(w, h);
        }

        @Override
        protected void paintComponent(Graphics g) {
            super.paintComponent(g);
            if (model == null) return;
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
                String component = objStr(model.getValueAt(r, 0));
                String targets = objStr(model.getValueAt(r, 1));
                String reason = objStr(model.getValueAt(r, 2));
                String paths = objStr(model.getValueAt(r, 3));

                // Card background for this row
                int cardW = PAD * 2 + ROLE_BOX_W + BOX_W + ARROW_LEN + 220;
                g2.setColor(cardBg);
                g2.fillRoundRect(PAD - 4, y - 4, cardW, ROW_HEIGHT + 4, CARD_ARC, CARD_ARC);
                g2.setColor(darkTheme ? new Color(70, 70, 74) : new Color(220, 220, 224));
                g2.drawRoundRect(PAD - 4, y - 4, cardW, ROW_HEIGHT + 4, CARD_ARC, CARD_ARC);

                int x = PAD;
                drawBox(g2, x, y, ROLE_BOX_W, BOX_H, component, true, darkTheme);
                x += ROLE_BOX_W + ARROW_LEN;
                drawArrow(g2, x - ARROW_LEN, y + BOX_H / 2, x, y + BOX_H / 2, darkTheme);
                drawBox(g2, x, y, BOX_W + 220, BOX_H, truncate(targets, 48), false, darkTheme);

                if (reason != null && !reason.isEmpty()) {
                    g2.setFont(g2.getFont().deriveFont(10f));
                    g2.setColor(secondaryColor());
                    String shortReason = truncate(reason, 62);
                    g2.drawString(shortReason, PAD, y + BOX_H + 16);
                    g2.setFont(g2.getFont().deriveFont(12f));
                    g2.setColor(foregroundColor());
                }
                if (paths != null && !paths.isEmpty()) {
                    g2.setFont(g2.getFont().deriveFont(10f));
                    g2.setColor(secondaryColor());
                    String firstLine = paths.contains("\n") ? paths.substring(0, paths.indexOf('\n')) : paths;
                    g2.drawString("Paths: " + truncate(firstLine, 72), PAD, y + BOX_H + 30);
                    g2.setFont(g2.getFont().deriveFont(12f));
                    g2.setColor(foregroundColor());
                }
                y += ROW_HEIGHT + ROW_PAD;
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
            Color boxFill = darkTheme ? new Color(30, 30, 34) : new Color(60, 60, 68);
            g2.setColor(boxFill);
            g2.fillRoundRect(x, y, w, h, 8, 8);
            Color edge = darkTheme ? new Color(120, 120, 128) : new Color(100, 100, 108);
            g2.setColor(edge);
            g2.drawRoundRect(x, y, w, h, 8, 8);
                if (text != null && !text.isEmpty()) {
                g2.setColor(darkTheme ? Color.WHITE : new Color(230, 230, 235));
                Font f = g2.getFont();
                if (bold) g2.setFont(f.deriveFont(Font.BOLD));
                FontMetrics fm = g2.getFontMetrics();
                int tw = fm.stringWidth(text);
                if (tw > w - 8) text = truncate(text, Math.max(1, (w - 8) / Math.max(1, fm.charWidth('m'))));
                g2.drawString(text, x + (w - fm.stringWidth(text)) / 2, y + h / 2 + fm.getAscent() / 2 - 2);
                g2.setFont(f);
            }
        }

        private static void drawArrow(Graphics2D g2, int x1, int y1, int x2, int y2, boolean darkTheme) {
            g2.setColor(darkTheme ? new Color(160, 160, 168) : new Color(100, 100, 108));
            java.awt.Stroke prev = g2.getStroke();
            g2.setStroke(new java.awt.BasicStroke(1.5f));
            g2.drawLine(x1, y1, x2, y2);
            int dx = x2 - x1;
            int dy = y2 - y1;
            double len = Math.sqrt(dx * dx + dy * dy);
            if (len >= 1) {
                int ax = (int) (x2 - 8 * dx / len);
                int ay = (int) (y2 - 8 * dy / len);
                g2.drawLine(x2, y2, ax + (int)(6 * dy / len), ay - (int)(6 * dx / len));
                g2.drawLine(x2, y2, ax - (int)(6 * dy / len), ay + (int)(6 * dx / len));
            }
            g2.setStroke(prev);
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
