package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;

import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.Component;
import java.io.PrintWriter;
import java.io.StringWriter;

/**
 * Unveil Burp Suite extension — adds an "Unveil" tab for attack-surface radar.
 * Requires Unveil CLI or daemon for scanning; this extension provides the UI.
 */
public class UnveilExtension implements BurpExtension {

    @SuppressWarnings("unused")
    private Registration suiteTabRegistration;

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Unveil");
        api.logging().logToOutput("Unveil: initialize() called.");

        Runnable register = () -> {
            api.logging().logToOutput("Unveil: creating tab component...");
            Component component;
            try {
                UnveilTab tab = new UnveilTab(api);
                component = tab.getTabComponent();
                if (component == null) {
                    api.logging().logToError("Unveil: getTabComponent() returned null");
                    component = makeErrorPanel(api, "Unveil tab returned null.");
                }
            } catch (Throwable t) {
                api.logging().logToError("Unveil failed to create tab: " + t.getMessage());
                if (t.getCause() != null) {
                    api.logging().logToError("  Cause: " + t.getCause().getMessage());
                }
                for (StackTraceElement e : t.getStackTrace()) {
                    api.logging().logToError("    at " + e.toString());
                }
                api.logging().logToOutput("Unveil: error creating tab - see Errors tab. " + t.getMessage());
                t.printStackTrace();
                component = makeErrorPanel(api, t);
            }

            try {
                suiteTabRegistration = api.userInterface().registerSuiteTab("Unveil", component);
                api.logging().logToOutput("Unveil: tab registered. If you don't see it: use the View menu (top menu bar) and click 'Unveil', or View → Restore default tab layout.");
                try {
                    api.userInterface().applyThemeToComponent(component);
                } catch (Throwable t) {
                    api.logging().logToError("Unveil: applyThemeToComponent failed: " + t.getMessage());
                }
            } catch (Throwable t) {
                api.logging().logToError("Unveil: registerSuiteTab failed: " + t.getMessage());
                api.logging().logToOutput("Unveil: registerSuiteTab failed - " + t.getMessage());
                for (StackTraceElement e : t.getStackTrace()) {
                    api.logging().logToError("    at " + e.toString());
                }
            }
        };

        if (SwingUtilities.isEventDispatchThread()) {
            register.run();
        } else {
            SwingUtilities.invokeLater(register);
        }
    }

    private static JPanel makeErrorPanel(MontoyaApi api, Throwable t) {
        StringWriter sw = new StringWriter();
        t.printStackTrace(new PrintWriter(sw));
        String msg = t.getMessage() != null ? t.getMessage() : t.getClass().getName();
        return makeErrorPanel(api, msg + "\n\n" + sw.toString());
    }

    private static JPanel makeErrorPanel(MontoyaApi api, String message) {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(16, 16, 16, 16));
        panel.add(new JLabel("Unveil failed to load. Check Extensions → Unveil → Errors for details."), BorderLayout.NORTH);
        JTextArea area = new JTextArea(20, 60);
        area.setEditable(false);
        area.setText(message);
        panel.add(new JScrollPane(area), BorderLayout.CENTER);
        return panel;
    }
}
