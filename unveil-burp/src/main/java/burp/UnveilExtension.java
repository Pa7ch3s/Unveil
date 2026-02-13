package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

/**
 * Unveil Burp Suite extension — adds an "Unveil" tab for attack-surface radar.
 * Requires Unveil CLI or daemon for scanning; this extension provides the UI.
 */
public class UnveilExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Unveil");

        UnveilTab tab = new UnveilTab(api);
        api.userInterface().registerSuiteTab("Unveil", tab.getTabComponent());
    }
}
