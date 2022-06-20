package com.tugalsan.api.file.pdf.sign.server;

import java.nio.file.Path;
import java.util.Locale;

public class TS_FilePdfSignSslCfg {

    public TS_FilePdfSignSslCfg(Path keyStorePath, CharSequence keyStorePass) {
        this(keyStorePath, keyStorePass, null);//"https://freetsa.org/tsr";
    }

    public TS_FilePdfSignSslCfg(Path keyStorePath, CharSequence keyStorePass, CharSequence tsaURL) {
        this.keyStorePath = keyStorePath;
        this.keyStorePass = keyStorePass.toString();
        this.tsaURL = tsaURL == null ? null : tsaURL.toString();
        var fn = keyStorePath.getFileName().toString().toLowerCase(Locale.ROOT);
        if (fn.endsWith(".p12")) {
            keyType = "PKCS12";
        } else if (fn.endsWith(".jks")) {
            keyType = "JKS";
        }
    }
    private Path keyStorePath;
    private String keyStorePass, tsaURL, keyType = null;

    public Path getKeyStorePath() {
        return keyStorePath;
    }

    public String getKeyStorePass() {
        return keyStorePass;
    }

    public String getTsaURL() {
        return tsaURL;
    }

    public String getType() {
        return keyType;
    }
}
