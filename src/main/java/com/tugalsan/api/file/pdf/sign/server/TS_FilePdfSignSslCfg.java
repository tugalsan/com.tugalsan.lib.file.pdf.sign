package com.tugalsan.api.file.pdf.sign.server;

import com.tugalsan.api.stream.client.TGS_StreamUtils;
import com.tugalsan.api.url.client.TGS_Url;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;

public class TS_FilePdfSignSslCfg {

    public List<TGS_Url> lstTsa() {
        return TGS_StreamUtils.toList(
                List.of(
                        "https://kbpdfstudio.qoppa.com/list-of-timestamp-servers-for-signing-pdf/",
                        "https://freetsa.org/tsr",
                        "http://time.certum.pl",
                        "http://timestamp.digicert.com",
                        "http://timestamp.apple.com/ts01",
                        "http://timestamp.entrust.net/TSS/RFC3161sha2TS",
                        "http://tsa.cesnet.cz:3161/tsa",
                        "https://tsa.cesnet.cz:3162/tsa",
                        "http://tsa.cesnet.cz:5816/tsa",
                        "https://tsa.cesnet.cz:5817/tsa"
                ).stream().map(s -> TGS_Url.of(s))
        );
    }

    public TS_FilePdfSignSslCfg(Path keyStorePath, CharSequence keyStorePass) {
        this(keyStorePath, keyStorePass, null);//"https://freetsa.org/tsr";
    }

    public TS_FilePdfSignSslCfg(Path keyStorePath, CharSequence keyStorePass, TGS_Url tsa) {
        this.keyStorePath = keyStorePath;
        this.keyStorePass = keyStorePass.toString();
        this.tsa = tsa;
        var fn = keyStorePath.getFileName().toString().toLowerCase(Locale.ROOT);
        if (fn.endsWith(".p12")) {
            keyType = "PKCS12";
        } else if (fn.endsWith(".jks")) {
            keyType = "JKS";
        }
    }
    private Path keyStorePath;
    private String keyStorePass, keyType = null;
    private TGS_Url tsa;

    public Path getKeyStorePath() {
        return keyStorePath;
    }

    public String getKeyStorePass() {
        return keyStorePass;
    }

    public TGS_Url getTsa() {
        return tsa;
    }

    public String getType() {
        return keyType;
    }

    @Override
    public String toString() {
        return TS_FilePdfSignSslCfg.class.getSimpleName() + "{" + "keyStorePath=" + keyStorePath + ", keyStorePass=" + keyStorePass + ", tsa=" + tsa + ", keyType=" + keyType + '}';
    }
}
