package com.tugalsan.lib.file.pdf.sign.server;

import com.tugalsan.api.charset.client.TGS_CharSetCast;
import com.tugalsan.api.url.client.TGS_Url;
import java.nio.file.Path;

public record TS_LibFilePdfSignCfgSsl(Path keyStorePath, String keyStorePass, TGS_Url tsa) {

    public static TGS_Url defaultTsa() {
        return TGS_Url.of("https://freetsa.org/tsr");
    }

    public String keyType() {
        var fn = TGS_CharSetCast.current().toLowerCase(keyStorePath.getFileName().toString());
        if (fn.endsWith(".p12")) {
            return "PKCS12";
        } else if (fn.endsWith(".jks")) {
            return "JKS";
        } else {
            return "Unknown";
        }
    }
}
