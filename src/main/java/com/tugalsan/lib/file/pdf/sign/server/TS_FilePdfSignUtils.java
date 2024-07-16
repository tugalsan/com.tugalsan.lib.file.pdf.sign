package com.tugalsan.lib.file.pdf.sign.server;

import com.tugalsan.api.file.properties.server.TS_FilePropertiesUtils;
import java.nio.file.Path;
import org.apache.pdfbox.*;
import com.tugalsan.api.file.server.*;
import com.tugalsan.api.log.server.*;
import com.tugalsan.api.os.server.TS_OsJavaUtils;
import com.tugalsan.api.os.server.TS_OsProcess;
import com.tugalsan.api.union.client.TGS_UnionExcuse;
import com.tugalsan.api.unsafe.client.*;
import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.stream.Collectors;

public class TS_FilePdfSignUtils {

    final private static TS_Log d = TS_Log.of(true, TS_FilePdfSignUtils.class);

    public static Path getPossibleDriverPath() {
        return List.of(File.listRoots()).stream()
                .map(p -> Path.of(p.toString()))
                .map(p -> p.resolve("bin"))
                .map(p -> p.resolve("com.tugalsan.dsk.pdf.sign"))
                .map(p -> p.resolve("home"))
                .map(p -> p.resolve("target"))
                .map(p -> p.resolve("com.tugalsan.dsk.pdf.sign-1.0-SNAPSHOT-jar-with-dependencies.jar"))
                .filter(p -> TS_FileUtils.isExistFile(p))
                .findAny().orElse(null);
    }

    public static Path getSignedPdfPath(Path rawPdf) {
        var label = TS_FileUtils.getNameLabel(rawPdf);
        return rawPdf.resolveSibling(label + "_signed.pdf");
    }

    public static Path getConfigPdfPath(Path rawPdf) {
//        var label = TS_FileUtils.getNameLabel(rawPdf);
        return rawPdf.resolveSibling("config.properties");
    }

    @Deprecated //NOT WORKING!
    public static TGS_UnionExcuse<Boolean> isSignedBefore(Path pdf) {
        return TGS_UnSafe.call(() -> {
            try (var doc = Loader.loadPDF(pdf.toFile())) {
                return TGS_UnionExcuse.of(!doc.getSignatureDictionaries().isEmpty());
            }
        }, e -> TGS_UnionExcuse.ofExcuse(e));
    }

    public static Properties config(TS_FilePdfSignCfgSsl cfgSssl, TS_FilePdfSignCfgDesc cfgDesc, Path pdfInput) {
        var props = new Properties();
        props.setProperty("certification.level", "NOT_CERTIFIED");
        props.setProperty("enc.home", System.getProperty("user.home"));
        props.setProperty("enc.keyPwd", cfgSssl.keyStorePass());
        props.setProperty("enc.keystorePwd", cfgSssl.keyStorePass());
        props.setProperty("inpdf.file", pdfInput.toAbsolutePath().toString());
        props.setProperty("outpdf.file", getSignedPdfPath(pdfInput).toAbsolutePath().toString());
        props.setProperty("keystore.file", cfgSssl.keyStorePath().toAbsolutePath().toString());
        props.setProperty("keystore.type", cfgSssl.keyType());
        props.setProperty("keystore.alias", "myallias");
        props.setProperty("keystore.keyIndex", "0");
        props.setProperty("hash.algorithm", "SHA512");
        props.setProperty("ocsp.enabled", "false");
        props.setProperty("pdf.encryption", "NONE");
        props.setProperty("signature.contact", cfgDesc.contact());
        props.setProperty("signature.reason", cfgDesc.reason());
        props.setProperty("signature.location", cfgDesc.place());
        props.setProperty("store.passwords", "true");
        props.setProperty("tsa.enabled", "true");
        props.setProperty("tsa.serverAuthn", "NONE");
        props.setProperty("tsa.url", cfgSssl.tsa().toString());
        return props;
    }

    public static TGS_UnionExcuse<Path> sign(Path driver, TS_FilePdfSignCfgSsl cfgSssl, TS_FilePdfSignCfgDesc cfgDesc, Path pdfInput) {
        return TGS_UnSafe.call(() -> {
             d.ci("sign", "pdfInput", pdfInput);
            //CREATE TMP-INPUT BY MAIN-INPUT
            var tmp = Files.createTempDirectory("tmp").toAbsolutePath();
            var _pdfInput = tmp.resolve("_pdfInput.pdf");
            TS_FileUtils.copyAs(pdfInput, _pdfInput, true);

            //IF SINGED, COPY TMP-OUTPUT TO MAIN-OUTPUT
            var u = _sign(driver, cfgSssl, cfgDesc, _pdfInput);
            if (u.isExcuse()) {
                return u.toExcuse();
            }
            var pdfOutput = getSignedPdfPath(pdfInput);
            TS_FileUtils.copyAs(u.value(), pdfOutput, true);

            return TGS_UnionExcuse.of(pdfOutput);
        }, e -> TGS_UnionExcuse.ofExcuse(e));
    }

    private static TGS_UnionExcuse<Path> _sign(Path driver, TS_FilePdfSignCfgSsl cfgSssl, TS_FilePdfSignCfgDesc cfgDesc, Path pdfInput) {
        var outputPdf = getSignedPdfPath(pdfInput);
        d.ci("_sign", "outputPdf", outputPdf);
        var configPdf = getConfigPdfPath(pdfInput);
        d.ci("_sign", "configPdf", configPdf);
        TS_FilePropertiesUtils.write(config(cfgSssl, cfgDesc, pdfInput), configPdf);
        return TGS_UnSafe.call(() -> {
            d.ci("_sign", "cfgSssl", cfgSssl);
            d.ci("_sign", "cfgDesc", cfgDesc);
            d.ci("_sign", "rawPdf", pdfInput);
            //CHECK IN-FILE
            if (pdfInput == null || !TS_FileUtils.isExistFile(pdfInput)) {
                return TGS_UnionExcuse.ofExcuse(d.className, "_sign", "input file not exists-" + pdfInput);
            }
            if (TS_FileUtils.isEmptyFile(pdfInput)) {
                return TGS_UnionExcuse.ofExcuse(d.className, "_sign", "input file is empty-" + pdfInput);
            }
//            var u_signedBefore = isSignedBefore(pdfInput);
//            if (u_signedBefore.isExcuse()) {
//                return u_signedBefore.toExcuse();
//            }
//            if (u_signedBefore.value()) {
//                return TGS_UnionExcuse.ofExcuse(d.className, "_sign", "input file signed before-" + pdfInput);
//            }
            //CHECK OUT-FILE
            TS_FileUtils.deleteFileIfExists(outputPdf);
            if (TS_FileUtils.isExistFile(outputPdf)) {
                return TGS_UnionExcuse.ofExcuse(d.className, "_sign", "output file cleanup error-" + outputPdf);
            }
            //SIGN
            List<String> args = new ArrayList();
            args.add("\"" + TS_OsJavaUtils.getPathJava().resolveSibling("java.exe") + "\"");
            args.add("-jar");
            args.add("\"" + driver.toAbsolutePath().toString() + "\"");
            args.add("--load-properties-file");
            args.add("\"" + configPdf.toAbsolutePath().toString() + "\"");
            d.cr("_sign", "args", args);
            var cmd = args.stream().collect(Collectors.joining(" "));
            d.cr("_sign", "cmd", cmd);
            var p = TS_OsProcess.of(args);
            //CHECK OUT-FILE
            if (!TS_FileUtils.isExistFile(outputPdf)) {
                d.ce("_sign", "cmd", p.toString());
                return TGS_UnionExcuse.ofExcuse(d.className, "_sign", "output file not created-" + outputPdf);
            }
            if (TS_FileUtils.isEmptyFile(outputPdf)) {
                d.ce("_sign", "cmd", p.toString());
                TS_FileUtils.deleteFileIfExists(outputPdf);
                return TGS_UnionExcuse.ofExcuse(d.className, "_sign", "output file is empty-" + outputPdf);
            }
            //RETURN
            d.cr("_sign", "returning outputPdf", outputPdf);
            return TGS_UnionExcuse.of(outputPdf);
        }, e -> {
            //HANDLE EXCEPTION
            d.ce("_sign", "HANDLE EXCEPTION...");
            TS_FileUtils.deleteFileIfExists(outputPdf);
            return TGS_UnionExcuse.ofExcuse(e);
        }, () -> TS_FileUtils.deleteFileIfExists(configPdf));
    }
}
