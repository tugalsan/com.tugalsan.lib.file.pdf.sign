package com.tugalsan.lib.file.pdf.sign.server;

import com.tugalsan.api.file.properties.server.TS_FilePropertiesUtils;
import java.nio.file.Path;
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

    public static Path pathDriver() {
        var driverPackageName = TS_FilePdfSignUtils.class.getPackageName().replace(".lib.", ".dsk.");
        return List.of(File.listRoots()).stream()
                .map(p -> Path.of(p.toString()))
                .map(p -> p.resolve("bin"))
                .map(p -> p.resolve(driverPackageName))
                .map(p -> p.resolve("home"))
                .map(p -> p.resolve("target"))
                .map(p -> p.resolve(driverPackageName + "-1.0-SNAPSHOT-jar-with-dependencies.jar"))
                .filter(p -> TS_FileUtils.isExistFile(p))
                .findAny().orElse(null);
    }

    public static Path pathOutput(Path rawPdf) {
        var label = TS_FileUtils.getNameLabel(rawPdf);
        return rawPdf.resolveSibling(label + "_executeed.pdf");
    }

    public static Path pathConfig(Path rawPdf) {
        return rawPdf.resolveSibling("config.properties");
    }

    public static Properties makeConfig(TS_FilePdfSignCfgSsl cfgSssl, TS_FilePdfSignCfgDesc cfgDesc, Path pathInput) {
        var props = new Properties();
        props.setProperty("certification.level", "NOT_CERTIFIED");
        props.setProperty("crl.enabled", "false");
        props.setProperty("enc.home", System.getProperty("user.home"));
        props.setProperty("enc.keyPwd", cfgSssl.keyStorePass());
        props.setProperty("enc.keystorePwd", cfgSssl.keyStorePass());
        props.setProperty("hash.algorithm", "SHA512");
        props.setProperty("inpdf.file", pathInput.toAbsolutePath().toString());
        props.setProperty("keystore.alias", "myallias");
        props.setProperty("keystore.file", cfgSssl.keyStorePath().toAbsolutePath().toString());
        props.setProperty("keystore.keyIndex", "0");
        props.setProperty("keystore.type", cfgSssl.keyType());
        props.setProperty("ocsp.enabled", "false");
        props.setProperty("outpdf.file", pathOutput(pathInput).toAbsolutePath().toString());
        props.setProperty("pdf.encryption", "NONE");
        props.setProperty("signature.append", "false");
        props.setProperty("signature.contact", cfgDesc.contact());
        props.setProperty("signature.location", cfgDesc.place());
        props.setProperty("signature.reason", cfgDesc.reason());
        props.setProperty("store.passwords", "true");
        props.setProperty("tsa.enabled", "true");
        props.setProperty("tsa.serverAuthn", "NONE");
        props.setProperty("tsa.url", cfgSssl.tsa().toString());
        return props;
    }

    public static TGS_UnionExcuse<Path> execute(Path driver, TS_FilePdfSignCfgSsl cfgSssl, TS_FilePdfSignCfgDesc cfgDesc, Path pathInput) {
        return TGS_UnSafe.call(() -> {
            d.ci("execute", "pathInput", pathInput);
            //CREATE TMP-INPUT BY MAIN-INPUT
            var tmp = Files.createTempDirectory("tmp").toAbsolutePath();
            var _pathInput = tmp.resolve("_pathInput.pdf");
            TS_FileUtils.copyAs(pathInput, _pathInput, true);

            //IF SINGED, COPY TMP-OUTPUT TO MAIN-OUTPUT
            var u = _execute(driver, cfgSssl, cfgDesc, _pathInput);
            if (u.isExcuse()) {
                return u.toExcuse();
            }
            var pdfOutput = pathOutput(pathInput);
            TS_FileUtils.copyAs(u.value(), pdfOutput, true);

            return TGS_UnionExcuse.of(pdfOutput);
        }, e -> TGS_UnionExcuse.ofExcuse(e));
    }

    private static TGS_UnionExcuse<Path> _execute(Path driver, TS_FilePdfSignCfgSsl cfgSssl, TS_FilePdfSignCfgDesc cfgDesc, Path pathInput) {
        var pathOutput = pathOutput(pathInput);
        d.ci("_execute", "pathOutput", pathOutput);
        var pathConfig = pathConfig(pathInput);
        d.ci("_execute", "pathConfig", pathConfig);
        TS_FilePropertiesUtils.write(makeConfig(cfgSssl, cfgDesc, pathInput), pathConfig);
        return TGS_UnSafe.call(() -> {
            d.ci("_execute", "cfgSssl", cfgSssl);
            d.ci("_execute", "cfgDesc", cfgDesc);
            d.ci("_execute", "rawPdf", pathInput);
            //CHECK IN-FILE
            if (pathInput == null || !TS_FileUtils.isExistFile(pathInput)) {
                return TGS_UnionExcuse.ofExcuse(d.className, "_execute", "pathInput not exists-" + pathInput);
            }
            if (TS_FileUtils.isEmptyFile(pathInput)) {
                return TGS_UnionExcuse.ofExcuse(d.className, "_execute", "pathInput is empty-" + pathInput);
            }
            //CHECK OUT-FILE
            TS_FileUtils.deleteFileIfExists(pathOutput);
            if (TS_FileUtils.isExistFile(pathOutput)) {
                return TGS_UnionExcuse.ofExcuse(d.className, "_execute", "pathOutput cleanup error-" + pathOutput);
            }
            //SIGN
            List<String> args = new ArrayList();
            args.add("\"" + TS_OsJavaUtils.getPathJava().resolveSibling("java.exe") + "\"");
            args.add("-jar");
            args.add("\"" + driver.toAbsolutePath().toString() + "\"");
            args.add("--load-properties-file");
            args.add("\"" + pathConfig.toAbsolutePath().toString() + "\"");
            d.cr("_execute", "args", args);
            var cmd = args.stream().collect(Collectors.joining(" "));
            d.cr("_execute", "cmd", cmd);
            var p = TS_OsProcess.of(args);
            //CHECK OUT-FILE
            if (!TS_FileUtils.isExistFile(pathOutput)) {
                d.ce("_execute", "cmd", p.toString());
                return TGS_UnionExcuse.ofExcuse(d.className, "_execute", "pathOutput not created-" + pathOutput);
            }
            if (TS_FileUtils.isEmptyFile(pathOutput)) {
                d.ce("_execute", "cmd", p.toString());
                TS_FileUtils.deleteFileIfExists(pathOutput);
                return TGS_UnionExcuse.ofExcuse(d.className, "_execute", "pathOutput is empty-" + pathOutput);
            }
            //RETURN
            d.cr("_execute", "returning pathOutput", pathOutput);
            return TGS_UnionExcuse.of(pathOutput);
        }, e -> {
            //HANDLE EXCEPTION
            d.ce("_execute", "HANDLE EXCEPTION...");
            TS_FileUtils.deleteFileIfExists(pathOutput);
            return TGS_UnionExcuse.ofExcuse(e);
        }, () -> TS_FileUtils.deleteFileIfExists(pathConfig));
    }
}
