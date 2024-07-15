package com.tugalsan.lib.file.pdf.sign.server;

import java.nio.file.Path;
import org.apache.pdfbox.*;
import com.tugalsan.api.file.server.*;
import com.tugalsan.api.list.client.TGS_ListUtils;
import com.tugalsan.api.log.server.*;
import com.tugalsan.api.os.server.TS_OsProcess;
import com.tugalsan.api.union.client.TGS_UnionExcuse;
import com.tugalsan.api.unsafe.client.*;
import java.io.File;
import java.util.List;

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

    public static TGS_UnionExcuse<Boolean> isSignedBefore(Path pdf) {
        return TGS_UnSafe.call(() -> {
            try (var doc = Loader.loadPDF(pdf.toFile())) {
                return TGS_UnionExcuse.of(!doc.getSignatureDictionaries().isEmpty());
            }
        }, e -> TGS_UnionExcuse.ofExcuse(e));
    }

    public static TGS_UnionExcuse<Path> sign(Path driver, TS_FilePdfSignCfgSsl cfgSssl, TS_FilePdfSignCfgDesc cfgDesc, Path pdfInput) {
        var outputPdf = getSignedPdfPath(pdfInput);
        d.ci("sign", "outputPdf", outputPdf);
        return TGS_UnSafe.call(() -> {
            d.ci("sign", "cfgSssl", cfgSssl);
            d.ci("sign", "cfgDesc", cfgDesc);
            d.ci("sign", "rawPdf", pdfInput);
            //CHECK IN-FILE
            if (pdfInput == null || !TS_FileUtils.isExistFile(pdfInput)) {
                return TGS_UnionExcuse.ofExcuse(d.className, "sign", "input file not exists-" + pdfInput);
            }
            if (TS_FileUtils.isEmptyFile(pdfInput)) {
                return TGS_UnionExcuse.ofExcuse(d.className, "sign", "input file is empty-" + pdfInput);
            }
            var u_signedBefore = isSignedBefore(pdfInput);
            if (u_signedBefore.isExcuse()) {
                return u_signedBefore.toExcuse();
            }
            if (u_signedBefore.value()) {
                return TGS_UnionExcuse.ofExcuse(d.className, "sign", "input file signed before-" + pdfInput);
            }
            //CHECK OUT-FILE
            TS_FileUtils.deleteFileIfExists(outputPdf);
            if (TS_FileUtils.isExistFile(outputPdf)) {
                return TGS_UnionExcuse.ofExcuse(d.className, "sign", "output file cleanup error-" + outputPdf);
            }
            //SIGN
            var options = TGS_ListUtils.of(
                    "\"" + pdfInput.toAbsolutePath().toString() + "\"",
                    "-kst", cfgSssl.keyType(),
                    "-ksf", "\"" + cfgSssl.keyStorePath() + "\"",
                    "-ksp", cfgSssl.keyStorePass(),
                    "--contact", cfgDesc.contact(),
                    "--reason", cfgDesc.reason(),
                    "--location", cfgDesc.place()
            );
            if (cfgSssl.tsa() != null) {
                options.add("--tsa-server-url");
                options.add(cfgSssl.tsa().toString());
            }
            var cmd = TS_OsProcess.constructJarExecuterString_console_preview(driver.toAbsolutePath().toString(), options);
            d.cr("sign", "cmd", cmd);
            var p = TS_OsProcess.of(cmd);
            //CHECK OUT-FILE
            if (TS_FileUtils.isExistFile(outputPdf)) {
                d.ce("sign", "cmd", p.toString());
                return TGS_UnionExcuse.ofExcuse(d.className, "sign", "output file not created-" + outputPdf);
            }
            if (TS_FileUtils.isEmptyFile(outputPdf)) {
                d.ce("sign", "cmd", p.toString());
                TS_FileUtils.deleteFileIfExists(outputPdf);
                return TGS_UnionExcuse.ofExcuse(d.className, "sign", "output file is empty-" + outputPdf);
            }
            //RETURN
            d.cr("sign", "returning outputPdf", outputPdf);
            return TGS_UnionExcuse.of(outputPdf);
        }, e -> {
            //HANDLE EXCEPTION
            d.ce("sign", "HANDLE EXCEPTION...");
            TS_FileUtils.deleteFileIfExists(outputPdf);
            return TGS_UnionExcuse.ofExcuse(e);
        });
    }
}
