package com.tugalsan.api.file.pdf.sign.server;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Calendar;
import org.apache.pdfbox.*;
import org.apache.pdfbox.examples.signature.CreateSignatureBase;
import org.apache.pdfbox.examples.signature.SigUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import com.tugalsan.api.file.server.*;
import com.tugalsan.api.log.server.*;
import com.tugalsan.api.stream.client.TGS_StreamUtils;
import com.tugalsan.api.unsafe.client.*;
import com.tugalsan.api.url.client.TGS_Url;
import java.util.List;

public class TS_FilePdfSignUtils extends CreateSignatureBase {

    final private static TS_Log d = TS_Log.of(true, TS_FilePdfSignUtils.class);

    public static List<TGS_Url> lstTsa() {
        return TGS_StreamUtils.toLst(
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

    private static KeyStore toKeyStore(TS_FilePdfSignSslCfg cfg) {
        return TGS_UnSafe.compile(() -> {
            var keystore = KeyStore.getInstance(cfg.getType());
            try ( var is = Files.newInputStream(cfg.getKeyStorePath())) {
                keystore.load(is, cfg.getKeyStorePass().toCharArray());
            }
            return keystore;
        });
    }

    private static TS_FilePdfSignUtils toSigner(TS_FilePdfSignSslCfg cfg) {
        return TGS_UnSafe.compile(() -> {
            var signer = new TS_FilePdfSignUtils(toKeyStore(cfg), cfg.getKeyStorePass().toCharArray());
            signer.setExternalSigning(cfg.getTsa() == null);
            return signer;
        });
    }

    public static Path getSignedPdfPath(Path rawPdf) {
        var label = TS_FileUtils.getNameLabel(rawPdf);
        return rawPdf.resolveSibling(label + "_signed.pdf");
    }

    public static Path signIfNotSignedBefore(Path keyStore, String keyPass, Path rawPdf, CharSequence signName, CharSequence signLoc, CharSequence signReason) {
        return signIfNotSignedBefore(
                new TS_FilePdfSignSslCfg(keyStore, keyPass),
                rawPdf, signName, signLoc, signReason
        );
    }

    public static boolean preCleanup(Path rawPdf) {
        d.ci("preCleanup", "rawPdf", rawPdf);
        var output = getSignedPdfPath(rawPdf);
        d.ci("preCleanup", "output", output);
        TS_FileUtils.deleteFileIfExists(output);
        d.ci("preCleanup", "supposed to be cleaned");
        if (TS_FileUtils.isExistFile(output)) {
            d.ce("preCleanup", "cannot clean", output);
            return false;
        }
        d.ci("preCleanup", "cleanning successfull");
        return true;
    }

    public static Path signIfNotSignedBefore(TS_FilePdfSignSslCfg cfg, Path rawPdf, CharSequence signName, CharSequence signLoc, CharSequence signReason) {
        d.ci("signIfNotSignedBefore", "init", cfg);
        if (!preCleanup(rawPdf)) {
            d.ci("signIfNotSignedBefore", "cleanup error", "cannot continue");
            return null;
        }
        d.ci("signIfNotSignedBefore", "after-preCleanup");
        var outputPdf = getSignedPdfPath(rawPdf);
        d.ci("signIfNotSignedBefore", "outputPdf", outputPdf);
        return TGS_UnSafe.compile(() -> {
            var result = toSigner(cfg).signIfNotSignedBefore(rawPdf, outputPdf, cfg.getTsa() == null ? null : cfg.getTsa().toString(), signName, signLoc, signReason);
            d.ci("signIfNotSignedBefore", "result", result);
            if (!result) {
                d.ce("signIfNotSignedBefore", "result is false", "CLEANNING GARBAGE FILE");
                TS_FileUtils.deleteFileIfExists(outputPdf);
                return null;
            }
            if (TS_FileUtils.isExistFile(outputPdf) && TS_FileUtils.isEmptyFile(outputPdf)) {
                d.ce("signIfNotSignedBefore", "result is false", "CLEANNING GARBAGE FILE");
                TS_FileUtils.deleteFileIfExists(outputPdf);
                return null;
            }
            d.ci("signIfNotSignedBefore", "returning");
            return outputPdf;
        }, e -> {
            TS_FileUtils.deleteFileIfExists(outputPdf);
            d.ce("signIfNotSignedBefore", e.getMessage());
//            return TGS_UnSafe.catchMeIfUCanReturns(e);
            return null;
        });
    }

    public TS_FilePdfSignUtils(KeyStore keystore, char[] pin) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException, CertificateException, IOException {
        super(keystore, pin);
    }

    private boolean signIfNotSignedBefore(Path rawPdf, Path output, CharSequence tsaUrl, CharSequence signName, CharSequence signLoc, CharSequence signReason) {
        return TGS_UnSafe.compile(() -> {
            if (rawPdf == null || !TS_FileUtils.isExistFile(rawPdf)) {
                d.ce("signIfNotSignedBefore", "ERROR: source document not exixts", rawPdf);
                return false;
            }
            if (TS_FileUtils.isEmptyFile(rawPdf)) {
                d.ce("signIfNotSignedBefore", "ERROR: source document is empty", rawPdf);
                return false;
            }
            setTsaUrl(tsaUrl == null ? null : tsaUrl.toString());
            try ( var fos = Files.newOutputStream(output);  var doc = Loader.loadPDF(rawPdf.toFile())) {
                if (!doc.getSignatureDictionaries().isEmpty()) {
                    d.ce("signIfNotSignedBefore", "SKIP: document is already signed before");
                    //WILL CREATE GARBAGE, HANDLE IT
                    return false;
                }
                signDetached(doc, fos, signName.toString(), signLoc.toString(), signReason.toString());
                return true;
            }
        });
    }

    private void signDetached(PDDocument document, OutputStream output, CharSequence signName, CharSequence signLoc, CharSequence signReason) {
        TGS_UnSafe.execute(() -> {
            var accessPermissions = SigUtils.getMDPPermission(document);
            if (accessPermissions == 1) {
                TGS_UnSafe.catchMeIfUCan(d.className, "signDetached", "No changes to the document are permitted due to DocMDP transform parameters dictionary");
            }
            var signature = new PDSignature();
            signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
            signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
            signature.setName(signName.toString());
            signature.setLocation(signLoc.toString());
            signature.setReason(signReason.toString());
            signature.setSignDate(Calendar.getInstance());
            if (accessPermissions == 0) {
                SigUtils.setMDPPermission(document, signature, 2);
            }
            if (isExternalSigning()) {
                document.addSignature(signature);
                var externalSigning = document.saveIncrementalForExternalSigning(output);
                var cmsSignature = sign(externalSigning.getContent());
                externalSigning.setSignature(cmsSignature);
            } else {
                var signatureOptions = new SignatureOptions();
                signatureOptions.setPreferredSignatureSize(SignatureOptions.DEFAULT_SIGNATURE_SIZE * 2);
                document.addSignature(signature, this, signatureOptions);
                document.saveIncremental(output);
            }
        });
    }
}
