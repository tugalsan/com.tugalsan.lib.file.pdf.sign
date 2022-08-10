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
import com.tugalsan.api.unsafe.client.*;

public class TS_FilePdfSignUtils extends CreateSignatureBase {

    final private static TS_Log d = TS_Log.of(true, TS_FilePdfSignUtils.class.getSimpleName());

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
            signer.setExternalSigning(cfg.getTsaURL() == null);
            return signer;
        });
    }

    public static Path getSignedPdfPath(Path rawPdf) {
        var label = TS_FileUtils.getNameLabel(rawPdf);
        return rawPdf.resolveSibling(label + "_signed.pdf");
    }

    public static Path signIfNotSignedBefore(Path keyStore, String keyPass, Path rawPdf, CharSequence signName, CharSequence signLoc, CharSequence signReason) {
        d.ci("signIfNotSignedBefore", "redirect");
        System.err.print("**********************");
        System.out.print("----------------------");
        return signIfNotSignedBefore(
                new TS_FilePdfSignSslCfg(keyStore, keyPass),
                rawPdf, signName, signLoc, signReason
        );
    }

    public static boolean preCleanup(Path rawPdf) {
        var output = getSignedPdfPath(rawPdf);
        TS_FileUtils.deleteFileIfExists(output);
        if (TS_FileUtils.isExistFile(output)) {
            d.ce("preCleanup", "cannot clean", output);
            return false;
        }
        return true;
    }

    public static Path signIfNotSignedBefore(TS_FilePdfSignSslCfg cfg, Path rawPdf, CharSequence signName, CharSequence signLoc, CharSequence signReason) {
        d.ci("signIfNotSignedBefore", "init", cfg);
        if (preCleanup(rawPdf)) {
            return null;
        }
        d.ci("signIfNotSignedBefore", "after-preCleanup");
        var output = getSignedPdfPath(rawPdf);
        d.ci("signIfNotSignedBefore", "output", output);
        return TGS_UnSafe.compile(() -> {
            var result = toSigner(cfg).signIfNotSignedBefore(rawPdf, output, cfg.getTsaURL(), signName, signLoc, signReason);
            d.ci("signIfNotSignedBefore", "result", result);
            if (!result) {
                d.ce("signIfNotSignedBefore", "result is false", "CLEANNING GARBAGE FILE");
                TS_FileUtils.deleteFileIfExists(output);
                return null;
            }
            if (TS_FileUtils.isExistFile(output) && TS_FileUtils.isEmptyFile(output)) {
                d.ce("signIfNotSignedBefore", "result is false", "CLEANNING GARBAGE IS EMPTY FILE");
                d.ce("signIfNotSignedBefore", "result is empty");
                TS_FileUtils.deleteFileIfExists(output);
                return null;
            }
            d.ci("signIfNotSignedBefore", "returning");
            return output;
        }, e -> {
            TS_FileUtils.deleteFileIfExists(output);
            d.ce("signIfNotSignedBefore", e.getMessage());
            return TGS_UnSafe.catchMeIfUCanReturns(e);
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
