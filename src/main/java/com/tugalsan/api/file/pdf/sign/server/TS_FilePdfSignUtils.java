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
import com.tugalsan.api.union.client.TGS_UnionExcuse;
import com.tugalsan.api.union.client.TGS_UnionExcuseVoid;
import com.tugalsan.api.url.client.TGS_Url;
import java.util.List;

public class TS_FilePdfSignUtils extends CreateSignatureBase {

    final private static TS_Log d = TS_Log.of(TS_FilePdfSignUtils.class);

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

    private static TGS_UnionExcuse<KeyStore> toKeyStore(TS_FilePdfSignSslCfg cfg) {
        try {
            var keystore = KeyStore.getInstance(cfg.getType());
            try (var is = Files.newInputStream(cfg.getKeyStorePath())) {
                keystore.load(is, cfg.getKeyStorePass().toCharArray());
            }
            return TGS_UnionExcuse.of(keystore);
        } catch (IOException | NoSuchAlgorithmException | CertificateException | KeyStoreException ex) {
            return TGS_UnionExcuse.ofExcuse(ex);
        }
    }

    private static TGS_UnionExcuse<TS_FilePdfSignUtils> toSigner(TS_FilePdfSignSslCfg cfg) {
        try {
            var u_keyStore = toKeyStore(cfg);
            if (u_keyStore.isExcuse()) {
                return u_keyStore.toExcuse();
            }
            var signer = new TS_FilePdfSignUtils(u_keyStore.value(), cfg.getKeyStorePass().toCharArray());
            signer.setExternalSigning(cfg.getTsa() == null);
            return TGS_UnionExcuse.of(signer);
        } catch (KeyStoreException | UnrecoverableKeyException | NoSuchAlgorithmException | CertificateException | IOException ex) {
            return TGS_UnionExcuse.ofExcuse(ex);
        }
    }

    public static Path getSignedPdfPath(Path rawPdf) {
        var label = TS_FileUtils.getNameLabel(rawPdf);
        return rawPdf.resolveSibling(label + "_signed.pdf");
    }

    public static TGS_UnionExcuse<Path> signIfNotSignedBefore(Path keyStore, String keyPass, Path rawPdf, CharSequence signName, CharSequence signLoc, CharSequence signReason) {
        return signIfNotSignedBefore(
                new TS_FilePdfSignSslCfg(keyStore, keyPass),
                rawPdf, signName, signLoc, signReason
        );
    }

    public static TGS_UnionExcuseVoid preCleanup(Path rawPdf) {
        d.ci("preCleanup", "rawPdf", rawPdf);
        var output = getSignedPdfPath(rawPdf);
        d.ci("preCleanup", "output", output);
        var u_deleteFileIfExists = TS_FileUtils.deleteFileIfExists(output);
        if (u_deleteFileIfExists.isExcuse()) {
            return u_deleteFileIfExists;
        }
        d.ci("preCleanup", "supposed to be cleaned");
        if (TS_FileUtils.isExistFile(output)) {
            return TGS_UnionExcuseVoid.ofExcuse(d.className, "preCleanup", "cannot clean " + output);
        }
        d.ci("preCleanup", "cleanning successfull");
        return TGS_UnionExcuseVoid.ofVoid();
    }

    public static TGS_UnionExcuse<Path> signIfNotSignedBefore(TS_FilePdfSignSslCfg cfg, Path rawPdf, CharSequence signName, CharSequence signLoc, CharSequence signReason) {
        d.ci("signIfNotSignedBefore", "init", cfg);
        var u_preCleanup = preCleanup(rawPdf);
        if (u_preCleanup.isExcuse()) {
            return u_preCleanup.toExcuse();
        }
        d.ci("signIfNotSignedBefore", "after-preCleanup");
        var outputPdf = getSignedPdfPath(rawPdf);
        d.ci("signIfNotSignedBefore", "outputPdf", outputPdf);
        var u_signer = toSigner(cfg);
        if (u_signer.isExcuse()) {
            return u_signer.toExcuse();
        }
        var result = u_signer.value().signIfNotSignedBefore(rawPdf, outputPdf, cfg.getTsa() == null ? null : cfg.getTsa().toString(), signName, signLoc, signReason);
        d.ci("signIfNotSignedBefore", "result", result);
        if (result.isExcuse()) {
            return result.toExcuse();
        }
        if (TS_FileUtils.isExistFile(outputPdf)) {
            d.ce("signIfNotSignedBefore", "result is false", "CLEANNING GARBAGE FILE");
            TS_FileUtils.deleteFileIfExists(outputPdf);
            return TGS_UnionExcuse.ofExcuse(d.className, "signIfNotSignedBefore", "signed file is not exists");
        }
        var u_isEmpty = TS_FileUtils.isEmptyFile(outputPdf);
        if (u_isEmpty.isExcuse()) {
            TS_FileUtils.deleteFileIfExists(outputPdf);
            return u_isEmpty.toExcuse();
        }
        if (u_isEmpty.value()) {
            TS_FileUtils.deleteFileIfExists(outputPdf);
            return TGS_UnionExcuse.ofExcuse(d.className, "signIfNotSignedBefore", "signed file is empty");
        }
        return TGS_UnionExcuse.of(outputPdf);
    }

    public TS_FilePdfSignUtils(KeyStore keystore, char[] pin) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException, CertificateException, IOException {
        super(keystore, pin);
    }

    private TGS_UnionExcuseVoid signIfNotSignedBefore(Path rawPdf, Path output, CharSequence tsaUrl, CharSequence signName, CharSequence signLoc, CharSequence signReason) {
        if (rawPdf == null || !TS_FileUtils.isExistFile(rawPdf)) {
            return TGS_UnionExcuseVoid.ofExcuse(d.className, "signIfNotSignedBefore", "ERROR: source document not exixts: " + rawPdf);
        }
        var u_empty = TS_FileUtils.isEmptyFile(rawPdf);
        if (u_empty.isExcuse()) {
            return u_empty.toExcuseVoid();
        }
        if (u_empty.value()) {
            return TGS_UnionExcuseVoid.ofExcuse(d.className, "signIfNotSignedBefore", "ERROR: source document is empty: " + rawPdf);
        }
        setTsaUrl(tsaUrl == null ? null : tsaUrl.toString());
        try (var fos = Files.newOutputStream(output); var doc = Loader.loadPDF(rawPdf.toFile())) {
            if (!doc.getSignatureDictionaries().isEmpty()) {
                return TGS_UnionExcuseVoid.ofExcuse(d.className, "signIfNotSignedBefore", "SKIP: document is already signed before");
                //WILL CREATE GARBAGE, HANDLE IT
            }
            var u_detach = signDetached(doc, fos, signName.toString(), signLoc.toString(), signReason.toString());
            if (u_detach.isExcuse()) {
                return u_detach;
            }
        } catch (IOException ex) {
            return TGS_UnionExcuseVoid.ofExcuse(ex);
        }
        return TGS_UnionExcuseVoid.ofVoid();
    }

    private TGS_UnionExcuseVoid signDetached(PDDocument document, OutputStream output, CharSequence signName, CharSequence signLoc, CharSequence signReason) {
        try {
            var accessPermissions = SigUtils.getMDPPermission(document);
            if (accessPermissions == 1) {
                return TGS_UnionExcuseVoid.ofExcuse(d.className, "signDetached", "No changes to the document are permitted due to DocMDP transform parameters dictionary");
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
            return TGS_UnionExcuseVoid.ofVoid();
        } catch (IOException ex) {
            return TGS_UnionExcuseVoid.ofExcuse(ex);
        }
    }
}
