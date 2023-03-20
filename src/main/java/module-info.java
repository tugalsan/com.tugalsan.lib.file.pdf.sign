module com.tugalsan.api.file.pdf.sign {
    requires pdfbox;
    requires pdfbox.examples;
    requires com.tugalsan.api.file;
    requires com.tugalsan.api.url;
    requires com.tugalsan.api.stream;
    requires com.tugalsan.api.compiler;
    requires com.tugalsan.api.unsafe;
    requires com.tugalsan.api.charset;
    requires com.tugalsan.api.log;
    exports com.tugalsan.api.file.pdf.sign.server;
}
