module com.tugalsan.api.file.pdf.sign {
    requires org.apache.pdfbox;
    requires pdfbox.examples;
    requires com.tugalsan.api.file;
    requires com.tugalsan.api.url;
    requires com.tugalsan.api.stream;
    requires com.tugalsan.api.callable;
    requires com.tugalsan.api.union;
    requires com.tugalsan.api.charset;
    requires com.tugalsan.api.log;
    exports com.tugalsan.api.file.pdf.sign.server;
}
