module com.tugalsan.lib.file.pdf.sign {
    requires org.apache.pdfbox;
    requires pdfbox.examples;
    requires com.tugalsan.api.file;
    requires com.tugalsan.api.url;
    requires com.tugalsan.api.stream;
    requires com.tugalsan.api.function;
    requires com.tugalsan.api.unsafe;
    requires com.tugalsan.api.list;
    requires com.tugalsan.api.charset;
    requires com.tugalsan.api.os;
    requires com.tugalsan.api.union;
    requires com.tugalsan.api.log;
    exports com.tugalsan.lib.file.pdf.sign.server;
}
