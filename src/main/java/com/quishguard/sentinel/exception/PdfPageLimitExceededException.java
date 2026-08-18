package com.quishguard.sentinel.exception;

public class PdfPageLimitExceededException extends FileValidationException {

    public PdfPageLimitExceededException(int actualPages) {
        super("PDF exceeds 50 page limit. Found: " + actualPages + " pages.");
    }
}