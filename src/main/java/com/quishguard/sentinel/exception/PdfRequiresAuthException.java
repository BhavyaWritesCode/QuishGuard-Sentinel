package com.quishguard.sentinel.exception;

public class PdfRequiresAuthException extends FileValidationException {

    public PdfRequiresAuthException() {
        super("PDF upload requires authentication. Please log in to scan PDF documents.");
    }
}