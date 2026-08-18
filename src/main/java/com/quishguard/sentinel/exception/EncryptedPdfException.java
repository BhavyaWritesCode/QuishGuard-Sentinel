package com.quishguard.sentinel.exception;

public class EncryptedPdfException extends FileValidationException {

    public EncryptedPdfException() {
        super("Encrypted PDFs are not supported. Please remove password protection and try again.");
    }
}