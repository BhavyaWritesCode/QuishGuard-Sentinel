package com.quishguard.sentinel.exception;

public class UnsupportedFileTypeException extends FileValidationException {

    public UnsupportedFileTypeException(String detectedMimeType) {
        super("Unsupported file type: " + detectedMimeType + ". Allowed: JPG, PNG, WEBP, BMP, TIFF, PDF.");
    }
}