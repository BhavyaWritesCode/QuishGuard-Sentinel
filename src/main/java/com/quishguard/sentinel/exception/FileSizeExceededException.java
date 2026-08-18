package com.quishguard.sentinel.exception;

public class FileSizeExceededException extends FileValidationException {

    public FileSizeExceededException(long maxBytes) {
        super("File size exceeds the " + (maxBytes / 1024 / 1024) + "MB limit.");
    }
}