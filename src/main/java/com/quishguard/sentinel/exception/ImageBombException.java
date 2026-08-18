package com.quishguard.sentinel.exception;

public class ImageBombException extends FileValidationException {

    public ImageBombException(int width, int height) {
        super("Image dimensions too large: " + width + "x" + height + "px. Possible image bomb detected.");
    }
}