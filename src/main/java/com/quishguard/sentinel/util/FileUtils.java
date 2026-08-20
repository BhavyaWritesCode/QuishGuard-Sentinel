package com.quishguard.sentinel.util;

import javax.imageio.ImageIO;
import javax.imageio.ImageReader;
import javax.imageio.stream.ImageInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;

public class FileUtils {

    private FileUtils() {}

    private static final long MAX_IMAGE_PIXELS = 100_000_000L;

    public static int[] getImageDimensions(InputStream inputStream) throws IOException {
        try (ImageInputStream iis = ImageIO.createImageInputStream(inputStream)) {
            if (iis == null) {
                throw new IOException("Cannot read image stream");
            }
            Iterator<ImageReader> readers = ImageIO.getImageReaders(iis);
            if (!readers.hasNext()) {
                throw new IOException("No reader found for image format");
            }
            ImageReader reader = readers.next();
            try {
                reader.setInput(iis);
                int width = reader.getWidth(0);
                int height = reader.getHeight(0);
                return new int[]{width, height};
            } finally {
                reader.dispose();
            }
        }
    }

    public static boolean isImageBomb(int width, int height) {
        return (long) width * height > MAX_IMAGE_PIXELS;
    }
}