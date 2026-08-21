package com.quishguard.sentinel.pipeline;

import com.google.zxing.*;
import com.google.zxing.client.j2se.BufferedImageLuminanceSource;
import com.google.zxing.common.HybridBinarizer;
import com.google.zxing.multi.GenericMultipleBarcodeReader;
import com.google.zxing.qrcode.QRCodeReader;
import org.bytedeco.javacv.Java2DFrameConverter;
import org.bytedeco.javacv.OpenCVFrameConverter;
import org.bytedeco.opencv.opencv_core.Mat;
import org.imgscalr.Scalr;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.imageio.ImageIO;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.io.InputStream;
import java.util.*;
import java.util.List;

import static org.bytedeco.opencv.global.opencv_core.*;
import static org.bytedeco.opencv.global.opencv_imgproc.*;

@Service
public class QrPipelineService {

    private static final Logger log = LoggerFactory.getLogger(QrPipelineService.class);
    private static final int MAX_DIMENSION = 4000;
    private static final double[] SCALES = {0.75, 1.0, 1.5, 2.0};

    public List<String> extractUrls(InputStream inputStream) throws IOException {
        BufferedImage original = ImageIO.read(inputStream);
        if (original == null) {
            throw new IOException("Cannot read image");
        }

        original = capDimension(original);
        Set<String> urls = new LinkedHashSet<>();

        // Strategy 0 — pure Java, no OpenCV
        // ZXing decodes directly from BufferedImage — handles colored QR codes well
        urls.addAll(decodeAllRotationsJava(original));
        if (!urls.isEmpty()) {
            log.debug("Strategy 0 (pure Java) found {} URLs", urls.size());
            return new ArrayList<>(urls);
        }

        // Strategy 1 — grayscale conversion + direct decode
        BufferedImage grayscale = toGrayscale(original);
        urls.addAll(decodeAllRotationsJava(grayscale));
        if (!urls.isEmpty()) {
            log.debug("Strategy 1 (grayscale) found {} URLs", urls.size());
            return new ArrayList<>(urls);
        }

        // Strategy 2 — inverted image
        BufferedImage inverted = invertImage(original);
        urls.addAll(decodeAllRotationsJava(inverted));
        if (!urls.isEmpty()) {
            log.debug("Strategy 2 (inverted) found {} URLs", urls.size());
            return new ArrayList<>(urls);
        }

        // Strategy 3 — multi-scale with OpenCV preprocessing
        for (double scale : SCALES) {
            BufferedImage scaled = scale == 1.0 ? original :
                    Scalr.resize(original, Scalr.Method.QUALITY,
                            (int) (original.getWidth() * scale),
                            (int) (original.getHeight() * scale));

            Java2DFrameConverter j2d = new Java2DFrameConverter();
            OpenCVFrameConverter.ToMat matConverter = new OpenCVFrameConverter.ToMat();
            Mat mat = matConverter.convert(j2d.convert(scaled));
            if (mat == null) {
                j2d.close();
                matConverter.close();
                continue;
            }
            try {
                Mat preprocessed = preprocess(mat);
                try {
                    decodeAllRotations(preprocessed, urls);
                } finally {
                    preprocessed.release();
                }
            } finally {
                mat.release();
                j2d.close();
                matConverter.close();
            }
        }

        // Strategy 4 — histogram equalization via OpenCV
        Java2DFrameConverter j2d = new Java2DFrameConverter();
        OpenCVFrameConverter.ToMat matConverter = new OpenCVFrameConverter.ToMat();
        Mat tempForEq = matConverter.convert(j2d.convert(original));
        if (tempForEq != null) {
            Mat gray2 = new Mat();
            Mat equalized = new Mat();
            try {
                cvtColor(tempForEq, gray2, COLOR_BGR2GRAY);
                equalizeHist(gray2, equalized);
                decodeAllRotations(equalized, urls);
            } finally {
                tempForEq.release();
                gray2.release();
                equalized.release();
                j2d.close();
                matConverter.close();
            }
        }

        log.debug("Extracted {} unique URLs from image", urls.size());
        return new ArrayList<>(urls);
    }

    // Pure Java rotations — no OpenCV dependency
    private List<String> decodeAllRotationsJava(BufferedImage image) {
        List<String> results = new ArrayList<>();
        results.addAll(decode(image));
        results.addAll(decode(rotateImage(image, 90)));
        results.addAll(decode(rotateImage(image, 180)));
        results.addAll(decode(rotateImage(image, 270)));
        return results;
    }

    private BufferedImage rotateImage(BufferedImage src, int degrees) {
        int w = src.getWidth();
        int h = src.getHeight();
        BufferedImage dst = new BufferedImage(
                degrees == 180 ? w : h,
                degrees == 180 ? h : w,
                BufferedImage.TYPE_INT_ARGB
        );
        Graphics2D g2 = dst.createGraphics();
        switch (degrees) {
            case 90  -> { g2.translate(h, 0); g2.rotate(Math.toRadians(90)); }
            case 180 -> { g2.translate(w, h); g2.rotate(Math.toRadians(180)); }
            case 270 -> { g2.translate(0, w); g2.rotate(Math.toRadians(270)); }
        }
        g2.drawImage(src, 0, 0, null);
        g2.dispose();
        return dst;
    }

    private BufferedImage toGrayscale(BufferedImage src) {
        BufferedImage gray = new BufferedImage(
                src.getWidth(), src.getHeight(), BufferedImage.TYPE_BYTE_GRAY);
        Graphics2D g2 = gray.createGraphics();
        g2.drawImage(src, 0, 0, null);
        g2.dispose();
        return gray;
    }

    private BufferedImage invertImage(BufferedImage src) {
        BufferedImage inverted = new BufferedImage(
                src.getWidth(), src.getHeight(), BufferedImage.TYPE_INT_RGB);
        for (int x = 0; x < src.getWidth(); x++) {
            for (int y = 0; y < src.getHeight(); y++) {
                int rgba = src.getRGB(x, y);
                int r = 255 - ((rgba >> 16) & 0xFF);
                int g = 255 - ((rgba >> 8) & 0xFF);
                int b = 255 - (rgba & 0xFF);
                inverted.setRGB(x, y, (r << 16) | (g << 8) | b);
            }
        }
        return inverted;
    }

    private void decodeAllRotations(Mat mat, Set<String> urls) {
        Java2DFrameConverter j2d = new Java2DFrameConverter();
        OpenCVFrameConverter.ToMat converter = new OpenCVFrameConverter.ToMat();
        try {
            urls.addAll(decode(j2d.convert(converter.convert(mat))));

            Mat r90 = new Mat();
            rotate(mat, r90, ROTATE_90_CLOCKWISE);
            try { urls.addAll(decode(j2d.convert(converter.convert(r90)))); }
            finally { r90.release(); }

            Mat r180 = new Mat();
            rotate(mat, r180, ROTATE_180);
            try { urls.addAll(decode(j2d.convert(converter.convert(r180)))); }
            finally { r180.release(); }

            Mat r270 = new Mat();
            rotate(mat, r270, ROTATE_90_COUNTERCLOCKWISE);
            try { urls.addAll(decode(j2d.convert(converter.convert(r270)))); }
            finally { r270.release(); }
        } finally {
            j2d.close();
            converter.close();
        }
    }

    private Mat preprocess(Mat input) {
        Mat gray;
        if (input.channels() == 1) {
            gray = input.clone();
        } else {
            gray = new Mat();
            cvtColor(input, gray, COLOR_BGR2GRAY);
        }

        Mat enhanced = new Mat();
        equalizeHist(gray, enhanced);
        gray.release();

        Mat thresholded = new Mat();
        adaptiveThreshold(enhanced, thresholded, 255,
                ADAPTIVE_THRESH_GAUSSIAN_C, THRESH_BINARY, 11, 2);
        enhanced.release();

        Mat normalized = new Mat();
        normalize(thresholded, normalized, 0, 255, NORM_MINMAX, -1, null);
        thresholded.release();

        return normalized;
    }

    private List<String> decode(BufferedImage image) {
        if (image == null) return Collections.emptyList();
        try {
            Map<DecodeHintType, Object> hints = new EnumMap<>(DecodeHintType.class);
            hints.put(DecodeHintType.ALSO_INVERTED, Boolean.TRUE);
            hints.put(DecodeHintType.TRY_HARDER, Boolean.TRUE);

            BinaryBitmap bitmap = new BinaryBitmap(
                    new HybridBinarizer(new BufferedImageLuminanceSource(image))
            );

            GenericMultipleBarcodeReader reader =
                    new GenericMultipleBarcodeReader(new QRCodeReader());

            Result[] results = reader.decodeMultiple(bitmap, hints);
            List<String> found = new ArrayList<>();
            for (Result result : results) {
                if (result.getText() != null && !result.getText().isBlank()) {
                    found.add(result.getText().trim());
                }
            }
            return found;
        } catch (NotFoundException e) {
            return Collections.emptyList();
        }
    }

    private BufferedImage capDimension(BufferedImage image) {
        if (image.getWidth() <= MAX_DIMENSION && image.getHeight() <= MAX_DIMENSION) {
            return image;
        }
        return Scalr.resize(image, Scalr.Method.QUALITY, MAX_DIMENSION);
    }
}