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
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.io.InputStream;
import java.util.*;

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

        for (double scale : SCALES) {
            BufferedImage scaled = scale == 1.0 ? original :
                    Scalr.resize(original, Scalr.Method.QUALITY,
                            (int) (original.getWidth() * scale),
                            (int) (original.getHeight() * scale));

            Mat mat = toMat(scaled);
            try {
                Mat preprocessed = preprocess(mat);
                try {
                    decodeAllRotations(preprocessed, urls);
                } finally {
                    preprocessed.release();
                }
            } finally {
                mat.release();
            }
        }

        log.debug("Extracted {} unique URLs from image", urls.size());
        return new ArrayList<>(urls);
    }

    private void decodeAllRotations(Mat mat, Set<String> urls) {
        urls.addAll(decode(toBufferedImage(mat)));

        Mat r90 = new Mat();
        rotate(mat, r90, ROTATE_90_CLOCKWISE);
        try { urls.addAll(decode(toBufferedImage(r90))); } finally { r90.release(); }

        Mat r180 = new Mat();
        rotate(mat, r180, ROTATE_180);
        try { urls.addAll(decode(toBufferedImage(r180))); } finally { r180.release(); }

        Mat r270 = new Mat();
        rotate(mat, r270, ROTATE_90_COUNTERCLOCKWISE);
        try { urls.addAll(decode(toBufferedImage(r270))); } finally { r270.release(); }
    }

    private Mat preprocess(Mat input) {
        Mat gray = new Mat();
        if (input.channels() == 1) {
            gray = input.clone();
        } else {
            cvtColor(input, gray, COLOR_BGR2GRAY);
        }

        Mat thresholded = new Mat();
        adaptiveThreshold(gray, thresholded, 255,
                ADAPTIVE_THRESH_GAUSSIAN_C, THRESH_BINARY, 11, 2);
        gray.release();

        Mat normalized = new Mat();
        normalize(thresholded, normalized, 0, 255, NORM_MINMAX, -1, null);
        thresholded.release();

        return normalized;
    }

    private List<String> decode(BufferedImage image) {
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

    private Mat toMat(BufferedImage image) {
        Java2DFrameConverter j2d = new Java2DFrameConverter();
        OpenCVFrameConverter.ToMat mat = new OpenCVFrameConverter.ToMat();
        return mat.convert(j2d.convert(image));
    }

    private BufferedImage toBufferedImage(Mat mat) {
        Java2DFrameConverter j2d = new Java2DFrameConverter();
        OpenCVFrameConverter.ToMat converter = new OpenCVFrameConverter.ToMat();
        return j2d.convert(converter.convert(mat));
    }
}