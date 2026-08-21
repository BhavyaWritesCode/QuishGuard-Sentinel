package com.quishguard.sentinel.service;

import com.quishguard.sentinel.exception.*;
import com.quishguard.sentinel.util.FileUtils;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.encryption.InvalidPasswordException;
import org.apache.tika.Tika;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.Set;

@Service
public class FileValidationService {

    private static final Logger log = LoggerFactory.getLogger(FileValidationService.class);

    private static final Set<String> ALLOWED_MIME_TYPES = Set.of(
            "image/jpeg", "image/png", "image/webp",
            "image/bmp", "image/tiff", "application/pdf"
    );

    private static final int  MAX_PDF_PAGES    = 50;
    private static final long MAX_UPLOAD_BYTES = 50L * 1024 * 1024;

    private final Tika tika = new Tika();

    public enum FileType { IMAGE, PDF }

    public FileType validateAndClassify(MultipartFile file, boolean isAuthenticated) {
        validateSize(file);

        String mimeType = detectMime(file);
        log.debug("Detected MIME: {}", mimeType);

        if (!ALLOWED_MIME_TYPES.contains(mimeType)) {
            throw new UnsupportedFileTypeException(mimeType);
        }

        if ("application/pdf".equals(mimeType)) {
            if (!isAuthenticated) {
                throw new PdfRequiresAuthException();
            }
            validatePdf(file);
            return FileType.PDF;
        }

        validateImage(file);
        return FileType.IMAGE;
    }

    private void validateSize(MultipartFile file) {
        if (file.getSize() > MAX_UPLOAD_BYTES) {
            throw new FileSizeExceededException(MAX_UPLOAD_BYTES);
        }
    }

    private String detectMime(MultipartFile file) {
        try {
            return tika.detect(file.getInputStream());
        } catch (IOException e) {
            throw new FileValidationException("Failed to read file for MIME detection", e);
        }
    }

    private void validatePdf(MultipartFile file) {
        try {
            byte[] bytes = file.getBytes();
            try (PDDocument doc = Loader.loadPDF(bytes)) {
                int pages = doc.getNumberOfPages();
                if (pages > MAX_PDF_PAGES) {
                    throw new PdfPageLimitExceededException(pages);
                }
            }
        } catch (InvalidPasswordException e) {
            throw new EncryptedPdfException();
        } catch (PdfPageLimitExceededException e) {
            throw e;
        } catch (IOException e) {
            throw new FileValidationException("Failed to parse PDF", e);
        }
    }

    private void validateImage(MultipartFile file) {
        try {
            int[] dims = FileUtils.getImageDimensions(file.getInputStream());
            if (FileUtils.isImageBomb(dims[0], dims[1])) {
                throw new ImageBombException(dims[0], dims[1]);
            }
        } catch (ImageBombException e) {
            throw e;
        } catch (IOException e) {
            throw new FileValidationException("Failed to read image dimensions", e);
        }
    }
}