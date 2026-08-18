package com.quishguard.sentinel.exception;

import com.quishguard.sentinel.dto.ErrorResponseDto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.multipart.MaxUploadSizeExceededException;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(PdfRequiresAuthException.class)
    public ResponseEntity<ErrorResponseDto> handlePdfRequiresAuth(PdfRequiresAuthException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(ErrorResponseDto.of("PDF_REQUIRES_AUTH", ex.getMessage(), 403));
    }

    @ExceptionHandler(PdfPageLimitExceededException.class)
    public ResponseEntity<ErrorResponseDto> handlePdfPageLimit(PdfPageLimitExceededException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(ErrorResponseDto.of("PDF_PAGE_LIMIT_EXCEEDED", ex.getMessage(), 400));
    }

    @ExceptionHandler(EncryptedPdfException.class)
    public ResponseEntity<ErrorResponseDto> handleEncryptedPdf(EncryptedPdfException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(ErrorResponseDto.of("ENCRYPTED_PDF", ex.getMessage(), 400));
    }

    @ExceptionHandler(UnsupportedFileTypeException.class)
    public ResponseEntity<ErrorResponseDto> handleUnsupportedFileType(UnsupportedFileTypeException ex) {
        return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE)
                .body(ErrorResponseDto.of("UNSUPPORTED_FILE_TYPE", ex.getMessage(), 415));
    }

    @ExceptionHandler(ImageBombException.class)
    public ResponseEntity<ErrorResponseDto> handleImageBomb(ImageBombException ex) {
        log.warn("Image bomb attempt detected: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(ErrorResponseDto.of("IMAGE_BOMB_DETECTED", ex.getMessage(), 400));
    }

    @ExceptionHandler(FileSizeExceededException.class)
    public ResponseEntity<ErrorResponseDto> handleFileSizeExceeded(FileSizeExceededException ex) {
        return ResponseEntity.status(HttpStatus.PAYLOAD_TOO_LARGE)
                .body(ErrorResponseDto.of("FILE_TOO_LARGE", ex.getMessage(), 413));
    }

    @ExceptionHandler(FileValidationException.class)
    public ResponseEntity<ErrorResponseDto> handleFileValidation(FileValidationException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(ErrorResponseDto.of("FILE_VALIDATION_ERROR", ex.getMessage(), 400));
    }

    // Catches @Valid failures on request DTOs
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponseDto> handleValidation(MethodArgumentNotValidException ex) {
        String message = ex.getBindingResult()
                .getFieldErrors()
                .stream()
                .map(e -> e.getField() + ": " + e.getDefaultMessage())
                .findFirst()
                .orElse("Validation failed");
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(ErrorResponseDto.of("VALIDATION_ERROR", message, 400));
    }

    // Catches multipart file size violations from Spring before our code runs
    @ExceptionHandler(MaxUploadSizeExceededException.class)
    public ResponseEntity<ErrorResponseDto> handleMaxUploadSize(MaxUploadSizeExceededException ex) {
        return ResponseEntity.status(HttpStatus.PAYLOAD_TOO_LARGE)
                .body(ErrorResponseDto.of("FILE_TOO_LARGE", "File size exceeds the 50MB limit.", 413));
    }

    // Catch-all — never expose raw stack traces to the client
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponseDto> handleGeneric(Exception ex) {
        log.error("Unhandled exception", ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ErrorResponseDto.of("INTERNAL_ERROR", "An unexpected error occurred.", 500));
    }
}