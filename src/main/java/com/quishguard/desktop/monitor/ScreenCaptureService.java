package com.quishguard.desktop.monitor;

import java.awt.*;
import java.awt.image.BufferedImage;
import java.util.logging.Logger;

public class ScreenCaptureService {

    private static final Logger log = Logger.getLogger(ScreenCaptureService.class.getName());

    private final Robot robot;

    public ScreenCaptureService() {
        try {
            this.robot = new Robot();
        } catch (AWTException e) {
            throw new RuntimeException("Failed to initialize Robot for screen capture", e);
        }
    }

    /**
     * Captures only the bounds of the active window — not the full screen.
     * This is intentional: we only capture what the user permitted us to monitor.
     */
    public BufferedImage capture(Rectangle bounds) {
        if (bounds == null) return null;

        try {
            // Clamp bounds to actual screen dimensions — prevents out-of-bounds capture
            Rectangle screen = GraphicsEnvironment
                    .getLocalGraphicsEnvironment()
                    .getDefaultScreenDevice()
                    .getDefaultConfiguration()
                    .getBounds();

            Rectangle clamped = bounds.intersection(screen);
            if (clamped.isEmpty()) return null;

            return robot.createScreenCapture(clamped);

        } catch (Exception e) {
            log.warning("Screen capture failed: " + e.getMessage());
            return null;
        }
    }

    /**
     * Checks if two screenshots are meaningfully different.
     * If the screen hasn't changed, there's no point running QR detection.
     * Samples 200 random pixels — fast, doesn't compare every pixel.
     */
    public boolean hasChanged(BufferedImage prev, BufferedImage curr) {
        if (prev == null || curr == null) return true;
        if (prev.getWidth() != curr.getWidth() ||
            prev.getHeight() != curr.getHeight()) return true;

        int width  = curr.getWidth();
        int height = curr.getHeight();
        int diffCount = 0;

        // Sample 200 random pixels
        for (int i = 0; i < 200; i++) {
            int x = (int) (Math.random() * width);
            int y = (int) (Math.random() * height);
            if (prev.getRGB(x, y) != curr.getRGB(x, y)) {
                diffCount++;
            }
        }

        // If more than 5% of sampled pixels differ → screen changed
        return diffCount > 10;
    }
}