package com.vpbank.dcp.auth.infrastructure.adapter.out.captcha;

import java.awt.Color;
import java.awt.image.IndexColorModel;
import java.security.SecureRandom;

/**
 * The sixteen colours a CAPTCHA image is drawn with, so the PNG is 4 bits per pixel: one background, five inks
 * for the characters, ten lighter shades for the noise. A 24-bit image of the same drawing is about four times
 * larger as base64, and the image travels in a response header ({@code X-Captcha-Image}).
 */
final class CaptchaPalette {
    private static final Color BACKGROUND = new Color(245, 245, 240);
    private static final Color[] INKS = {
            new Color(20, 20, 80), new Color(40, 20, 100), new Color(10, 40, 90),
            new Color(60, 30, 110), new Color(30, 50, 120),
    };
    private static final Color[] NOISE = {
            new Color(70, 70, 140), new Color(90, 90, 160), new Color(110, 110, 180), new Color(130, 130, 200),
            new Color(150, 150, 215), new Color(100, 120, 170), new Color(120, 140, 190), new Color(140, 160, 210),
            new Color(160, 170, 220), new Color(180, 185, 230),
    };

    private CaptchaPalette() {
    }

    static Color background() {
        return BACKGROUND;
    }

    static Color ink(SecureRandom secureRandom) {
        return INKS[secureRandom.nextInt(INKS.length)];
    }

    static Color noise(SecureRandom secureRandom) {
        return NOISE[secureRandom.nextInt(NOISE.length)];
    }

    /** The image's colour table: index 0 the background, then the inks, then the noise shades. */
    static IndexColorModel colorModel() {
        Color[] all = new Color[1 + INKS.length + NOISE.length];
        all[0] = BACKGROUND;
        System.arraycopy(INKS, 0, all, 1, INKS.length);
        System.arraycopy(NOISE, 0, all, 1 + INKS.length, NOISE.length);
        byte[] red = new byte[all.length];
        byte[] green = new byte[all.length];
        byte[] blue = new byte[all.length];
        for (int i = 0; i < all.length; i++) {
            red[i] = (byte) all[i].getRed();
            green[i] = (byte) all[i].getGreen();
            blue[i] = (byte) all[i].getBlue();
        }
        return new IndexColorModel(4, all.length, red, green, blue);
    }
}
