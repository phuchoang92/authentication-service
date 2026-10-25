package com.vpbank.dcp.auth.infrastructure.adapter.out.captcha;

import com.vpbank.dcp.auth.application.port.out.gateway.CaptchaGenerator;
import com.vpbank.dcp.auth.domain.model.CaptchaAnswer;
import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Font;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import javax.imageio.ImageIO;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/**
 * Server-drawn CAPTCHA with the JDK alone (headless AWT): five characters without look-alikes,
 * each rotated and shifted, over noise lines and dots, as a PNG. Good enough to stop plain
 * scripted guessing; an external provider can replace it behind the same port later.
 */
@RequiredArgsConstructor
public final class AwtCaptchaGenerator implements CaptchaGenerator {
    static final String ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    static final int LENGTH = 5;
    private static final int WIDTH = 180;
    private static final int HEIGHT = 64;

    static {
        System.setProperty("java.awt.headless", "true");
    }

    @NonNull private final SecureRandom secureRandom;

    @Override
    public GeneratedCaptcha next() {
        char[] answerText = new char[LENGTH];
        for (int i = 0; i < LENGTH; i++) {
            answerText[i] = ALPHABET.charAt(secureRandom.nextInt(ALPHABET.length()));
        }
        CaptchaAnswer answer = new CaptchaAnswer(new String(answerText));
        byte[] imagePng = draw(answerText);
        return new GeneratedCaptcha(answer, imagePng);
    }

    private byte[] draw(char[] text) {
        BufferedImage image = new BufferedImage(WIDTH, HEIGHT, BufferedImage.TYPE_INT_RGB);
        Graphics2D graphics = image.createGraphics();
        try {
            graphics.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            graphics.setColor(new Color(245, 245, 240));
            graphics.fillRect(0, 0, WIDTH, HEIGHT);
            graphics.setStroke(new BasicStroke(1.5f));
            for (int i = 0; i < 6; i++) {
                graphics.setColor(new Color(secureRandom.nextInt(120) + 80, secureRandom.nextInt(120) + 80, secureRandom.nextInt(120) + 80));
                graphics.drawLine(secureRandom.nextInt(WIDTH), secureRandom.nextInt(HEIGHT), secureRandom.nextInt(WIDTH), secureRandom.nextInt(HEIGHT));
            }
            for (int i = 0; i < 150; i++) {
                graphics.setColor(new Color(secureRandom.nextInt(160) + 60, secureRandom.nextInt(160) + 60, secureRandom.nextInt(160) + 60));
                graphics.fillRect(secureRandom.nextInt(WIDTH), secureRandom.nextInt(HEIGHT), 1, 1);
            }
            Font font = new Font(Font.SANS_SERIF, Font.BOLD, 34);
            int step = WIDTH / (LENGTH + 1);
            for (int i = 0; i < text.length; i++) {
                Graphics2D glyph = (Graphics2D) graphics.create();
                try {
                    int x = step * (i + 1) - 10 + secureRandom.nextInt(7) - 3;
                    int y = HEIGHT / 2 + 12 + secureRandom.nextInt(9) - 4;
                    glyph.rotate(Math.toRadians(secureRandom.nextInt(50) - 25), x, y);
                    glyph.setFont(font);
                    glyph.setColor(new Color(secureRandom.nextInt(80), secureRandom.nextInt(80), secureRandom.nextInt(120) + 40));
                    glyph.drawString(String.valueOf(text[i]), x, y);
                } finally {
                    glyph.dispose();
                }
            }
        } finally {
            graphics.dispose();
        }
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            ImageIO.write(image, "png", out);
            return out.toByteArray();
        } catch (IOException failure) {
            throw new IllegalStateException("CAPTCHA image could not be encoded", failure);
        }
    }
}
