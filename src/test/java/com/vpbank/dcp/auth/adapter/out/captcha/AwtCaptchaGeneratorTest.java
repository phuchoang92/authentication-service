package com.vpbank.dcp.auth.adapter.out.captcha;

import static org.assertj.core.api.Assertions.assertThat;

import com.vpbank.dcp.auth.application.port.out.CaptchaGenerator.GeneratedCaptcha;
import java.io.ByteArrayInputStream;
import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Set;
import javax.imageio.ImageIO;
import org.junit.jupiter.api.Test;

class AwtCaptchaGeneratorTest {
    private final AwtCaptchaGenerator generator = new AwtCaptchaGenerator(new SecureRandom());

    @Test
    void drawsAFiveCharacterPngWithoutLookAlikesAndDoesNotRepeat() throws Exception {
        Set<String> answers = new HashSet<>();
        for (int i = 0; i < 20; i++) {
            GeneratedCaptcha captcha = generator.next();
            assertThat(captcha.answer().value()).hasSize(5).matches("[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{5}");
            assertThat(captcha.imagePng()).startsWith((byte) 0x89, (byte) 'P', (byte) 'N', (byte) 'G');
            var image = ImageIO.read(new ByteArrayInputStream(captcha.imagePng()));
            assertThat(image.getWidth()).isEqualTo(180);
            assertThat(image.getHeight()).isEqualTo(64);
            assertThat(captcha.toString()).doesNotContain(captcha.answer().value());
            answers.add(captcha.answer().value());
        }
        assertThat(answers).hasSizeGreaterThan(15);
    }
}
