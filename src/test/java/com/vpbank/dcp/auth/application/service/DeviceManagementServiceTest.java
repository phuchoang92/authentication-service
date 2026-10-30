package com.vpbank.dcp.auth.application.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import com.vpbank.dcp.auth.application.command.ListDevicesCommand;
import com.vpbank.dcp.auth.application.port.out.gateway.OpaqueTokenGenerator;
import com.vpbank.dcp.auth.application.port.out.gateway.TokenEnvelopeSealer;
import com.vpbank.dcp.auth.application.result.ListDevicesResult;
import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.DevicePlatform;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.DevicePolicy;
import com.vpbank.dcp.auth.domain.model.OpaqueToken;
import com.vpbank.dcp.auth.domain.model.Session;
import com.vpbank.dcp.auth.domain.model.SessionId;
import com.vpbank.dcp.auth.domain.model.SessionPolicy;
import com.vpbank.dcp.auth.domain.model.TrustedDevice;
import com.vpbank.dcp.auth.domain.model.TrustedDeviceId;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/** The device list is decided from one session read: ACTIVE lists, restricted is refused, gone is gone. */
class DeviceManagementServiceTest {
    private static final Instant NOW = Instant.parse("2026-10-30T10:00:00Z");
    private static final CustomerId ALICE = new CustomerId("90359");
    private static final DeviceId PHONE = new DeviceId("phone-1");
    private static final SessionId ACTIVE_ID = new SessionId(UUID.fromString("00000000-0000-4000-8000-000000000001"));
    private static final SessionId RESTRICTED_ID = new SessionId(UUID.fromString("00000000-0000-4000-8000-000000000002"));
    private static final OpaqueToken ACTIVE_TOKEN = OpaqueToken.of(Channel.MOBILE, ACTIVE_ID, "A".repeat(43));
    private static final OpaqueToken RESTRICTED_TOKEN = OpaqueToken.of(Channel.MOBILE, RESTRICTED_ID, "B".repeat(43));
    private static final OpaqueToken UNKNOWN_TOKEN = OpaqueToken.of(Channel.MOBILE, SessionId.random(), "C".repeat(43));

    private final InMemorySessionStore sessions = new InMemorySessionStore();
    private final InMemoryTrustedDeviceRepository devices = new InMemoryTrustedDeviceRepository();
    private final Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
    private final SessionPolicy sessionPolicy = new SessionPolicy(Duration.ofMinutes(15), Duration.ofMinutes(20), Duration.ofSeconds(30));
    private final SessionService sessionService = new SessionService(sessions, mock(TokenEnvelopeSealer.class),
            mock(OpaqueTokenGenerator.class), SessionId::random, sessionPolicy, DevicePolicy.standard(), clock);
    private final TrustedDeviceService trustedDevices = new TrustedDeviceService(devices, DevicePolicy.standard(),
            TrustedDeviceId::random, clock);
    private final DeviceManagementService service = new DeviceManagementService(sessionService, trustedDevices);

    @Test
    void listsFromAnActiveSessionRefusesARestrictedOneAndReportsAGoneOne() {
        TrustedDevice phone = TrustedDevice.trustedNow(TrustedDeviceId.random(), ALICE, Channel.MOBILE, PHONE,
                DevicePlatform.ANDROID, null, NOW.minusSeconds(60), DevicePolicy.standard());
        devices.rows.put(phone.id(), phone);
        devices.primaries.put(new InMemoryTrustedDeviceRepository.Key(ALICE, Channel.MOBILE), phone.id());
        sessions.create(Session.start(ACTIVE_ID, ALICE, PHONE, Channel.MOBILE, NOW, sessionPolicy), ACTIVE_TOKEN);
        sessions.create(Session.startRestricted(RESTRICTED_ID, ALICE, new DeviceId("tablet-2"), Channel.MOBILE, NOW,
                DevicePolicy.standard()), RESTRICTED_TOKEN);

        ListDevicesResult listed = service.list(new ListDevicesCommand(ACTIVE_TOKEN));
        assertThat(listed).isInstanceOf(ListDevicesResult.Devices.class);
        assertThat(((ListDevicesResult.Devices) listed).devices()).hasSize(1);
        assertThat(((ListDevicesResult.Devices) listed).devices().get(0).primary()).isTrue();

        assertThat(service.list(new ListDevicesCommand(RESTRICTED_TOKEN))).isInstanceOf(ListDevicesResult.DeviceTrustRequired.class);
        assertThat(service.list(new ListDevicesCommand(UNKNOWN_TOKEN))).isInstanceOf(ListDevicesResult.SessionGone.class);

        sessions.unavailable = true;
        assertThat(service.list(new ListDevicesCommand(ACTIVE_TOKEN))).isInstanceOf(ListDevicesResult.Unavailable.class);
    }
}
