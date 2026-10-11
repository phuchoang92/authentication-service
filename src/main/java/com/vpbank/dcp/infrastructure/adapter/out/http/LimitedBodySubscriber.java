package com.vpbank.dcp.infrastructure.adapter.out.http;

import java.io.ByteArrayOutputStream;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Flow;

/** Stops the exchange as soon as the configured response budget is exceeded. */
final class LimitedBodySubscriber implements HttpResponse.BodySubscriber<byte[]> {

    private final int limit;
    private final CompletableFuture<byte[]> body = new CompletableFuture<>();
    private final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    private Flow.Subscription subscription;

    LimitedBodySubscriber(int limit) {
        this.limit = limit;
    }

    @Override
    public CompletableFuture<byte[]> getBody() {
        return body;
    }

    @Override
    public void onSubscribe(Flow.Subscription next) {
        subscription = next;
        next.request(1);
    }

    @Override
    public void onNext(List<ByteBuffer> chunks) {
        if (body.isDone()) {
            return;
        }
        for (ByteBuffer chunk : chunks) {
            int length = chunk.remaining();
            if (length > limit - bytes.size()) {
                subscription.cancel();
                body.completeExceptionally(new ExternalHttpRequestFailedException());
                return;
            }
            byte[] copied = new byte[length];
            chunk.get(copied);
            bytes.writeBytes(copied);
        }
        subscription.request(1);
    }

    @Override
    public void onError(Throwable failure) {
        body.completeExceptionally(failure);
    }

    @Override
    public void onComplete() {
        body.complete(bytes.toByteArray());
    }
}
