package io.github.ahnyeongjun.oauth.client;

import io.github.ahnyeongjun.oauth.exception.UnsupportedProviderException;
import io.github.ahnyeongjun.oauth.provider.OAuthProvider;

import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

public class OAuthClientFactory {

    private final Map<OAuthProvider, OAuthClient> clients;

    public OAuthClientFactory(List<OAuthClient> oAuthClients) {
        this.clients = oAuthClients.stream()
                .collect(Collectors.toMap(OAuthClient::getProvider, Function.identity()));
    }

    public OAuthClient getClient(OAuthProvider provider) {
        OAuthClient client = clients.get(provider);
        if (client == null) {
            throw new UnsupportedProviderException(provider.name());
        }
        return client;
    }

    public OAuthClient getClient(String providerName) {
        return OAuthProvider.fromString(providerName)
                .map(this::getClient)
                .orElseThrow(() -> new UnsupportedProviderException(providerName));
    }
}
