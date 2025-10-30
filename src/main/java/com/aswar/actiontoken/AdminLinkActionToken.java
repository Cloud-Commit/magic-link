package com.aswar.actiontoken;

import org.keycloak.authentication.actiontoken.DefaultActionToken;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.UUID;

public class AdminLinkActionToken extends DefaultActionToken {

    public static final String TOKEN_TYPE = "admin-link-action-token";

    @JsonProperty("redirectUri")
    private String redirectUri;
    
    @JsonProperty("userId")
    private String userId;
    
    @JsonProperty("nonce")
    private UUID nonce;

    // Default constructor for Jackson deserialization
    public AdminLinkActionToken() {
    }

    public AdminLinkActionToken(String userId, int absoluteExpirationInSecs, UUID actionVerificationNonce, String redirectUri) {
        super(userId, TOKEN_TYPE, absoluteExpirationInSecs, actionVerificationNonce);
        this.redirectUri = redirectUri;
        this.userId = userId;
        this.nonce = actionVerificationNonce;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    @Override
    public String getUserId() {
        return userId;
    }

    public UUID getNonce() {
        return nonce;
    }
}