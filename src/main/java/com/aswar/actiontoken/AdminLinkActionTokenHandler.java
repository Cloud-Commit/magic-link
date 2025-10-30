package com.aswar.actiontoken;

import org.keycloak.authentication.actiontoken.AbstractActionTokenHandler;
import org.keycloak.authentication.actiontoken.ActionTokenContext;
import org.keycloak.events.Errors;
import org.keycloak.events.EventType;
import org.keycloak.models.*;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.common.util.Time;

import jakarta.ws.rs.core.Response;
import java.util.UUID;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.sessions.RootAuthenticationSessionModel;

public class AdminLinkActionTokenHandler extends AbstractActionTokenHandler<AdminLinkActionToken> {

    public AdminLinkActionTokenHandler() {
        super(
            AdminLinkActionToken.TOKEN_TYPE,
            AdminLinkActionToken.class,
            Messages.INVALID_CODE,
            EventType.EXECUTE_ACTION_TOKEN_ERROR,
            Errors.INVALID_CODE
        );
    }

    @Override
    public Response handleToken(AdminLinkActionToken token, ActionTokenContext<AdminLinkActionToken> tokenContext) {
        KeycloakSession session = tokenContext.getSession();
        RealmModel realm = tokenContext.getRealm();

        // Validate nonce
        UUID nonce = token.getNonce();
        if (nonce == null) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Missing nonce").build();
        }

        // Find user
        String userId = token.getUserId();
        UserModel user = session.users().getUserById(realm, userId);
        if (user == null || !user.isEnabled()) {
            return Response.status(Response.Status.FORBIDDEN).entity("User not found or disabled").build();
        }

        // Check nonce
        String attrKey = "admin-link-nonce:" + nonce.toString();
        String stored = user.getFirstAttribute(attrKey);
        if (stored == null) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Token not found or already consumed").build();
        }

        int storedExp;
        try {
            storedExp = Integer.parseInt(stored);
        } catch (NumberFormatException e) {
            user.removeAttribute(attrKey);
            return Response.status(Response.Status.BAD_REQUEST).entity("Invalid token metadata").build();
        }

        if (Time.currentTime() > storedExp) {
            user.removeAttribute(attrKey);
            return Response.status(Response.Status.BAD_REQUEST).entity("Token expired").build();
        }

        // Create user session
        String sessionId = UUID.randomUUID().toString();
        try {
            session.sessions().createUserSession(
                sessionId,
                realm,
                user,
                user.getUsername(),
                tokenContext.getClientConnection().getRemoteAddr(),
                "magic-link",
                false,
                null,
                null,
                UserSessionModel.SessionPersistenceState.PERSISTENT
            );
        } catch (Exception e) {
            user.removeAttribute(attrKey);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("Failed to create session").build();
        }

        // Create exchange token
        String exchangeToken = UUID.randomUUID().toString();
        int exchangeTtl = 60;
        int exchangeExp = Time.currentTime() + exchangeTtl;
        String redirectUri = token.getRedirectUri();
        if (redirectUri == null || redirectUri.isEmpty()) {
            redirectUri = String.format("/admin/%s/console/", realm.getName());
        }

        try {
            String encodedRedirect = java.net.URLEncoder.encode(redirectUri, java.nio.charset.StandardCharsets.UTF_8);
            String value = sessionId + "|" + exchangeExp + "|" + encodedRedirect;
            user.setSingleAttribute("admin-link-exchange:" + exchangeToken, value);
        } catch (Exception e) {
            user.removeAttribute(attrKey);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("Failed to persist exchange token").build();
        }

        // Consume nonce
        user.removeAttribute(attrKey);

        // Redirect to exchange endpoint
        String exchangePath = String.format("/realms/%s/admin-link/exchange?token=%s&userId=%s",
            realm.getName(), exchangeToken, user.getId());

        return Response.status(Response.Status.FOUND)
                .location(java.net.URI.create(exchangePath))
                .build();
    }

    @Override
    public AuthenticationSessionModel startFreshAuthenticationSession(AdminLinkActionToken token, ActionTokenContext<AdminLinkActionToken> tokenContext) {
    // Create a minimal auth session for Keycloak's event logging
    // This doesn't interfere with the UserSession we create in handleToken()
       KeycloakSession session = tokenContext.getSession();
       RealmModel realm = tokenContext.getRealm();
    
       AuthenticationSessionManager authSessionManager = new AuthenticationSessionManager(session);
       RootAuthenticationSessionModel rootAuthSession = authSessionManager.createAuthenticationSession(realm, true);
    
    // Use account-console as a safe default client
       ClientModel client = realm.getClientByClientId("account-console");
       if (client == null) {
          client = realm.getClientByClientId("account");
      }
    
       AuthenticationSessionModel authSession = rootAuthSession.createAuthenticationSession(client);
       authSession.setAuthenticatedUser(session.users().getUserById(realm, token.getUserId()));
    
       return authSession;
}
    
}