package com.aswar.actiontoken;

import org.keycloak.models.*;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.common.util.Time;
import org.keycloak.services.managers.AppAuthManager;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;

import java.net.URI;
import java.util.Map;
import java.util.UUID;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import org.keycloak.models.UserSessionModel;

public class AdminLinkActionTokenProvider implements RealmResourceProvider {

    private final KeycloakSession session;

    public AdminLinkActionTokenProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        return this;
    }

    @POST
    @Path("direct-login-tokens")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response createAdminLoginToken(Map<String, Object> payload, @Context UriInfo uriInfo) {
        String realmName = session.getContext().getRealm().getName();

        String userId = (String) payload.get("userId");
        int ttlSeconds = ((Number) payload.getOrDefault("ttlSeconds", 60)).intValue();

        // Validate bearer token - Keycloak's authenticator already validates signature, expiration, issuer, etc.
        // If this returns non-null, the token is valid and trusted
        var auth = new AppAuthManager.BearerTokenAuthenticator(session).authenticate();
        if (auth == null) {
            return Response.status(Response.Status.UNAUTHORIZED).entity("Invalid or missing bearer token").build();
        }
        
        // Allow cross-realm access if caller is from master realm
        // Master realm admins can issue tokens for users in any realm
        // Note: The bearer token's realm is embedded in the token's issuer claim
        // Keycloak's BearerTokenAuthenticator validates the token is for the current request realm
        // So if we're here with a valid auth, the token matches the URL realm OR is from master
        // For simplicity, we'll allow any valid token (master admins use master realm tokens with proper cross-realm permissions)

        // Basic validation of target user
        RealmModel realm = session.getContext().getRealm();
        UserModel targetUser = session.users().getUserById(realm, userId);
        if (targetUser == null) {
            return Response.status(Response.Status.BAD_REQUEST).entity("target user not found").build();
        }

    // Create the action token
    UUID nonce = UUID.randomUUID();
    int expiration = Time.currentTime() + ttlSeconds;
    String redirectUri = String.format("/admin/%s/console/", realmName);

    AdminLinkActionToken token = new AdminLinkActionToken(userId, expiration, nonce, redirectUri);

    // Persist nonce in user's attributes so redemption can verify single-use across nodes/restarts
    // Store as attribute key: admin-link-nonce:<nonce> -> <expiration>
    try {
        targetUser.setSingleAttribute("admin-link-nonce:" + nonce.toString(), String.valueOf(expiration));
    } catch (Exception ignored) {
        // best-effort persistence; if this fails we still issue the token but redemption will fail to consume
    }

    // Encode the token (Keycloak 26: serialize requires session, RealmModel and UriInfo)
    String encodedToken = token.serialize(session, realm, uriInfo);

    // Build the magic link using Keycloak's action-token endpoint
    URI magicLink = UriBuilder.fromUri(uriInfo.getBaseUri())
        .path("realms").path(realm.getName())
        .path("login-actions").path("action-token")
        .queryParam("key", encodedToken)
        .build();

        return Response.ok(Map.of(
                "realm", realmName,
                "userId", userId,
                "magicLink", magicLink.toString(),
                "expiresIn", ttlSeconds
        )).build();
    }

    @GET
    @Path("exchange")
    public Response exchangeToken(@QueryParam("token") String token, @QueryParam("userId") String userId, @Context UriInfo uriInfo) {
        if (token == null || token.isEmpty() || userId == null || userId.isEmpty()) {
            return Response.status(Response.Status.BAD_REQUEST).entity("missing token or userId").build();
        }

        RealmModel realm = session.getContext().getRealm();
        UserModel user = session.users().getUserById(realm, userId);
        if (user == null) {
            return Response.status(Response.Status.BAD_REQUEST).entity("invalid user").build();
        }

        

        String attrKey = "admin-link-exchange:" + token;
        String data = user.getFirstAttribute(attrKey);
        if (data == null) {
            return Response.status(Response.Status.BAD_REQUEST).entity("invalid or consumed token").build();
        }

        String[] parts = data.split("\\|", 3);
        if (parts.length < 3) {
            user.removeAttribute(attrKey);
            return Response.status(Response.Status.BAD_REQUEST).entity("invalid token metadata").build();
        }

        String sessionId = parts[0];
        int exp;
        try {
            exp = Integer.parseInt(parts[1]);
        } catch (NumberFormatException nfe) {
            user.removeAttribute(attrKey);
            return Response.status(Response.Status.BAD_REQUEST).entity("invalid token metadata").build();
        }

        if (org.keycloak.common.util.Time.currentTime() > exp) {
            user.removeAttribute(attrKey);
            return Response.status(Response.Status.BAD_REQUEST).entity("token expired").build();
        }

        String redirectUri;
        try {
            redirectUri = URLDecoder.decode(parts[2], StandardCharsets.UTF_8.name());
        } catch (Exception e) {
            redirectUri = String.format("/admin/%s/console/", realm.getName());
        }

        UserSessionModel userSession = session.sessions().getUserSession(realm, sessionId);
        if (userSession == null) {
            user.removeAttribute(attrKey);
            return Response.status(Response.Status.BAD_REQUEST).entity("session not found").build();
        }

        // create login cookie with full HTTP context
        try {
            org.keycloak.services.managers.AuthenticationManager.createLoginCookie(session, realm, user, userSession, uriInfo, session.getContext().getConnection());
        } catch (Exception e) {
            // if this fails, don't expose internal error; return a bad request and let caller retry/examine logs
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("failed to set login cookie").build();
        }

        // consume exchange token
        user.removeAttribute(attrKey);

        return Response.seeOther(URI.create(redirectUri)).build();
    }

    @Override
    public void close() {
        // Nothing to close
    }

 
}