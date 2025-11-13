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
import org.jboss.logging.Logger;

public class AdminLinkActionTokenProvider implements RealmResourceProvider {

    private static final Logger logger = Logger.getLogger(AdminLinkActionTokenProvider.class);
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

        // Validate bearer token - ONLY accepts master realm tokens (cross-realm access)
        // Master admin must authenticate to master realm, then can generate magic links for any realm
        RealmModel masterRealm = session.realms().getRealmByName("master");
        if (masterRealm == null) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                .entity("Master realm not found")
                .build();
        }
        
        // Switch to master realm context to validate master token
        RealmModel originalRealm = session.getContext().getRealm();
        Object authResult;
        try {
            session.getContext().setRealm(masterRealm);
            authResult = new AppAuthManager.BearerTokenAuthenticator(session).authenticate();
        } finally {
            // Restore original realm context
            session.getContext().setRealm(originalRealm);
        }
        
        var auth = authResult;
        
        if (auth == null) {
            return Response.status(Response.Status.UNAUTHORIZED)
                .entity("Invalid or missing bearer token. Must use master realm access token.")
                .build();
        }

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

        // Consume token immediately to minimize race condition window
        // Parse from local 'data' variable (not from attribute) for remaining validation
        user.removeAttribute(attrKey);

        String[] parts = data.split("\\|", 3);
        if (parts.length < 3) {
            return Response.status(Response.Status.BAD_REQUEST).entity("invalid token metadata").build();
        }

        String sessionId = parts[0];
        int exp;
        try {
            exp = Integer.parseInt(parts[1]);
        } catch (NumberFormatException nfe) {
            return Response.status(Response.Status.BAD_REQUEST).entity("invalid token metadata").build();
        }

        if (org.keycloak.common.util.Time.currentTime() > exp) {
            return Response.status(Response.Status.BAD_REQUEST).entity("token expired").build();
        }

        String redirectUri;
        try {
            redirectUri = URLDecoder.decode(parts[2], StandardCharsets.UTF_8.name());
        } catch (Exception e) {
            redirectUri = String.format("/admin/%s/console/", realm.getName());
        }

        // Validate redirect URI to prevent open redirect attacks
        redirectUri = validateAndSanitizeRedirectUri(redirectUri, realm);

        UserSessionModel userSession = session.sessions().getUserSession(realm, sessionId);
        if (userSession == null) {
            return Response.status(Response.Status.BAD_REQUEST).entity("session not found").build();
        }

        // create login cookie with full HTTP context
        try {
            org.keycloak.services.managers.AuthenticationManager.createLoginCookie(session, realm, user, userSession, uriInfo, session.getContext().getConnection());
        } catch (Exception e) {
            // if this fails, don't expose internal error; return a bad request and let caller retry/examine logs
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("failed to set login cookie").build();
        }

        // Token already consumed at line 131 (immediately after null check)
        return Response.seeOther(URI.create(redirectUri)).build();
    }

    @Override
    public void close() {
        // Nothing to close
    }

    /**
     * Validates and sanitizes redirect URI to prevent open redirect attacks.
     * Only allows relative paths starting with /admin/ or /realms/
     * Blocks absolute URLs, path traversal, and dangerous protocols.
     * 
     * @param redirectUri The URI to validate
     * @param realm The current realm
     * @return A safe redirect URI (defaults to admin console if validation fails)
     */
    private String validateAndSanitizeRedirectUri(String redirectUri, RealmModel realm) {
        String defaultRedirect = String.format("/admin/%s/console/", realm.getName());
        
        if (redirectUri == null || redirectUri.trim().isEmpty()) {
            return defaultRedirect;
        }
        
        redirectUri = redirectUri.trim();
        
        try {
            URI uri = new URI(redirectUri);
            
            // Block absolute URIs (must be relative paths only)
            if (uri.isAbsolute()) {
                logger.warnf("Blocked absolute redirect URI: %s", redirectUri);
                return defaultRedirect;
            }
            
            // Block protocol-relative URLs (//example.com)
            if (redirectUri.startsWith("//")) {
                logger.warnf("Blocked protocol-relative redirect URI: %s", redirectUri);
                return defaultRedirect;
            }
            
            // Block dangerous protocols (javascript:, data:, file:, etc.)
            if (redirectUri.matches("^[a-zA-Z][a-zA-Z0-9+.-]*:.*")) {
                logger.warnf("Blocked redirect URI with protocol: %s", redirectUri);
                return defaultRedirect;
            }
            
            // Must start with /admin/ or /realms/
            if (!redirectUri.startsWith("/admin/") && !redirectUri.startsWith("/realms/")) {
                logger.warnf("Blocked redirect URI not starting with /admin/ or /realms/: %s", redirectUri);
                return defaultRedirect;
            }
            
            // Normalize path and check for path traversal
            java.nio.file.Path normalized = java.nio.file.Paths.get(redirectUri).normalize();
            String normalizedStr = normalized.toString().replace('\\', '/');
            
            // After normalization, must still start with /admin/ or /realms/
            if (!normalizedStr.startsWith("/admin/") && !normalizedStr.startsWith("/realms/")) {
                logger.warnf("Blocked path traversal in redirect URI: %s -> %s", redirectUri, normalizedStr);
                return defaultRedirect;
            }
            
            // Block newline characters (HTTP response splitting)
            if (normalizedStr.contains("\n") || normalizedStr.contains("\r")) {
                logger.warnf("Blocked redirect URI with newline characters: %s", redirectUri);
                return defaultRedirect;
            }
            
            return normalizedStr;
            
        } catch (Exception e) {
            logger.warnf("Invalid redirect URI format: %s - %s", redirectUri, e.getMessage());
            return defaultRedirect;
        }
    }
}