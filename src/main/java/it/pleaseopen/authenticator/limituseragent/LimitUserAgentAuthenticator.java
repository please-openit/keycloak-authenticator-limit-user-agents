package it.pleaseopen.authenticator.limituseragent;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import jakarta.ws.rs.core.Response;
import org.keycloak.services.messages.Messages;

public class LimitUserAgentAuthenticator implements Authenticator {


    private final KeycloakSession keycloakSession;
    private static final Logger LOG = Logger.getLogger(LimitUserAgentAuthenticator.class);



    public LimitUserAgentAuthenticator(KeycloakSession keycloakSession){
        this.keycloakSession = keycloakSession;
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        AuthenticatorConfigModel authenticatorConfig = context.getAuthenticatorConfig();
        List<String> headersUserAgent = context.getHttpRequest().getHttpHeaders().getRequestHeader("User-Agent");
        List<String> allowedHeaders = new ArrayList<>();

        if(authenticatorConfig == null){
            allowedHeaders.add(LimitUserAgentAuthenticatorFactory.DEFAULT_VALUE);
        }else{
            allowedHeaders = Arrays.asList(authenticatorConfig.getConfig().getOrDefault("Allowed user-agents", LimitUserAgentAuthenticatorFactory.DEFAULT_VALUE).split("##"));
        }

        for(String headerUserAgent: headersUserAgent){
            for(String allowedHeader: allowedHeaders){
                Pattern pattern = Pattern.compile(allowedHeader);
                Matcher matcher = pattern.matcher(headerUserAgent);
                if(matcher.find()){
                    context.success();
                    return;
                }
            }
        }
        context.failure(AuthenticationFlowError.ACCESS_DENIED, Response.status(400).build(), "User agent not allowed", "Bad user agent");
        return;
    }

    @Override
    public void action(AuthenticationFlowContext context) {

    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return false;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {

    }

    @Override
    public void close() {

    }

    
}
