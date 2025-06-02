package it.pleaseopen.authenticator.limituseragent;

import java.util.ArrayList;
import java.util.List;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

public class LimitUserAgentAuthenticatorFactory implements AuthenticatorFactory {
    @Override
    public String getDisplayType() {
        return "Filter by user agent";
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    public static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED,
    };

    public static final String DEFAULT_VALUE="(?i)(Firefox|Chrome|Safari|Edge|Opera)";

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Filter authentication by User Agent header";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        ProviderConfigProperty providerConfigProperty = new ProviderConfigProperty();
        providerConfigProperty.setType(ProviderConfigProperty.MULTIVALUED_STRING_TYPE);
        providerConfigProperty.setName("Allowed user-agents");
        providerConfigProperty.setLabel("List user agents headers authorized");
        providerConfigProperty.setHelpText("Each User Agent header listed will be allowed, all other results to an authentication failed. Regular expressions only.");
        providerConfigProperty.setDefaultValue(DEFAULT_VALUE);
        providerConfigProperty.setRequired(true);
        List<ProviderConfigProperty> providerConfigProperties = new ArrayList<>();
        providerConfigProperties.add(providerConfigProperty);
        return providerConfigProperties;
    }

    @Override
    public Authenticator create(KeycloakSession keycloakSession) {
        return new LimitUserAgentAuthenticator(keycloakSession);
    }

    @Override
    public void init(Config.Scope scope) {

    }

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return "POIT-auth-allow-user-agent";
    }

}