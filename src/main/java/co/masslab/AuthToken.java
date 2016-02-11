package co.masslab;

import org.springframework.security.authentication.AbstractAuthenticationToken;

class AuthToken extends AbstractAuthenticationToken {

    private final String token;

    public AuthToken(String token) {
        super(null);
        this.token = token;
        setAuthenticated(false);
    }

    public Object getCredentials() {
        return null;
    }

    public Object getPrincipal() {
        return null;
    }

    public String getToken() {
        return token;
    }
}
