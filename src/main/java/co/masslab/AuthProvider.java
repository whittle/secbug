package co.masslab;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

@Component
public class AuthProvider implements AuthenticationProvider {

    private static final AuthenticationException AUTH_ERROR = new AuthException("Auth error");

    private static final Logger log = LoggerFactory.getLogger(AuthProvider.class);

    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        AuthToken authToken = (AuthToken) authentication;

        log.info("Considering token: " + authToken);
        if (authToken.getToken().equals("foo")) {
            authToken.setAuthenticated(true);
            return authToken;
        } else {
            throw AUTH_ERROR;
        }
    }

    public boolean supports(Class<?> authentication) {
        boolean supported = AuthToken.class.isAssignableFrom(authentication);
        log.info(authentication + " is supported: " + supported);
        return true;
    }
}
