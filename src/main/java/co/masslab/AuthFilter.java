package co.masslab;

import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.GenericFilterBean;

@Component
class AuthFilter extends GenericFilterBean {

    private final static Pattern AUTHORIZATION_HEADER_PATTERN =
        Pattern.compile("^Bearer\\s+([\\w\\.\\-]+)\\s*$");

    private final static Logger log = LoggerFactory.getLogger(AuthFilter.class);

    @Autowired
    AuthenticationManager authenticationManager;

    public void doFilter(ServletRequest req,
                         ServletResponse res,
                         FilterChain chain) throws IOException, ServletException {

        final HttpServletRequest request = (HttpServletRequest) req;
        final HttpServletResponse response = (HttpServletResponse) res;

        String token = getToken(request);
        log.info("Looking at token: " + token);

        if (token != null) {
            try {
                AuthToken authToken = new AuthToken(token);
                Authentication authResult = authenticationManager.authenticate(authToken);
                SecurityContextHolder.getContext().setAuthentication(authResult);
            } catch (AuthenticationException failed) {
                log.info("auth failed: " + failed);
                SecurityContextHolder.clearContext();
                return;
            }
        }

        chain.doFilter(request, response);
    }

    private String getToken(HttpServletRequest httpRequest) {
        final String authorizationHeader = httpRequest.getHeader("authorization");
        if (authorizationHeader == null) {
            return null;
        }

        final Matcher matcher = AUTHORIZATION_HEADER_PATTERN.matcher(authorizationHeader);
        if (matcher.matches()) {
            return matcher.group(1);
        } else {
            return null;
        }
    }
}
