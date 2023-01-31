package com.example.securitymaster.security.filters;

import com.example.securitymaster.security.SecurityRoles;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;
import static com.example.securitymaster.security.SecurityRoles.*;

import java.io.IOException;
import java.util.Collections;

public class CustomRequestParameterAuthenticationFilter extends GenericFilterBean {

    private static final String CODE="x-admin";

    //http://localhost:8080/customers?id=1
    //http://localhost:8080/customers?x-code=x-admin
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        SecurityContext context = SecurityContextHolder.getContext();
        if (CODE.equals(request.getParameter("x-code")) && context != null){
            context.setAuthentication(
                    new AnonymousAuthenticationToken(
                            "x-admin",
                            "x-code",
                            Collections.singletonList(
                                    new SimpleGrantedAuthority(ROLES_PREFIX + ROLES_ADMIN)
                            )
                    )
            );
        }
        chain.doFilter(request,response);
    }
}
