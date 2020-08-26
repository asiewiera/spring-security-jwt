package com.ge.springsecurityjwt.filter;



import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
import java.util.Map;

public class JwtFilter extends OncePerRequestFilter {

    private String key="Ilove GE";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String bearerToken = request.getHeader("Authorization");
        JWTVerifier jwtVerifier = JWT.require(Algorithm.HMAC256(key)).build();

        DecodedJWT decodedJWT = jwtVerifier.verify(bearerToken.substring(7));
        String name = decodedJWT.getClaim("name").asString();
        String role = decodedJWT.getClaim("role").asString();
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken;
        usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(name, null, Collections.singleton(new SimpleGrantedAuthority(role)));
/*        if(role.equals("ADMIN")){
            usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(name, null, Collections.singleton(new SimpleGrantedAuthority("ROLE_ADMIN")));
        }else {
            usernamePasswordAuthenticationToken =new UsernamePasswordAuthenticationToken(name,null, Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")));
        }*/
        SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
        System.out.println("Hello " + name );

        filterChain.doFilter(request,response);
    }

}
