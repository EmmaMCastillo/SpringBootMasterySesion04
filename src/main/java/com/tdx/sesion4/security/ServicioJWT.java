package com.tdx.sesion4.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.stream.Collectors;

@Service
public class ServicioJWT {
    private static final String SECRET_KEY = "JmNxM2U3NDljNDZmNDkwZDkxNTYwZTZmYzY4YjZkNTg2ZTcwMjFjNmMwMGQ0YjEwZmFhYTk2NDRjMGQ0MGJlODgxNzZkNzgwZA=="; // Misma clave que en JwtAuthenticationFilter
    private static final long EXPIRATION_TIME = 86400000;

    public String generarToken(Authentication authentication) {
        String username = authentication.getName();
        var roles = authentication.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .claim("roles", roles)
                .signWith(SignatureAlgorithm.HS512, SECRET_KEY)
                .compact();
    }
}