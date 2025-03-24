package com.tdx.sesion4.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.security.Key;
import java.util.List;
import java.util.stream.Collectors;

@Component // Asegúrate de que esta anotación esté presente
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String SECRET_KEY = "JmNxM2U3NDljNDZmNDkwZDkxNTYwZTZmYzY4YjZkNTg2ZTcwMjFjNmMwMGQ0YjEwZmFhYTk2NDRjMGQ0MGJlODgxNzZkNzgwZA==";// Misma clave que en JwtAuthenticationFilter

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String header = request.getHeader("Authorization");

        if (header == null || !header.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = header.replace("Bearer ", "");
        try {
            Claims claims = Jwts.parser()
                    .setSigningKey(SECRET_KEY)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            String username = claims.getSubject();
            List<String> roles = claims.get("roles", List.class);

            List<GrantedAuthority> authorities = roles.stream()
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());

            UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                    username, null, authorities);
            SecurityContextHolder.getContext().setAuthentication(auth);
        } catch (Exception e) {
            // Agregar log aquí para ver si hay algún error
            System.out.println("Token no válido o expirado: " + e.getMessage());
            SecurityContextHolder.clearContext();
        }

        filterChain.doFilter(request, response);
    }
}