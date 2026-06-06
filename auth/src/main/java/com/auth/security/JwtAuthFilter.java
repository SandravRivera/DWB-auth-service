package com.auth.security;

import com.auth.service.DefaultUserAuthentication;
import com.auth.util.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtil jwtUtil;
    @Autowired
    private DefaultUserAuthentication userDetailsService;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");
        String username = null;
        String token    = null;

        // 1. SI NO HAY TOKEN, O NO EMPIEZA CON BEARER, PASAMOS AL SIGUIENTE FILTRO DE INMEDIATO
        // Esta es la validación clave para que rutas públicas como /login funcionen sin dar 403
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return; // Detiene la ejecución de este filtro para que no procese lógica vacía
        }

        // 2. Extraer token (si llegamos aquí, es porque sí contiene un Header válido)
        token    = authHeader.substring(7);
        username = jwtUtil.extractUsername(token);

        // 3. Validar y poner en SecurityContext
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            if (jwtUtil.validateToken(token, userDetails)) {
                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(
                                userDetails, null, userDetails.getAuthorities()
                        );
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }

        // 4. Continuar la cadena con la petición autenticada
        filterChain.doFilter(request, response);
    }
}