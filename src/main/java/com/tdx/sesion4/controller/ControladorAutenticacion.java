package com.tdx.sesion4.controller;

import com.tdx.sesion4.dto.SolicitudLoginDTO;
import com.tdx.sesion4.security.ServicioJWT;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
public class ControladorAutenticacion {

    private  final AuthenticationManager authenticationManager;
    private  final ServicioJWT servicioJWT;

    public  ControladorAutenticacion(AuthenticationManager authenticationManager, ServicioJWT servicioJWT){
        this.authenticationManager = authenticationManager;
        this.servicioJWT = servicioJWT;
    }

    @PostMapping("/login")
    public ResponseEntity<String> login (@RequestBody SolicitudLoginDTO solicitudLoginDTO) {
        Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(solicitudLoginDTO.getNombreUsuario(), solicitudLoginDTO.getContrasena())
        );
        String token = servicioJWT.generarToken(auth);

        return ResponseEntity.ok(token);
    }
}
