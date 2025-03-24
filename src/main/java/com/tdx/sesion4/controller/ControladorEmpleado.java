package com.tdx.sesion4.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/empleados")
public class ControladorEmpleado {

    @GetMapping
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_USER')")
    public ResponseEntity<String> listarEmpleados(){
        return ResponseEntity.ok("ListaEmpleados");
    }

    @PostMapping
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public  ResponseEntity<String> crearEmpleado(){
        return ResponseEntity.ok("Empleado creado");
    }
}
