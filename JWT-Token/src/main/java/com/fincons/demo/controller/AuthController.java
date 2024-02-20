package com.fincons.demo.controller;

import com.fincons.demo.exception.AuthenticationnCustomException;
import com.fincons.demo.jwt.JwtAuthResponse;
import com.fincons.demo.jwt.LoginDto;
import com.fincons.demo.jwt.RegisterDto;
import com.fincons.demo.service.AuthService;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;



@AllArgsConstructor
@NoArgsConstructor
@RestController
@RequestMapping("/api/auth")
public class AuthController {


    @Autowired
    AuthService authService;

    // Build Register REST API
    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody RegisterDto registerDto,@RequestParam String passwordForAdmin) throws AuthenticationnCustomException {
        String response = authService.register(registerDto, passwordForAdmin);
        return new ResponseEntity<>(response, HttpStatus.CREATED);
    }

    // Build Login REST API
    @PostMapping("/login")
    public ResponseEntity<JwtAuthResponse> login(@RequestBody LoginDto loginDto){
        String token = authService.login(loginDto);

        JwtAuthResponse jwtAuthResponse = new JwtAuthResponse();
        jwtAuthResponse.setAccessToken(token);

        return new ResponseEntity<>(jwtAuthResponse, HttpStatus.OK);
    }

}

