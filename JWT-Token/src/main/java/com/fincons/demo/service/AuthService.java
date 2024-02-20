package com.fincons.demo.service;

import com.fincons.demo.exception.AuthenticationnCustomException;
import com.fincons.demo.jwt.JwtAuthResponse;
import com.fincons.demo.jwt.LoginDto;
import com.fincons.demo.jwt.RegisterDto;

public interface AuthService {
    String login(LoginDto loginDto);

    String register(RegisterDto registerDto,String paswordForAdmin) throws AuthenticationnCustomException;
}
