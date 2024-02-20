package com.fincons.demo.service;

import com.fincons.demo.entity.Role;
import com.fincons.demo.entity.User;
import com.fincons.demo.exception.AuthenticationnCustomException;
import com.fincons.demo.jwt.JwtTokenProvider;
import com.fincons.demo.jwt.LoginDto;
import com.fincons.demo.jwt.RegisterDto;
import com.fincons.demo.repository.RoleRepository;
import com.fincons.demo.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import java.util.HashSet;
import java.util.Set;

@Service
public class AuthServiceImpl implements AuthService {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Autowired
    private RoleRepository roleRepo;

    public AuthServiceImpl(AuthenticationManager authenticationManager, UserRepository userRepository, PasswordEncoder passwordEncoder, JwtTokenProvider jwtTokenProvider, RoleRepository roleRepo) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtTokenProvider = jwtTokenProvider;
        this.roleRepo = roleRepo;
    }

    @Value("${admin.password}")
    private String passwordAdmin;


    public String register(RegisterDto registerDto, String passwordForAdmin) throws AuthenticationnCustomException {

        // check username is already exists in database
        if(Boolean.TRUE.equals(userRepository.existsByEmail(registerDto.getEmail()))){
            throw new AuthenticationnCustomException(HttpStatus.BAD_REQUEST, "Email already exists!");
        }

        // check email is already exists in database
        if(Boolean.TRUE.equals(userRepository.existsByEmail(registerDto.getEmail()))){
            throw new AuthenticationnCustomException(HttpStatus.BAD_REQUEST, "Email is already exists!.");
        }


        User user = new User();
        user.setName(registerDto.getName());
        user.setUsername(registerDto.getUsername());
        user.setEmail(registerDto.getEmail());
        user.setPassword(passwordEncoder.encode(registerDto.getPassword()));

        Set<Role> roles = new HashSet<>();

        Role userRole;

        if (passwordForAdmin != null && passwordForAdmin.equals(passwordAdmin)) {
            userRole = roleToAssign("ROLE_ADMIN");
        } else {
            userRole = roleToAssign("ROLE_USER");
        }
        user.setRoles(roles);
        userRepository.save(user);

        return "User Registered Successfully!.";

    }


    public String login(LoginDto loginDto) {

        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                loginDto.getEmail(),
                loginDto.getPassword()
        ));

        SecurityContextHolder.getContext().setAuthentication(authentication);


        return jwtTokenProvider.generateToken(authentication);
    }


    public Role roleToAssign(String nomeRuolo) {
        Role role = roleRepo.findByName(nomeRuolo);
        if (role == null) {
            Role newRole = new Role();
            newRole.setName(nomeRuolo);
            role = roleRepo.save(newRole);
        }
        return role;
    }




}
