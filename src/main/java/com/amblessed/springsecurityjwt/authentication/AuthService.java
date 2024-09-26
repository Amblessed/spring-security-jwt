package com.amblessed.springsecurityjwt.authentication;



/*
 * @Project Name: spring-security-jwt
 * @Author: Okechukwu Bright Onwumere
 * @Created: 26-Sep-24
 */

import com.amblessed.springsecurityjwt.jwt.JwtService;
import com.amblessed.springsecurityjwt.repository.UserRepository;
import com.amblessed.springsecurityjwt.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest request) {
        User user = User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(request.getRole())
                .build();
        User savedUser = userRepository.save(user);
        String jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder().accessToken(jwtToken).build();
    }


    public AuthenticationResponse authenticate(AuthenticationRequest request) {

        //We need to validate our request (validate whether password & username is correct)
        //verify whether user is present in the database
        //Which Authentication Provider -> DaoAuthenticationProvider(inject)
        //We need to authenticate using this authenticationManager injecting this authenticationProvider

        //Verify whether username and password is correct
        //verify whether user is present in db
        //generate Token
        //Return Token

        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));
        var user = userRepository.findByEmail(request.getEmail()).orElseThrow();
        String jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder().accessToken(jwtToken).build();
    }
}
