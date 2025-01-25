package com.auth_jwt_estudo.controllers;

import com.auth_jwt_estudo.domain.user.User;
import com.auth_jwt_estudo.dtos.LoginDTO;
import com.auth_jwt_estudo.dtos.RegisterDTO;
import com.auth_jwt_estudo.dtos.ResponseDTO;
import com.auth_jwt_estudo.infra.security.TokenService;
import com.auth_jwt_estudo.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private  TokenService tokenService;

    @PostMapping("/login")
    public ResponseEntity login(@RequestBody LoginDTO dados){
        User user = userRepository.findByEmail(dados.email()).orElseThrow(() -> new RuntimeException("User not found"));
        if(passwordEncoder.matches(dados.password(), user.getPassword())){
            String token = this.tokenService.generateToken(user);
            return ResponseEntity.ok(new ResponseDTO(user.getName(), token));
        }
        return ResponseEntity.badRequest().build();
    }

    @PostMapping("/register")
    public ResponseEntity register(@RequestBody RegisterDTO dados){
        Optional user = userRepository.findByEmail(dados.email());

        if(user.isEmpty()){
            User newUser = new User();
            newUser.setPassword(passwordEncoder.encode(dados.password()));
            newUser.setEmail(dados.email());
            newUser.setName(dados.name());
            this.userRepository.save(newUser);

            String token = this.tokenService.generateToken(newUser);
            return ResponseEntity.ok(new ResponseDTO(newUser.getName(), token));

        }
        return ResponseEntity.badRequest().build();
    }
}
