package com.ipsenh.prototype.controllers;

import com.ipsenh.prototype.Payloads.SignupRequest;
import com.ipsenh.prototype.model.Account;
import com.ipsenh.prototype.Payloads.LoginRequest;
import com.ipsenh.prototype.repositories.AccountRepository;
import com.ipsenh.prototype.services.AuthService;
import com.ipsenh.prototype.services.EncryptionService;
import com.ipsenh.prototype.services.JwtProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping
public class AuthController {

    @Autowired
    AccountRepository accountRepository;
    @Autowired
    AuthService authService;
    @Autowired
    EncryptionService encryptionService;

    JwtProvider jwtProvider = new JwtProvider();


    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody LoginRequest loginRequest, @RequestHeader(name = "token", required = false) String token){
        if (jwtProvider.isValidToken(token)){
            System.out.println("user logged in with existing token: " + token);
            return ResponseEntity.ok(token);
        }

        String username = loginRequest.getUsername();
        String password = loginRequest.getPassword();
        password = encryptionService.hashPassword(password);


        Account account = accountRepository.findByUsername(username);
        String actualPass = account.getPassword();
        if (password.equals(actualPass)){
            String newToken = jwtProvider.createToken(username);
            return ResponseEntity.ok(newToken);
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Authentication error");
    }

    @PostMapping("/register")
    public ResponseEntity<String> createAccount(@RequestBody SignupRequest signupRequest) {
        if (signupRequest.getPassword().isEmpty() || signupRequest.getUsername().isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Request body was invalid");
        } else if (authService.usernameTaken(signupRequest.getUsername())) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Username allready taken");
        } else {
            authService.createAndSaveUser(signupRequest);
            return ResponseEntity.ok("Account created");
        }
    }

    @GetMapping("/authenticateRequest")
    public ResponseEntity<String> authenticateRequest(@RequestHeader("token") String token) {
        System.out.println("received request from token: " + token);
        if (jwtProvider.isValidToken(token)) {
            return ResponseEntity.ok("Token is valid");
        }

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid token");
    }
}
