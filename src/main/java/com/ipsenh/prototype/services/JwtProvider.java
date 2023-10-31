package com.ipsenh.prototype.services;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.Date;
import java.util.UUID;

public class JwtProvider {
    private final String secretKey = "thisIsThePlaceYouWouldPlaceYourSecureSalt785434567";
    private final long validityInMilliseconds = 3600000; // 1 hour
    Algorithm algorithm = Algorithm.HMAC256(secretKey);
    JWTVerifier verifier = JWT.require(algorithm)
            .withIssuer("Hemiron")
            .build();

    public String createToken(String username) {

        return JWT.create()
                .withIssuer("Hemiron")
                .withClaim("username", username)
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis()+ validityInMilliseconds))
                .withJWTId(UUID.randomUUID().toString())
                .sign(algorithm);
    }

    public boolean isValidToken(String token){
        try {
            verifier.verify(token);
            return true;
        } catch (JWTVerificationException e){
            System.out.println(e);
            return false;
        }
    }
}
