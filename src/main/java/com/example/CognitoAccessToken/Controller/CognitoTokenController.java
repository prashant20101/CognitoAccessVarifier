package com.example.CognitoAccessToken.Controller;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.CognitoAccessToken.Service.CognitoTokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/token")
public class CognitoTokenController {

    @Autowired
    private CognitoTokenService cognitoTokenService;

    @PostMapping("/verify")
    public ResponseEntity<?> verifyToken(@RequestHeader("Authorization") String token) {
        if (!token.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid Authorization header format.");
        }
        try {
            DecodedJWT decodedJWT = cognitoTokenService.verifyToken(token.replace("Bearer ", ""));
            TokenResponse response = new TokenResponse(
                    decodedJWT.getIssuer(),
                    decodedJWT.getSubject(),
                    decodedJWT.getIssuedAt().toString(),
                    decodedJWT.getExpiresAt().toString()
            );
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid token: " + e.getMessage());
        }
    }

    static class TokenResponse {
        private String issuer;
        private String subject;
        private String issuedAt;
        private String expiresAt;

        public TokenResponse(String issuer, String subject, String issuedAt, String expiresAt) {
            this.issuer = issuer;
            this.subject = subject;
            this.issuedAt = issuedAt;
            this.expiresAt = expiresAt;
        }

        // Getters and setters
        public String getIssuer() {
            return issuer;
        }

        public void setIssuer(String issuer) {
            this.issuer = issuer;
        }

        public String getSubject() {
            return subject;
        }

        public void setSubject(String subject) {
            this.subject = subject;
        }

        public String getIssuedAt() {
            return issuedAt;
        }

        public void setIssuedAt(String issuedAt) {
            this.issuedAt = issuedAt;
        }

        public String getExpiresAt() {
            return expiresAt;
        }

        public void setExpiresAt(String expiresAt) {
            this.expiresAt = expiresAt;
        }
    }
}
