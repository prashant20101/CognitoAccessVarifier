package com.example.CognitoAccessToken.Service;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.JwkProviderBuilder;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.stereotype.Service;

import java.net.URL;
import java.security.interfaces.RSAPublicKey;

@Service
public class CognitoTokenService {
    private static final String JWKS_URL = "https://cognito-idp.ap-south-1.amazonaws.com/ap-south-1_GpXVuUEoa/.well-known/jwks.json";
    private static final String ISSUER = "https://cognito-idp.ap-south-1.amazonaws.com/ap-south-1_GpXVuUEoa";

    public DecodedJWT verifyToken(String token) throws Exception {
        JwkProvider provider = new JwkProviderBuilder(new URL(JWKS_URL)).build();
        DecodedJWT jwt = JWT.decode(token);
        Jwk jwk = provider.get(jwt.getKeyId());

        // Debugging information
        System.out.println("Token Key ID: " + jwt.getKeyId());
        System.out.println("JWK Key ID: " + jwk.getId());
        System.out.println("JWK Algorithm: " + jwk.getAlgorithm());
        System.out.println("JWK Public Key: " + jwk.getPublicKey());
        System.out.println("JWT Algorithm: " + jwt.getAlgorithm());

        try {
            Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) jwk.getPublicKey(), null);
            System.out.println("algo: " + algorithm.getName());
            System.out.println("algo: " + algorithm.getSigningKeyId());
            JWTVerifier verifier = JWT.require(algorithm)
                    .withIssuer(ISSUER)
                    .build();

            return verifier.verify(token);
        } catch (IllegalArgumentException e) {
            System.err.println("Base64 Decoding Error: " + e.getMessage());
            e.printStackTrace();
            throw new Exception("Base64 decoding failed during token verification", e);
        }
        catch (SignatureVerificationException e) {
            System.err.println("Signature Verification Error: " + e.getMessage());
            e.printStackTrace();
            throw new Exception("Token signature verification failed", e);
        } catch (Exception e) {
            System.err.println("Verification failed------>>>>: " + e.getMessage());
            e.printStackTrace();
            throw new Exception("Token verification failed", e);
        }
    }
}
