package com.example.demo.token;

import com.example.demo.config.JwtProperties;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Component;

@Component
public class TokenSigner {
  private final JWSSigner signer;
  private final JWSVerifier verifier;

  public TokenSigner(final JwtProperties jwtProperties) {
    this.signer = new RSASSASigner(jwtProperties.privateKey());
    this.verifier = new RSASSAVerifier(jwtProperties.publicKey());
  }

  public SignedJWT sign(final JWTClaimsSet claimsSet) {
    final var header = new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT).build();
    final var signedJWT = new SignedJWT(header, claimsSet);
    try {
      signedJWT.sign(this.signer);
    } catch (final JOSEException e) {
      throw new IllegalStateException(e);
    }
    return signedJWT;
  }

  @PostConstruct
  public void validateKeyPair() throws Exception {
    final JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().subject("test").build();
    final SignedJWT signedJWT = sign(claimsSet);
    if (!signedJWT.verify(this.verifier)) {
      throw new IllegalStateException("The pair of public key and private key is wrong.");
    }
  }
}
