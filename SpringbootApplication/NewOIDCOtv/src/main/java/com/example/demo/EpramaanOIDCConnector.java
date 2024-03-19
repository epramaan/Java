package com.example.demo;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Autowired;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.claims.ACR;

public class EpramaanOIDCConnector {

	public static String aesKey = "bd64a027-1eXX-440c-a07f-XX230d68b1XX";
	public static String salt = "1007XX";
	AuthenticationRequest request;
	String apiHmac;
	
	
public static String hashHMACHex(String hMACKey, String inputValue) {
        
        System.out.println("InputValue: "+inputValue);
        System.out.println("HMAC Key: "+hMACKey);
        
        
            byte[] keyByte = hMACKey.getBytes(StandardCharsets.US_ASCII);
            byte[] messageBytes = inputValue.getBytes(StandardCharsets.US_ASCII);
            
            Mac sha256_HMAC = null;
			try {
				sha256_HMAC = Mac.getInstance("HmacSHA256");
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			}
            SecretKeySpec secret_key = new SecretKeySpec(keyByte, "HmacSHA256");
            try {
				sha256_HMAC.init(secret_key);
			} catch (InvalidKeyException e) {
				e.printStackTrace();
			}
            
            System.out.println("Secret key generated is "+secret_key);
            return Base64.getUrlEncoder().encodeToString(sha256_HMAC.doFinal(messageBytes));
            
         

    }
public AuthenticationRequest createOIDCAuthGrantRequest(String serviceId,
        String[] requestedScopes, String callbackURL, String endpointUrl, CodeVerifier codeVerifier, Nonce nonce ) throws JOSEException {
	
	Scope scope = new Scope();
	scope.add(OIDCScopeValue.OPENID);
   
	State stateId = new State(UUID.randomUUID().toString());
	
	
	
	//TODO
	//Persist codeVerifier, Nonce and stateId in database along with current timestamp
	
	
	
	ResponseType responseType = new ResponseType("code");
	
			request = new AuthenticationRequest.Builder(
			URI.create(endpointUrl),
            new ClientID(serviceId))
            .scope(scope)
            .state(stateId)
            .redirectionURI(URI.create(callbackURL))
            .endpointURI(URI.create(endpointUrl))
            .codeChallenge(codeVerifier, CodeChallengeMethod.S256)
			.nonce(nonce)
			.responseType(responseType)
			.build();
		
			State stateID = request.getState();
			URI redirectionURI = request.getRedirectionURI();
			scope = request.getScope();
			CodeChallenge codeChallenge = request.getCodeChallenge();
			String inputValue = ""+serviceId+aesKey+stateID+nonce+redirectionURI+scope+codeChallenge;
			
			apiHmac = hashHMACHex(aesKey, inputValue);
		
    System.out.println("request: "+request);
    System.out.println("apiHmac: "+apiHmac);
    return request;
}




}
