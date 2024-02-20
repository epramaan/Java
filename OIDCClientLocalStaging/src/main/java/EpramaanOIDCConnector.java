//adding this comment for testing git commands
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.UUID;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.stereotype.Component;

import com.nimbusds.jose.JOSEException;
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


public class EpramaanOIDCConnector {

	static String aesKey = "35485fb2-70d8-410c-9bf1-8ebd84d66524";
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
   
	State state = new State(UUID.randomUUID().toString());
	DDemo ddemo = new DDemo();
	ddemo.insertNewRecord(codeVerifier.getValue(), nonce.getValue(), state.getValue());
	
	ResponseType responseType = new ResponseType("code");
	
			request = new AuthenticationRequest.Builder(
			URI.create(endpointUrl),
            new ClientID(serviceId))
            .scope(scope)
            .state(state)
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
