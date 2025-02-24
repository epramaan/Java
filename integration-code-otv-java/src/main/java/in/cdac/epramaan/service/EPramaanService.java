/* Pratik Dhote */

package in.cdac.epramaan.service;

import java.io.FileInputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.json.JSONObject;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.AESDecrypter;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;

@Component
public class EPramaanService {

	public static final String SCOPE = "openid";
	public static final String RESPONSE_TYPE = "code";
	public static final String CPDE_CHALLENGE_METHOD = "S256";
	public static final String GRANT_TYPE = "authorization_code";
	public static final String ISS = "ePramaan";

	public static final String SALT = "1****6";
	private static final String CLIENT_ID = "1*******0";
	private static final String AES_KEY = "j0****4-c**b-4**a-9**9-a**********6";
	private static final String REDIRECT_URI = "http://localhost:8080/Epramaan/ProcessAuthCodeAndGetToken";
	private static final String SERVICE_LOGOUT_URI = "http://localhost:8080/Epramaan/LogoutOnEpramaan";
	private static final String CERTIFICATE_PATH = "/epramaan.crt";
	private static final String CUSTOM_PARAMETER = "WhateverValueServiceWant";

	public static final String AUTH_GRANT_REQUEST_URI = "https://epstg.meripehchaan.gov.in/openid/jwt/processJwtAuthGrantRequest.do";
	public static final String TOKEN_REQUEST_URI = "https://epstg.meripehchaan.gov.in/openid/jwt/processJwtTokenRequest.do";
	public static final String LOGOUT_URI = "https://epstg.meripehchaan.gov.in/openid/jwt/processOIDCSLORequest.do";
    public static final String PUSH_BACK_URI = "https://epstg.meripehchaan.gov.in/rest/epramaan/enrol/response";

    
	private CodeVerifier codeVerifier;
	private State stateID;
	private Nonce nonce;

	public String buildEpramaanAuthRequest() throws Exception {

		//1. save codeVerifier, stateID, nonce in db
		stateID = new State(UUID.randomUUID().toString());
		nonce = new Nonce();
		codeVerifier = new CodeVerifier();

		Scope scope = new Scope();
		scope.add(OIDCScopeValue.OPENID);

		AuthenticationRequest authenticationRequest = 
				new AuthenticationRequest.Builder(URI.create(AUTH_GRANT_REQUEST_URI), new ClientID(CLIENT_ID))
				.scope(scope)
				.state(stateID)
				.redirectionURI(URI.create(REDIRECT_URI))
				.endpointURI(URI.create(AUTH_GRANT_REQUEST_URI))
				.codeChallenge(codeVerifier, CodeChallengeMethod.S256)
				.nonce(nonce)
				.responseType(new ResponseType(RESPONSE_TYPE)).build();

		String inputValue = CLIENT_ID + AES_KEY + stateID + nonce + REDIRECT_URI + SCOPE + authenticationRequest.getCodeChallenge();
		String apiHmac = hashHMACHex(inputValue, AES_KEY);
		String finalUrl = authenticationRequest.toURI().toString() + "&apiHmac=" + apiHmac;
		return finalUrl;
	}

	public Map<String, Object> getJWTTokenFromEpramaan(String code, String state) throws Exception {
		//2. Retrieve codeVerifier, stateID, nonce in db against state
		if (!this.stateID.getValue().equals(state)) {
			throw new Exception("State does not match");
		}
		JSONObject data = new JSONObject();
		data.put("code", new String[] { code });
		data.put("grant_type", new String[] { GRANT_TYPE });
		data.put("scope", new String[] { SCOPE });
		data.put("redirect_uri", new String[] { AUTH_GRANT_REQUEST_URI });
		data.put("request_uri", new String[] { REDIRECT_URI });
		data.put("code_verifier", new String[] { codeVerifier.getValue() });
		data.put("client_id", new String[] { CLIENT_ID });

		RestTemplate restTemplate = new RestTemplate();
		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_JSON);
		HttpEntity<String> entity = new HttpEntity<String>(data.toString(), headers);
		ResponseEntity<String> responseData = restTemplate.exchange(TOKEN_REQUEST_URI, HttpMethod.POST, entity, String.class);
		String jweToken = responseData.getBody();
		System.out.println("jweToken : " + jweToken);
		SecretKeySpec secretKeySpec = (SecretKeySpec) generateAES256Key(nonce.toString());
		JWEObject jweObject = JWEObject.parse(jweToken);
		jweObject.decrypt(new AESDecrypter(secretKeySpec));
		SignedJWT signedJWT = jweObject.getPayload().toSignedJWT();
		JWSVerifier jwsVerifier = new RSASSAVerifier((RSAPublicKey) getPublicKey());
		boolean signatureVerified = signedJWT.verify(jwsVerifier);

		if (signatureVerified) {
			Map<String, Object> JWS = signedJWT.getPayload().toJSONObject();
			System.out.println("JWT: " + JWS);
			return signedJWT.getPayload().toJSONObject();
		}
		return null;
	}

	public String buildEpramaanLogoutRequest(String sessionId, String sub) throws Exception {
		String logoutRequestId = UUID.randomUUID().toString();
		String inputValue = CLIENT_ID + sessionId + ISS + AES_KEY + sub + SERVICE_LOGOUT_URI;
		String hmac = hashHMACHex(inputValue, AES_KEY);
		JSONObject data = new JSONObject();
		data.put("clientId", CLIENT_ID);
		data.put("sessionId", sessionId);
		data.put("hmac", hmac);
		data.put("iss", ISS);
		data.put("logoutRequestId", logoutRequestId);
		data.put("sub", sub);
		data.put("redirectUrl", SERVICE_LOGOUT_URI);
		data.put("customParameter", CUSTOM_PARAMETER);
		return data.toString();
	}

	private static String hashHMACHex(String inputValue, String hMACKey) throws Exception {
			Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
			SecretKeySpec secret_key = new SecretKeySpec(hMACKey.getBytes(StandardCharsets.US_ASCII), "HmacSHA256");
			sha256_HMAC.init(secret_key);
			return Base64.getUrlEncoder().encodeToString(sha256_HMAC.doFinal(inputValue.getBytes(StandardCharsets.US_ASCII)));
	}

	public static PublicKey getPublicKey() throws Exception {
		CertificateFactory certFac = CertificateFactory.getInstance("X.509");
		FileInputStream fis = new FileInputStream(CERTIFICATE_PATH);
		X509Certificate cer = (X509Certificate) certFac.generateCertificate(fis);
		PublicKey publicKey = cer.getPublicKey();
		return publicKey;
	}

	public Key generateAES256Key(String seed) throws Exception {
		MessageDigest sha256 = null;
		sha256 = MessageDigest.getInstance("SHA-256");
		byte[] passBytes = seed.getBytes();
		byte[] passHash = sha256.digest(passBytes);
		SecretKeySpec secretKeySpec = new SecretKeySpec(passHash, "AES");
		return secretKeySpec;
	}
	
	public Map<String, Object> readSsoToken(String ssoToken) throws Exception {
		String decryptedText = decrypt(ssoToken, AES_KEY, SALT);
		ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.readValue(decryptedText, new TypeReference<Map<String, Object>>() {});
	}
	
	public String executeOneTimePushBack(String username, String epramaanId) throws Exception {
		String transactionId = epramaanId;
		long responseTimestamp = new Date().getTime();
		int serviceId = Integer.parseInt(CLIENT_ID);
		String serviceUserId = username;
		Boolean verified = true;
		
		Map<String, Object> pushBackObj = new HashMap<>();
		pushBackObj.put("transactionId", transactionId);
		pushBackObj.put("responseTimestamp", responseTimestamp);
		pushBackObj.put("serviceId", serviceId);
		pushBackObj.put("serviceUserId", serviceUserId);
		pushBackObj.put("verified", verified);

		ObjectMapper objectMapper = new ObjectMapper();
		String plainTextEnrolSPServiceResponse = objectMapper.writeValueAsString(pushBackObj) + SALT;
		String encryptedEnrolSPServiceResponse = encrypt(plainTextEnrolSPServiceResponse, AES_KEY, SALT);

		Map<String, Object> jsonVariables = new HashMap<>();
		jsonVariables.put("serviceId", CLIENT_ID);
		jsonVariables.put("encryptedEnrolSPServiceResponse", encryptedEnrolSPServiceResponse);
		String EnrolSPServiceResponseWrapper = objectMapper.writeValueAsString(jsonVariables);
		
		RestTemplate restTemplate = new RestTemplate();
		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_JSON);

		HttpEntity<String> entity = new HttpEntity<String>(EnrolSPServiceResponseWrapper, headers);
		ResponseEntity<String> response = restTemplate.exchange(PUSH_BACK_URI, HttpMethod.POST, entity, String.class);

		return response.getBody();
	}
	
	public String encrypt(String plainText, String seed, String salt) throws Exception {
		SecretKeySpec secretKeySpec = (SecretKeySpec) generateAES256Key(seed);
		byte[] plainTextByte = (plainText + salt).getBytes();
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
		byte[] encryptedByte = cipher.doFinal(plainTextByte);
		String encryptedText = Base64.getEncoder().encodeToString(encryptedByte);
		return encryptedText;
	}

	public String decrypt(String encryptedText, String seed, String salt) throws Exception {
		SecretKeySpec secretKeySpec = (SecretKeySpec) generateAES256Key(seed);
		byte[] encryptedTextByte = Base64.getDecoder().decode(encryptedText);
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
		byte[] decryptedByte = cipher.doFinal(encryptedTextByte);
		String decryptedText = new String(decryptedByte);
		decryptedText = decryptedText.substring(0, decryptedText.lastIndexOf(salt));
		return decryptedText;
	}

}
