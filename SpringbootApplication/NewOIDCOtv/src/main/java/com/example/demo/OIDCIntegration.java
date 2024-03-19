package com.example.demo;
import org.json.JSONObject;
import java.io.FileInputStream;
import java.net.URI;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.ModelAndView;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.crypto.AESDecrypter;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;

import jakarta.servlet.http.HttpServletRequest;

@Controller
public class OIDCIntegration {
	
	
	
	private static Map<String, String> sampleCredentials;
	
	static {
		System.out.println("Inside static block");
		sampleCredentials = new HashMap<>();
		sampleCredentials.put("demouser1", "demo1");
		sampleCredentials.put("demouser2", "demo2");
		sampleCredentials.put("demouser3", "demo3");
	}
	
	@Autowired
	private ForLogout forLogout;
	
	@GetMapping("/")
	public String homePage(){
		System.out.println("Inside homePage method");
		return "index";
	}
	
	@GetMapping("/Demo")
	public ModelAndView createOIDCAuthGrantRequest(HttpServletRequest request) {
		System.out.println("Inside createOIDCAuthGrantRequest method");
		
		CodeVerifier codeVerifier = new CodeVerifier();
		
		Nonce nonce = new Nonce();
		
				
		String redirectionURL = null;
	
		String[] scope = {"OpenId"};
		
		System.out.println("codeVerifier: "+ codeVerifier.getValue());
		System.out.println("Nonce: "+ nonce.getValue());
		
		EpramaanOIDCConnector eoidc = new EpramaanOIDCConnector();
		AuthenticationRequest grantRequest = null;
		
			try {
				grantRequest = eoidc.createOIDCAuthGrantRequest("1000013XX", scope,"http://localhost:8083/UDemo","https://epstg.meripehchaan.gov.in/openid/jwt/processJwtAuthGrantRequest.do",codeVerifier,nonce);

			} catch (JOSEException e) {
				e.printStackTrace();
			}
		
		
		request.getSession().setAttribute("codeVerifier", codeVerifier);
		System.out.println("apiHmac from Demo method: "+ eoidc.apiHmac);
		redirectionURL = grantRequest.toURI().toString()+"&apiHmac="+eoidc.apiHmac;
		System.out.println("redirectionURL: "+redirectionURL);
		ModelAndView modelAndView = new ModelAndView();
		modelAndView.setViewName("post");
		modelAndView.addObject("redirectionURL", redirectionURL);
		return modelAndView;
	}

	public Key generateAES256Key(String seed) {
		System.out.println(seed);
		MessageDigest sha256 = null;
		try {
			sha256 = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		byte[] passBytes = seed.getBytes();
		System.out.println(passBytes.length);
		byte[] passHash = sha256.digest(passBytes);
		System.out.println(passHash.length);
		SecretKeySpec secretKeySpec = new SecretKeySpec(passHash, "AES");

		return secretKeySpec;
	}

	public static PublicKey getPublicKey() {
		try {
			String filepath = "ePramaan certificate path";
			CertificateFactory certFac = CertificateFactory.getInstance("X.509");
			System.out.println(filepath);
			FileInputStream fis = new FileInputStream(filepath);

			X509Certificate cer = (X509Certificate) certFac.generateCertificate(fis);
			PublicKey publicKey = cer.getPublicKey();
			return publicKey;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}

	}

	private TokenRequest createOIDCTokenRequest(String callbackURL, String authCode, String serviceId,
			String endPointURL, CodeVerifier codeVerifier) {
		AuthorizationCode code = new AuthorizationCode(authCode);
		URI callback = URI.create(callbackURL);

		AuthorizationGrant codeGrant = new AuthorizationCodeGrant(code, callback, codeVerifier);
		ClientID clientID = new ClientID(serviceId);

		URI tokenEndpoint = URI.create(endPointURL);

		Scope scope = new Scope();
		scope.add(OIDCScopeValue.OPENID);

		Map<String, List<String>> map = new HashMap<>();

		List<String> arr = new ArrayList<>();

		arr.add("clientSecret");

		map.put("params", arr);

		TokenRequest request = new TokenRequest(tokenEndpoint, clientID, codeGrant, scope, null, null, map);

		return request;
	}
	
	@RequestMapping(value="/UDemo", method = {RequestMethod.GET, RequestMethod.POST})
	public ModelAndView consumeAuthCodeAndCreateTokenRequest(HttpServletRequest request) {
		ModelAndView modelAndView = new ModelAndView();
		String authCode = request.getParameter("code");
		String state = request.getParameter("state");
		String error = request.getParameter("error");
		String errorDesc = request.getParameter("error_description");
		String errorUri = request.getParameter("error_uri");
		if (error != null) {
			modelAndView.setViewName("claimset");
			modelAndView.addObject("JWSClaimset", error + " : " + errorDesc);
			return modelAndView;

		} else {
				Map<String, Object> map = fetchJWTToken(authCode, state);
				request.setAttribute("JWSClaimset", map);
				request.setAttribute("tokenRequestParameters", map);
				modelAndView.setViewName("claimset");
				modelAndView.addObject("JWSClaimset", map);
				return modelAndView;
		}
	}
	
	@RequestMapping(value="/oneTimeVerification", method = {RequestMethod.GET,RequestMethod.POST})	
	public ModelAndView verifyFirstTimeUser(@RequestParam(required = false) String state, @RequestParam(required = false) String code, @RequestParam(required=false) String ssoToken) throws Exception {
		System.out.println("Inside verifyFirstTimeUser method");
		ModelAndView modelAndView = new ModelAndView();
		System.out.println("state in OTV: " + state);
		System.out.println("code in OTV: " + code);
		System.out.println("sso token: " + ssoToken);
		
		String ePramaanId = null;
		
		if(ssoToken != null) {
			TokenEnc tenc = new TokenEnc();
			String decryptedJsonSSOToken = tenc.decrypt(ssoToken, EpramaanOIDCConnector.aesKey,
					EpramaanOIDCConnector.salt);
			System.out.println("Decrypted SSO Token " + decryptedJsonSSOToken);
			JSONObject json = new JSONObject(decryptedJsonSSOToken);
			ePramaanId = (String) json.get("sso_id");
		}else {
		Map<String, Object> map = fetchJWTToken(code, state);
		ePramaanId = (String)map.get("sso_id");
		System.out.println("ePramaanId: " + ePramaanId);
		}
		
		modelAndView.setViewName("oneTimePushback");
		modelAndView.addObject("ePramaanId", ePramaanId);
		return modelAndView;
		
	}
	
	@GetMapping("/oneTimePushback")
	public String afterPushBack(@RequestParam("username") String serviceUserId, @RequestParam("password") String password, @RequestParam("SSO_Id") String ssoId, HttpServletRequest req) throws Exception {
		System.out.println("Inside afterPushBack method");
		System.out.println("serviceUserId: " + serviceUserId);
		System.out.println("ssoId: " + ssoId);
		if(!sampleCredentials.get(serviceUserId).equals(password)) {
			req.setAttribute("msgForUser", "Invalid credentials");
			req.setAttribute("ePramaanId", ssoId);
			return "oneTimePushback";
		};
		
		int serviceId = Integer.parseInt("1000013XX");
		String ePramaanUrl = "https://epstg.meripehchaan.gov.in/rest/epramaan/enrol/response";
		EnrolSPServiceResponse enspr = new EnrolSPServiceResponse();
		enspr.setServiceId(serviceId);
		enspr.setServiceUserId(serviceUserId);
		enspr.setTransactionId(UUID.fromString(ssoId));
		enspr.setResponseTimestamp(Calendar.getInstance().getTimeInMillis());
		enspr.setVerified(true);
		
		ObjectMapper objectMapper = new ObjectMapper();
		String requestJSON = objectMapper.writeValueAsString(enspr);
		System.out.println("Request Json : " + requestJSON);
		TokenEnc tenc = new TokenEnc();
		String encryptedEnrolResp = tenc
				.encrypt(requestJSON, EpramaanOIDCConnector.aesKey, EpramaanOIDCConnector.salt).trim();
		
		EnrolSPServiceResponseWrapper ensprw = new EnrolSPServiceResponseWrapper();
		ensprw.setEncryptedEnrolSPServiceResponse(encryptedEnrolResp);
		ensprw.setServiceId(serviceId);
		
		RestTemplate restTemplate = new RestTemplate();
		String otvResp = restTemplate.postForObject(ePramaanUrl, ensprw, String.class);
		System.out.println("Response: " + otvResp);
		
		//model.addAttribute("otvResp", otvResp);
		req.setAttribute("otvResp", otvResp);
		return "otvResponse";
		
	}
	
	public Map<String, Object> fetchJWTToken(String authCode, String state){
		System.out.println("Inside fetchJWTToken method");
		PublicKey publicKey = getPublicKey();
		
		System.out.println("publicKey=" + publicKey);

		System.out.println("authCode: " + authCode);
		System.out.println("state: " + state);
		
		
		//TODO
		//Fetch codeVerifier, nonce against the state received in the query parameter
		
		String codeVerifierFromDb = "codeVerifer value fetched from Database";
		CodeVerifier codeVerifier = new CodeVerifier(codeVerifierFromDb);
		
		TokenRequest tokenRequest = createOIDCTokenRequest("http://localhost:8083/UDemo", authCode,
		"1000013XX", "https://epstg.meripehchaan.gov.in/openid/jwt/processJwtTokenRequest.do",
		codeVerifier);

		System.out.println("tokenRequest: " + tokenRequest);
		System.out.println(tokenRequest.toHTTPRequest().getQueryParameters());


	RestTemplate restTemplate = new RestTemplate();
	
	final String url = "https://epstg.meripehchaan.gov.in/openid/jwt/processJwtTokenRequest.do";
	String authResp = restTemplate.postForObject(url, tokenRequest.toHTTPRequest().getQueryParameters(),
			String.class);
	System.out.println("authResp: " + authResp);

	// decrypting the authResp
	System.out.println("*****decrypting JWE using AES 256****************");
	System.out.println("*************decrypting JWE using NonceValue****************");
	
	String nonce = "nonce value fetched from Database";
	SecretKeySpec secretKeySpec = (SecretKeySpec) generateAES256Key(nonce);

	System.out.println("-----------NonceValue in UDemo--------->" + nonce);

	JWEObject jweObject = null;
	try {
		jweObject = JWEObject.parse(authResp);
	} catch (ParseException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	System.out.println("jweObject after parse method: " + jweObject.toString());

	try {
		jweObject.decrypt(new AESDecrypter(secretKeySpec));
	} catch (KeyLengthException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (JOSEException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	System.out.println("jweObject after decrypt method: " + jweObject.toString());

	System.out.println("jweObject payload: " + jweObject.getPayload());
	System.out.println("jweObject parsedString: " + jweObject.getParsedString());
	System.out.println("jweObject serialize: " + jweObject.serialize());
	System.out.println("jweObject parsedParts: " + jweObject.getParsedParts());

	SignedJWT signedJWT = jweObject.getPayload().toSignedJWT();

	System.out.println("signedJWT: " + signedJWT);

	System.out.println("RSAPublickey retrieved. Proceeding with verification. ");

	// Verifying signature of decrypted authResp
	JWSVerifier jwsVerifier = new RSASSAVerifier((RSAPublicKey) getPublicKey());

	// Checking the signature verification status
	boolean signatureVerified = false;
	try {
		signatureVerified = signedJWT.verify(jwsVerifier);
	} catch (JOSEException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}


	 Map<String, Object> JWS = signedJWT.getPayload().toJSONObject();
	
	 System.out.println("JWS: "+ JWS);
	 forLogout.setSessionId((String)JWS.get("session_id"));
	 forLogout.setSub((String)JWS.get("sub"));
	System.out.println("JWS Signature is valid: " + signatureVerified);
	System.out.println("JWS Claim Set: " + signedJWT.getPayload().toJSONObject());
	return signedJWT.getPayload().toJSONObject();
	}
	
	
	@GetMapping("/Logout")
	public String logoutFromePramaan(HttpServletRequest request) {
		System.out.println("Inside logoutFromePramaan method");
		
		String sessionId = forLogout.getSessionId();
		System.out.println("sessionId: " + sessionId);
		String logoutRequestId = UUID.randomUUID().toString();
		
		String clientId = "1000013XX";
		String iss = "ePramaan";
		
		String sub = forLogout.getSub();
		System.out.println("sub: " + sub);
		String redirectUrl = "http://localhost:8083/";
		
		String inputValue = clientId+sessionId+iss+logoutRequestId+sub+redirectUrl;
		
		String hmac = EpramaanOIDCConnector.hashHMACHex(logoutRequestId, inputValue);
		
		String customParameter = "";
		
		
		String url = "https://epstg.meripehchaan.gov.in/openid/jwt/processOIDCSLORequest.do";
		String data = "{\"clientId\":\"1000013XX\",\"sessionId\":\""+sessionId+"\",\"hmac\":\""+hmac+"\",\"iss\":\"ePramaan\",\"logoutRequestId\":\""+logoutRequestId+"\",\"sub\":\""+sub+"\",\"redirectUrl\":\""+redirectUrl+"\",\"customParameter\":\""+customParameter+"\"}";
		
		System.out.println("json string of data: "+ data);
		request.setAttribute("redirectionURL", url);
		request.setAttribute("data", data);
		return "post";
	}

	
}
