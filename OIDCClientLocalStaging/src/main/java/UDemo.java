
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URI;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLContext;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import com.google.gson.Gson;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSVerifier;
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
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;

@WebServlet("/UDemo")
public class UDemo extends HttpServlet {

	private static final long serialVersionUID = 1L;

	@Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {

		System.out.println("*********inside doGet method of UDemo*************");

		doPost(request, response);

	}

	@Override
	protected void doPost(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {

		System.out.println("***********Inside doPost method of UDemo*************");

		String authCode = request.getParameter("code");
		String state = request.getParameter("state");
		String error = request.getParameter("error");
		String errorDesc = request.getParameter("error_description");
		String errorUri = request.getParameter("error_uri");
		if (error != null) {
			request.setAttribute("JWSClaimset", error + " : " + errorDesc);
			RequestDispatcher dispatcher;
			dispatcher = request.getRequestDispatcher("Claimset.jsp");
			dispatcher.forward(request, response);

		} else {

			PublicKey publicKey = UDemo.getPublicKey();
		
			System.out.println("publicKey=" + publicKey);

			System.out.println("authCode: " + authCode);
			System.out.println("state: " + state);
			DDemo dao = new DDemo();
			List<MDemo> myModellist = dao.fetchRecord(state);
			CodeVerifier codeVerifier = new CodeVerifier(myModellist.get(0).getCodeVerifier());
			TokenRequest tokenRequest = createOIDCTokenRequest("http://localhost:8081/OIDCClientLocalStaging/UDemo",
					authCode, "100000907", "https://epstg.meripehchaan.gov.in/openid/jwt/processJwtTokenRequest.do",
					codeVerifier);

			System.out.println("tokenRequest: " + tokenRequest);
			System.out.println(tokenRequest.toHTTPRequest().getQueryParameters());

			TrustStrategy acceptingTrustStrategy = (X509Certificate[] chain, String authType) -> true;

			SSLContext sslContext;
			try {
				sslContext = org.apache.http.ssl.SSLContexts.custom().loadTrustMaterial(null, acceptingTrustStrategy)
						.build();

				SSLConnectionSocketFactory csf = new SSLConnectionSocketFactory(sslContext);

				CloseableHttpClient httpClient = HttpClients.custom().setSSLSocketFactory(csf).build();

				HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory();

				requestFactory.setHttpClient(httpClient);
				RestTemplate restTemplate = new RestTemplate(requestFactory);
				
				Gson gson = new Gson();
				String json = gson.toJson(tokenRequest.toHTTPRequest().getQueryParameters());
				System.out.println("JSON: " + json);
				HttpHeaders headers = new HttpHeaders();
				headers.setContentType(MediaType.APPLICATION_JSON);
				HttpEntity<String>  entity = new HttpEntity<String>(json,headers);
				HttpMethod method = HttpMethod.POST;
				final String url = "https://epstg.meripehchaan.gov.in/openid/jwt/processJwtTokenRequest.do";
				ResponseEntity<String> authRespEntity = restTemplate.exchange(url, method,entity,String.class);
				String authResp = authRespEntity.getBody();
				

				System.out.println("authResp: " + authResp);

				// decrypting the authResp
				System.out.println("*****decrypting JWE using AES 256****************");
				System.out.println("*************decrypting JWE using NonceValue****************");
				System.out.println("-----------NonceValue in UDemo--------->" + myModellist.get(0).getNonce());
				SecretKeySpec secretKeySpec = (SecretKeySpec) generateAES256Key(myModellist.get(0).getNonce());

				JWEObject jweObject = JWEObject.parse(authResp);
				System.out.println("jweObject after parse method: " + jweObject.toString());

				jweObject.decrypt(new AESDecrypter(secretKeySpec));
				System.out.println("jweObject after decrypt method: " + jweObject.toString());

				System.out.println("jweObject payload: " + jweObject.getPayload());
				System.out.println("jweObject parsedString: " + jweObject.getParsedString());
				System.out.println("jweObject serialize: " + jweObject.serialize());
				System.out.println("jweObject parsedParts: " + jweObject.getParsedParts());

				SignedJWT signedJWT = jweObject.getPayload().toSignedJWT();

				System.out.println("signedJWT: " + signedJWT);

				System.out.println("RSAPublickey retrieved. Proceeding with verification. ");

				// Verifying signature of decrypted authResp
				JWSVerifier jwsVerifier = new RSASSAVerifier((RSAPublicKey) publicKey);

				// Checking the signature verification status
				boolean signatureVerified = signedJWT.verify(jwsVerifier);
				System.out.println("signatureVerified status: " + signatureVerified);
				RequestDispatcher dispatcher;
				if(!signatureVerified) {
					dispatcher = request.getRequestDispatcher("error.jsp");
					dispatcher.forward(request, response);
					return;
				}
				Map<String, Object> JWS = signedJWT.getPayload().toJSONObject();

				System.out.println("JWS: " + JWS);
//			
				System.out.println("JWS Claim Set: " + signedJWT.getPayload().toJSONObject());
				request.setAttribute("JWSClaimset", signedJWT.getPayload().toJSONObject());
				request.setAttribute("tokenRequestParameters", tokenRequest.toHTTPRequest().getQueryParameters());
				request.setAttribute("tokenRequestUrl", url);
				
				dispatcher = request.getRequestDispatcher("Claimset.jsp");
				dispatcher.forward(request, response);


			} catch (Exception e) {
				e.printStackTrace();
			}
		}
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
			String filepath = "C:/Users/demo/Documents/epramaan.crt";
//			String filepath = "C:/Users/CDAC-HP73/Documents/epramaan.pem";
			CertificateFactory certFac = CertificateFactory.getInstance("X.509");
			System.out.println("filepath: " + filepath);
			FileInputStream fis = new FileInputStream(filepath);

//			X509Certificate cer = (X509Certificate) certFac.generateCertificate(fis);
			Certificate cer = (Certificate) certFac.generateCertificate(fis);
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
}
