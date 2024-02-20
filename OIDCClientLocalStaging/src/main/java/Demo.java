import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest.Builder;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;

@WebServlet("/Demo")
public class Demo extends HttpServlet {
	
	RequestDispatcher dispatcher;
	
	@Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException, java.io.IOException {
		CodeVerifier codeVerifier = new CodeVerifier();
		Nonce nonceValue = new Nonce();
		String redirectionURL = null;
		String[] scope = {"OpenId"};
		
		System.out.println("codeVerifier: "+ codeVerifier.getValue());
		System.out.println("Nonce: "+ nonceValue.getValue());
		
		EpramaanOIDCConnector eoidc = new EpramaanOIDCConnector();
		AuthenticationRequest grantRequest = null;
		
			try {
				grantRequest = eoidc.createOIDCAuthGrantRequest("100000907", scope,"http://localhost:8081/OIDCClientLocalStaging/UDemo","https://epstg.meripehchaan.gov.in/openid/jwt/processJwtAuthGrantRequest.do",codeVerifier,nonceValue);

			} catch (JOSEException e) {
				e.printStackTrace();
			}
		
		request.getSession().setAttribute("codeVerifier", codeVerifier);
		System.out.println("apiHmac from Demo class: "+ eoidc.apiHmac);
		redirectionURL = grantRequest.toURI().toString()+"&apiHmac="+eoidc.apiHmac;
		System.out.println("redirectionURL: "+redirectionURL);
		request.setAttribute("redirectionURL", redirectionURL );
		dispatcher = request.getRequestDispatcher("post.jsp");
		dispatcher.forward(request, response);
		}

}
