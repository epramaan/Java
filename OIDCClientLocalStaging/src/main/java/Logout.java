//This comment has been added for testing git commands
import java.io.IOException;
import java.util.Arrays;
import java.util.Map;
import java.util.UUID;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.json.JSONObject;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

@WebServlet("/Logout")
public class Logout extends HttpServlet{

	
	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		System.out.println("Inside doGet method of Logout Servlet");
		doPost(req, resp);
	}
	
	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		System.out.println("Inside doPost method of Logout Servlet");

		
		String map = req.getParameter("tokenForLogout");
		System.out.println("tokenForLogout: "+ map);
		
		String logoutRequestId = UUID.randomUUID().toString();
		JSONObject json = new JSONObject(map);
		String clientId = "100000907";
		String sessionId = (String) json.getString("sid");
		String iss = "ePramaan";
		
		String sub = (String) json.getString("sub");
		String redirectUrl = "http://localhost:8081/OIDCClientLocalStaging";
		
		String inputValue = clientId+sessionId+iss+EpramaanOIDCConnector.aesKey+sub+redirectUrl;
		
		String hmac = EpramaanOIDCConnector.hashHMACHex(EpramaanOIDCConnector.aesKey, inputValue);
		
		String customParameter = "";
		RestTemplate restTemplate = new RestTemplate();
		HttpHeaders headers = new HttpHeaders();
		
		String url = "https://epstg.meripehchaan.gov.in/openid/jwt/processOIDCSLORequest.do";
		String data = "{\"clientId\":\"100000907\",\"sessionId\":\""+sessionId+"\",\"hmac\":\""+hmac+"\",\"iss\":\"ePramaan\",\"logoutRequestId\":\""+logoutRequestId+"\",\"sub\":\""+sub+"\",\"redirectUrl\":\""+redirectUrl+"\",\"customParameter\":\""+customParameter+"\"}";
		
		System.out.println("json string of data: "+ data);

		
		
		req.setAttribute("redirectionURL", url);
		req.setAttribute("data", data);
		RequestDispatcher dispatcher;
		dispatcher = req.getRequestDispatcher("post2.jsp");
		dispatcher.forward(req, resp);
	}
}
