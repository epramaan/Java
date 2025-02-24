/* Pratik Dhote */

package in.cdac.epramaan.controller;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import in.cdac.epramaan.service.EPramaanService;
import jakarta.servlet.http.HttpSession;


@Controller
@RestController
public class EPramaanController {

	@Autowired
	EPramaanService epramaanService;
	
	@GetMapping("/")
	public ModelAndView loginUsingEpramaan(HttpSession session) throws Exception {
		if (session.getAttribute("jwtMap") != null && session.getAttribute("otv_completed").equals(true)) 
			return new ModelAndView("LoginSuccessful");
		session.invalidate();
		ModelAndView modelAndView = new ModelAndView("LoginUsingEPramaan");
		modelAndView.addObject("finalUrl", epramaanService.buildEpramaanAuthRequest());
		return modelAndView;
	}
	
	@PostMapping("/Epramaan/OneTimeVerificationForUser")
	public ModelAndView oneTimeVerificationForUser(String ssoToken, HttpSession session) throws Exception {
		Map<String, Object> ssoTokenMap = epramaanService.readSsoToken(ssoToken);
		session.setAttribute("jwtMap", ssoTokenMap);
	    session.setAttribute("sessionId", ssoTokenMap.get("session_id"));
	    session.setAttribute("sub", ssoTokenMap.get("sso_id"));
	    session.setAttribute("otv_completed", false);
		ModelAndView modelAndView = new ModelAndView("OneTimeVerificationForUser");
		modelAndView.addObject("epramaanId", ssoTokenMap.get("sso_id"));
		modelAndView.addObject("salt", EPramaanService.SALT);
		return modelAndView;	// Send to service login page with epramaanId and salt
	}

	@PostMapping("/Epramaan/OneTimePushBack")
	public ModelAndView oneTimePushBack(String username, String password, String epramaanId, String salt, HttpSession session) throws Exception { 
		// validate username-password and if successful, proceed for executeOneTimePushBack else throw exception
		String response = epramaanService.executeOneTimePushBack(username, epramaanId);
		if(response.equals("success")) {
			session.setAttribute("otv_completed", true);
			return new ModelAndView("LoginSuccessful", "message", response);
		}
		session.setAttribute("otv_completed", false);
		return new ModelAndView("errorPage", "message", response);
	}

	@PostMapping("/Epramaan/ProcessAuthCodeAndGetToken")
	public ModelAndView processAuthCodeAndGetToken(String code, String state, HttpSession session) throws Exception {
		ModelAndView modelAndView = new ModelAndView("LoginSuccessful");
		Map<String, Object> map = epramaanService.getJWTTokenFromEpramaan(code, state);
		session.setAttribute("jwtMap", map);
	    session.setAttribute("sessionId", map.get("session_id"));
	    session.setAttribute("sub", map.get("sso_id"));
	    session.setAttribute("otv_completed", true);
		return modelAndView;
	}

	@PostMapping("/Epramaan/CreateRequestForLogoutOnEpramaan")
	public ModelAndView createRequestForLogoutOnEpramaan(String sessionId, String sub) throws Exception {
		String data = epramaanService.buildEpramaanLogoutRequest(sessionId, sub);
		ModelAndView modelAndView = new ModelAndView("LogoutPostRedirectToEPramaan");
		modelAndView.addObject("data", data);	//keep the key "data" as it is
		modelAndView.addObject("logoutUrl", EPramaanService.LOGOUT_URI);
		return modelAndView;
	}
	
	@GetMapping("/Epramaan/LogoutOnEpramaan")	
	public ModelAndView logoutOnEpramaan(String LogoutResponse, HttpSession session) {
        String decodedString = new String(Base64.getDecoder().decode(LogoutResponse), StandardCharsets.UTF_8);
        JsonElement jsonElement = JsonParser.parseString(decodedString);
        JsonObject jsonObject = jsonElement.getAsJsonObject();
        String logoutStatus = jsonObject.get("logoutStatus").getAsString();
        ModelAndView modelAndView = new ModelAndView("LogoutResponse");
        modelAndView.addObject("jsonObject", jsonObject);
        modelAndView.addObject("logoutStatus", logoutStatus);
        session.invalidate();
        return modelAndView;
    }
}
