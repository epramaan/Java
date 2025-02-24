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
		if (session.getAttribute("jwtMap") != null) return new ModelAndView("LoginSuccessful"); 
		ModelAndView modelAndView = new ModelAndView("LoginUsingEPramaan");
		modelAndView.addObject("finalUrl", epramaanService.buildEpramaanAuthRequest());
		return modelAndView;
	}

	@PostMapping("/Epramaan/ProcessAuthCodeAndGetToken")
	public ModelAndView processAuthCodeAndGetToken(String code, String state, HttpSession session) throws Exception {
		ModelAndView modelAndView = new ModelAndView("LoginSuccessful");
		Map<String, Object> map = epramaanService.getJWTTokenFromEpramaan(code, state);
		session.setAttribute("jwtMap", map);
	    session.setAttribute("sessionId", map.get("session_id"));
	    session.setAttribute("sub", map.get("sub"));
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
