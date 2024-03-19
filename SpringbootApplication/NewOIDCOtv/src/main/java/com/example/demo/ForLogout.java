package com.example.demo;

import org.springframework.stereotype.Component;

@Component
public class ForLogout{

	private String sessionId;

	private String sub; 
	
	public String getSessionId() {
		return sessionId;
	}

	public void setSessionId(String sessionId) {
		this.sessionId = sessionId;
	}

	public String getSub() {
		return sub;
	}

	public void setSub(String sub) {
		this.sub = sub;
	}
	
	
	
}
