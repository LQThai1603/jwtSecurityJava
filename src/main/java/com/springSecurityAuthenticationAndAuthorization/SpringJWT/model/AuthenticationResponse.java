package com.springSecurityAuthenticationAndAuthorization.SpringJWT.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public class AuthenticationResponse {
	@JsonProperty("access_token")
	private String accessToken;
	
	@JsonProperty("refresh_token")
	private String refreshToken;
	public AuthenticationResponse(String accessToken, String refreshToken) {
		super();
		this.accessToken = accessToken;
		this.refreshToken = refreshToken;
	}
	public String getAccessToken() {
		return accessToken;
	}
	public String getRefreshToken() {
		return refreshToken;
	}
	
	
}
