package com.springSecurityAuthenticationAndAuthorization.SpringJWT.controller;


import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.springSecurityAuthenticationAndAuthorization.SpringJWT.model.AuthenticationResponse;
import com.springSecurityAuthenticationAndAuthorization.SpringJWT.model.User;
import com.springSecurityAuthenticationAndAuthorization.SpringJWT.service.AuthenticationService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@RestController
public class AuthenticationController {

	private final AuthenticationService authenticationService;

	public AuthenticationController(AuthenticationService authenticationService) {
		super();
		this.authenticationService = authenticationService;
	}
	
	@PostMapping("/register")
	public ResponseEntity<AuthenticationResponse> register(@RequestBody User request){
		return ResponseEntity.ok(authenticationService.register(request));
	}
	
	@PostMapping("/login")
	public ResponseEntity<AuthenticationResponse> login(@RequestBody User request){
		return ResponseEntity.ok(authenticationService.authenticate(request));
	}
	
	@PostMapping("/refresh_token")
	public ResponseEntity refreshToken(
			HttpServletRequest request,
			HttpServletResponse response){
		return authenticationService.refreshToken(request, response);
	}
}
