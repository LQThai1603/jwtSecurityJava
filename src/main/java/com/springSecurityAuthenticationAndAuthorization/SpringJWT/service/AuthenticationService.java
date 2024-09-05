package com.springSecurityAuthenticationAndAuthorization.SpringJWT.service;

import java.util.List;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.springSecurityAuthenticationAndAuthorization.SpringJWT.model.AuthenticationResponse;
import com.springSecurityAuthenticationAndAuthorization.SpringJWT.model.Token;
import com.springSecurityAuthenticationAndAuthorization.SpringJWT.model.User;
import com.springSecurityAuthenticationAndAuthorization.SpringJWT.repository.TokenRepository;
import com.springSecurityAuthenticationAndAuthorization.SpringJWT.repository.UserRepository;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Service
public class AuthenticationService {
	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;
	private final JwtService jwtService;
	private final AuthenticationManager authenticationManager;
	private final TokenRepository tokenRepository;
	
	public AuthenticationService(UserRepository userRepository, PasswordEncoder passwordEncoder,
			JwtService jwtService, AuthenticationManager authenticationManager, TokenRepository tokenRepository) {
		super();
		this.userRepository = userRepository;
		this.passwordEncoder = passwordEncoder;
		this.jwtService = jwtService;
		this.authenticationManager = authenticationManager; //một giao diện trung tâm chịu trách nhiệm xử lý quy trình xác thực.Nó xác minh thông tin xác thực (như tên người dùng và mật khẩu) của người dùng và trả về một đối tượng Authentication đã được xác thực nếu thông tin đó hợp lệ.
		this.tokenRepository = tokenRepository;
	}
	
	public AuthenticationResponse register(User request) {
		User user = new User();
		
		user.setFirstName(request.getFirstName());
		user.setLastName(request.getLastName());
		user.setUserName(request.getUserName());
		user.setRole(request.getRole());
		user.setPassword(passwordEncoder.encode(request.getPassword()));
		
		user = userRepository.save(user);
		
		String accessToken = jwtService.generateAccessToken(user); //create accessToken
		String refreshToken = jwtService.generateRefreshToken(user); // create refreshToken
		//save the gennerated token
		saveUserToken(user, accessToken);
		
		return new AuthenticationResponse(accessToken, refreshToken);
	}

	
	public AuthenticationResponse authenticate(User request) {
		authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(
						request.getUsername(), 
						request.getPassword()
						)
				);
		
		User user = userRepository.findByUsername(request.getUsername()).orElseThrow();
		String accessToken = jwtService.generateAccessToken(user);//create accessToken
		String refreshToken = jwtService.generateRefreshToken(user);// create refreshToken
		
		revokeAllTokenByUser(user);
		
		saveUserToken(user, accessToken);
		
		return new AuthenticationResponse(accessToken, refreshToken);
		
	}

	private void saveUserToken(User user, String jwt) { ////save the generated token
		Token token = new Token();
		token.setToken(jwt);
		token.setLoggedOut(false);
		token.setUser(user);
		tokenRepository.save(token);
	}
	
	private void revokeAllTokenByUser(User user) { //thu hồi tất cả các token còn hợp lệ của một người dùng cụ thể bằng cách đánh dấu các token đó là đã bị đăng xuất (logged out).
		List<Token> validTokenListByUser = tokenRepository.findAllTokenByUser(user.getId());
		if(!validTokenListByUser.isEmpty()) {
			validTokenListByUser.forEach(t->{
				t.setLoggedOut(true);
			});
		}
		tokenRepository.saveAll(validTokenListByUser);
	}

	public ResponseEntity refreshToken(HttpServletRequest request, HttpServletResponse response) {
		
		//extract the token from authorization header
		String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
		
		if(authHeader == null || !authHeader.startsWith("Bearer ")) {
			return new ResponseEntity(HttpStatus.UNAUTHORIZED);
		}
		
		String token = authHeader.substring(7);
		
		//extract unsername form token
		
		String username = jwtService.extractUsername(token);
		
		//check if  the user exist on database
		
		User user = userRepository.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException("No user found"));
		
		//now check if refresh token is valid
		
		if(jwtService.isValidRefreshToken(token, user)) {
			//generate access token 
			String accessToken = jwtService.generateAccessToken(user);
			String refeshToken = jwtService.generateRefreshToken(user);
			
			revokeAllTokenByUser(user);
			
			saveUserToken(user, accessToken);
			
			return new ResponseEntity(new AuthenticationResponse(accessToken, refeshToken), HttpStatus.OK);
		}
		return new ResponseEntity(HttpStatus.UNAUTHORIZED);
	}

}
