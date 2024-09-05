package com.springSecurityAuthenticationAndAuthorization.SpringJWT.config;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;

import com.springSecurityAuthenticationAndAuthorization.SpringJWT.model.Token;
import com.springSecurityAuthenticationAndAuthorization.SpringJWT.repository.TokenRepository;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class CustomLogoutHandler implements LogoutHandler{

	private final TokenRepository tokenRepository;
	
	
	
	public CustomLogoutHandler(TokenRepository tokenRepository) {
		super();
		this.tokenRepository = tokenRepository;
	}



	@Override
	public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
		String authHeader = request.getHeader("Authorization"); //Lấy giá trị của header Authorization từ yêu cầu HTTP. Đây là nơi chứa JWT trong các yêu cầu bảo mật.
		System.out.println("authHeader: " + authHeader);
		
		if(authHeader == null || !authHeader.startsWith("Bearer ")) { //Nếu authHeader là null hoặc không bắt đầu bằng "Bearer " (chuỗi token JWT thường bắt đầu bằng "Bearer "), thì không xử lý tiếp và chuyển yêu cầu đến bộ lọc tiếp theo trong chuỗi (filterChain.doFilter).
			return;
		}
		
		String token = authHeader.substring(7); //Trích xuất JWT: Lấy phần token thực tế từ authHeader, bỏ qua phần "Bearer " (7 ký tự đầu tiên).
	
		//get the stored token in the database
		Token storedToken = tokenRepository.findByToken(token).orElse(null);
		
		//innvalidate the token i.e make logout true
		if(token != null) {
			storedToken.setLoggedOut(true);
			tokenRepository.save(storedToken);
		}
	
	}

}
