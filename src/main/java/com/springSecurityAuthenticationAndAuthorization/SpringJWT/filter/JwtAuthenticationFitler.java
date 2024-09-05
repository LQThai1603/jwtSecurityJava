package com.springSecurityAuthenticationAndAuthorization.SpringJWT.filter;

import java.io.IOException;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.springSecurityAuthenticationAndAuthorization.SpringJWT.service.JwtService;
import com.springSecurityAuthenticationAndAuthorization.SpringJWT.service.UserDetailsServiceImp;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtAuthenticationFitler extends OncePerRequestFilter{ //OncePerRequestFilter, một lớp trừu tượng đảm bảo bộ lọc chỉ được thực hiện một lần trong một yêu cầu.

	private final JwtService jwtService; //OncePerRequestFilter, một lớp trừu tượng đảm bảo bộ lọc chỉ được thực hiện một lần trong một yêu cầu.

	private final UserDetailsServiceImp userDetailsService; //Dịch vụ lấy thông tin người dùng từ cơ sở dữ liệu, dựa trên tên đăng nhập (username).

	public JwtAuthenticationFitler(JwtService jwtService, UserDetailsServiceImp userDetailsService) {
		super();
		this.jwtService = jwtService;
		this.userDetailsService = userDetailsService;
	}

	@Override
	protected void doFilterInternal( //Đây là phương thức chính thực hiện việc lọc các yêu cầu HTTP
			HttpServletRequest request, //Đối tượng đại diện cho yêu cầu HTTP hiện tại
			HttpServletResponse response, //Đối tượng đại diện cho phản hồi HTTP.
			FilterChain filterChain) //Đối tượng đại diện cho chuỗi các bộ lọc tiếp theo trong quá trình xử lý yêu cầu.
			throws ServletException, IOException {
		
		String authHeader = request.getHeader("Authorization"); //Lấy giá trị của header Authorization từ yêu cầu HTTP. Đây là nơi chứa JWT trong các yêu cầu bảo mật.
		System.out.println("authHeader: " + authHeader);
		
		if(authHeader == null || !authHeader.startsWith("Bearer ")) { //Nếu authHeader là null hoặc không bắt đầu bằng "Bearer " (chuỗi token JWT thường bắt đầu bằng "Bearer "), thì không xử lý tiếp và chuyển yêu cầu đến bộ lọc tiếp theo trong chuỗi (filterChain.doFilter).
			filterChain.doFilter(request, response);
			return;
		}
		
		String token = authHeader.substring(7); //Trích xuất JWT: Lấy phần token thực tế từ authHeader, bỏ qua phần "Bearer " (7 ký tự đầu tiên).
		
		String username = jwtService.extractUsername(token); //Trích xuất tên người dùng (username) từ JWT bằng cách sử dụng dịch vụ JwtService.
		
		if(username != null && SecurityContextHolder.getContext().getAuthentication() == null) { //Kiểm tra: Nếu username không rỗng và không có người dùng nào đã được xác thực trước đó (kiểm tra qua SecurityContextHolder), thì tiếp tục quá trình xác thực.
			UserDetails userDetails = userDetailsService.loadUserByUsername(username); //Lấy thông tin chi tiết về người dùng từ cơ sở dữ liệu bằng cách sử dụng dịch vụ UserDetailsImp.
			
			if(jwtService.isValid(token, userDetails)) { // Kiểm tra xem JWT có hợp lệ với thông tin người dùng hay không. Điều này bao gồm kiểm tra tính toàn vẹn của token và đảm bảo rằng nó chưa hết hạn.
				UsernamePasswordAuthenticationToken authToken =  new UsernamePasswordAuthenticationToken( //Tạo đối tượng UsernamePasswordAuthenticationToken: Nếu JWT hợp lệ, tạo một đối tượng xác thực UsernamePasswordAuthenticationToken chứa thông tin người dùng (userDetails) và các quyền hạn của họ (userDetails.getAuthorities()).
						userDetails, null, userDetails.getAuthorities() //UsernamePasswordAuthenticationToken à một lớp trong Spring Security dùng để đại diện cho thông tin xác thực của người dùng khi họ đăng nhập vào ứng dụng
						);  
				//Khi Nào Được Sử Dụng?
				//Khi người dùng đăng nhập: Để xác thực thông tin đăng nhập và thiết lập quyền hạn.
				//Khi yêu cầu cần kiểm tra quyền truy cập: Để xác định người dùng có quyền thực hiện hành động nhất định hay không.
				authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request)); //Thiết lập chi tiết xác thực: Thiết lập chi tiết bổ sung cho đối tượng xác thực, như địa chỉ IP của người dùng, thông tin về session, v.v.
				//WebAuthenticationDetailsSource là một lớp của Spring Security cung cấp cách để xây dựng chi tiết xác thực từ yêu cầu HTTP hiện tại.
				//buildDetails(request) tạo ra một đối tượng WebAuthenticationDetails từ yêu cầu HTTP (HttpServletRequest). Đối tượng này bao gồm thông tin như địa chỉ IP của người dùng và các chi tiết khác liên quan đến yêu cầu HTTP.
				SecurityContextHolder.getContext().setAuthentication(authToken); //Đặt đối tượng xác thực vào SecurityContext: Đặt đối tượng authToken vào SecurityContextHolder, xác nhận rằng người dùng đã được xác thực.

			}
		}
		
		filterChain.doFilter(request, response); //Tiếp tục chuỗi bộ lọc: Sau khi hoàn thành quá trình xác thực, tiếp tục xử lý các bộ lọc tiếp theo trong chuỗi.
	}

}
