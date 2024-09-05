package com.springSecurityAuthenticationAndAuthorization.SpringJWT.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.springSecurityAuthenticationAndAuthorization.SpringJWT.filter.JwtAuthenticationFitler;
import com.springSecurityAuthenticationAndAuthorization.SpringJWT.service.UserDetailsServiceImp;

@Configuration
@EnableWebSecurity //Kích hoạt tính năng bảo mật web của Spring Security cho ứng dụng
public class SecurityConfig {
	private final UserDetailsServiceImp userDetailsServiceImp;
	private final JwtAuthenticationFitler jwtauthenticationFilter;
	private final CustomAccessDeniedHandler accessDeniedHandler;
	private final CustomLogoutHandler logoutHandler;

	

	public SecurityConfig(UserDetailsServiceImp userDetailsServiceImp, JwtAuthenticationFitler jwtauthenticationFilter,
			CustomAccessDeniedHandler accessDeniedHandler, CustomLogoutHandler logoutHandler) {
		super();
		this.userDetailsServiceImp = userDetailsServiceImp;
		this.jwtauthenticationFilter = jwtauthenticationFilter;
		this.accessDeniedHandler = accessDeniedHandler;
		this.logoutHandler = logoutHandler;
	}

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{ //SecurityFilterChain để xử lý authorization(ủy quền, cho phép)
		
		return http
				.csrf(AbstractHttpConfigurer::disable) //Vô hiệu hóa CSRF (Cross-Site Request Forgery) để không yêu cầu token CSRF cho các yêu cầu. Điều này hữu ích trong các API RESTful, nơi mà CSRF thường không cần thiết.
				.authorizeHttpRequests( //authorizeHttpRequests(): Cấu hình các quy tắc xác thực cho các yêu cầu HTTP
						req->req.requestMatchers("/login/**", "/register/**", "/refresh_token/**") //req: Là biến đại diện cho HttpSecurity.RequestMatcherRegistry
						.permitAll() //req.requestMatchers("/login/**", "/register/**").permitAll(): Cho phép tất cả các yêu cầu truy cập các endpoint /login/** và /register/** mà không cần xác thực.
						.requestMatchers("/admin_only/**").hasAuthority("Admin")
						.anyRequest()
						.authenticated() //anyRequest().authenticated(): Yêu cầu xác thực cho tất cả các yêu cầu khác.
						).userDetailsService(userDetailsServiceImp) //userDetailsService(userDetailsServiceImp): Cấu hình userDetailsService tùy chỉnh để Spring Security sử dụng trong quá trình xác thực.
				.exceptionHandling(e->e.accessDeniedHandler(accessDeniedHandler) //e.accessDeniedHandler(accessDeniedHandler): Đây là nơi cấu hình AccessDeniedHandler tùy chỉnh, trong trường hợp người dùng đã được xác thực nhưng cố gắng truy cập vào một tài nguyên mà họ không có quyền. Trong trường hợp này, CustomAccessDeniedHandler sẽ xử lý yêu cầu và trả về mã trạng thái HTTP 403 (Forbidden) cho người dùng, như đã được định nghĩa trong lớp CustomAccessDeniedHandler.
						.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))) //e.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)): Đây là nơi cấu hình AuthenticationEntryPoint. Nó được sử dụng khi người dùng chưa được xác thực (chưa đăng nhập) mà cố gắng truy cập vào một tài nguyên yêu cầu xác thực. HttpStatusEntryPoint sẽ trả về mã trạng thái HTTP 401 (Unauthorized) để thông báo rằng người dùng cần đăng nhập trước khi truy cập tài nguyên
				.sessionManagement(session->session //SessionManagementConfigurer<HttpSecurity>.SessionCreationPolicyConfigurer: Đây là một lớp trong Spring Security dùng để cấu hình cách Spring Security quản lý phiên làm việc (session) của người dùng.
						.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) //.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)): Thiết lập chính sách quản lý session là STATELESS, nghĩa là không lưu trữ trạng thái session trên server, thường sử dụng cho các ứng dụng API RESTful để mỗi yêu cầu đều là độc lập.
				.addFilterBefore(jwtauthenticationFilter, UsernamePasswordAuthenticationFilter.class) //addFilterBefore(jwtauthenticationFilter, UsernamePasswordAuthenticationFilter.class): Thêm bộ lọc JWT (jwtauthenticationFilter) vào chuỗi bộ lọc của Spring Security, và đảm bảo nó được thực thi trước bộ lọc UsernamePasswordAuthenticationFilter.
				.logout(l->l.logoutUrl("/logout") // xu ly logout
						.addLogoutHandler(logoutHandler)
						.logoutSuccessHandler(
								(request, response, authentication) -> SecurityContextHolder.clearContext()
								))
				.build(); //build(): Xây dựng và trả về đối tượng SecurityFilterChain với cấu hình đã định.
				
	}
	
	@Bean
	public PasswordEncoder passwordEncoder() { //PasswordEncoder passwordEncoder(): Định nghĩa một bean PasswordEncoder sử dụng thuật toán mã hóa BCrypt để mã hóa mật khẩu người dùng trước khi lưu vào cơ sở dữ liệu.
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception { //AuthenticationManager authenticationManager(AuthenticationConfiguration configuration): Định nghĩa một AuthenticationManager bean sử dụng cấu hình hiện tại (AuthenticationConfiguration). AuthenticationManager chịu trách nhiệm quản lý xác thực trong ứng dụng Spring Security.
		return configuration.getAuthenticationManager();
	}
}
