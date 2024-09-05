package com.springSecurityAuthenticationAndAuthorization.SpringJWT.service;

import java.util.Date;
import java.util.function.Function;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import com.springSecurityAuthenticationAndAuthorization.SpringJWT.model.User;
import com.springSecurityAuthenticationAndAuthorization.SpringJWT.repository.TokenRepository;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {
	@Value("${application.security.jwt.secret-key}")
	private String secretKey;
	
	@Value("${application.security.jwt.accsess-token-expiration}")
	private long accessTokenExpiration;
	
	@Value("${application.security.jwt.refresh-token-expiration}")
	private long refreshTokenExpiration;
	private final TokenRepository tokenRepository;
	
	
	
	public JwtService(TokenRepository tokenRepository) {
		super();
		this.tokenRepository = tokenRepository;
	}

	public	String extractUsername(String token) {//Phương thức này dùng để giải mã JWT và trích xuất thông tin userName từ token
		return extractClaims(token, Claims::getSubject);
	}
	
	public boolean isValid(String token, UserDetails user) {
		String username = extractUsername(token);
		
		boolean isValidToken = tokenRepository.findByToken(token).map(t->!t.isLoggedOut()).orElse(false); // bien bollen kiem tra xem isLoggedOut() cua token co dang o trang thai false khong (chua dang xuat)
		
		return username.equals(user.getUsername()) && !isTokenExpired(token) && isValidToken;
	}
	
	public boolean isValidRefreshToken(String token, User user) {
		String username = extractUsername(token);
		
		return username.equals(user.getUsername()) && !isTokenExpired(token);
	}
	
	private boolean isTokenExpired(String token) {
		return extractExpiration(token).before(new Date());
	}

	private Date extractExpiration(String token) {//Phương thức này dùng để giải mã JWT và trích xuất thông tin thời gian tồn tại có hiệu lực của user từ token
		return extractClaims(token, Claims::getExpiration);
	}

	public <T> T extractClaims(String token, Function<Claims, T> resolver) { //Phương thức này dùng để giải mã JWT và trích xuất thông tin mong muốn (không phải tất cả) (claim) từ token
		//String token: Tham số đầu vào, là JWT cần được giải mã
		//Function<Claims, T> resolver: Đây là một đối tượng Function nhận đầu vào là Claims và trả về kiểu dữ liệu T. Đây là một hàm tùy chỉnh để xử lý và chuyển đổi Claims thành kiểu dữ liệu mong muốn
		Claims calims = extractAllClaims(token);  // Gọi phương thức extractAllClaims(token) (phương thức riêng của lớp JwtService) để giải mã token và lấy các thông tin (claims). Kết quả được lưu vào biến claims kiểu Claims
		return resolver.apply(calims); // Áp dụng hàm resolver vào đối tượng claims. Hàm resolver sẽ xử lý claims và trả về kết quả kiểu T. Kết quả này sẽ được trả về từ phương thức extractAllClaims.
		
	}
	
	private Claims extractAllClaims(String token) { //Phương thức này dùng để giải mã JWT và trích xuất các thông tin (claims) từ token.
		return Jwts
				.parser() //Tạo đối tượng phân tích JWT
				.verifyWith(getSigninKey()) //Xác thực token bằng khóa bí mật.
				.build() // Xây dựng đối tượng phân tích.
				.parseSignedClaims(token) // Phân tích token đã ký và trích xuất các claims
				.getPayload(); // Trả về payload của JWT chứa các thông tin mà bạn đã lưu trữ khi tạo token.
	}
	
	public String generateAccessToken(User user) { //Phương thức này dùng để tạo JWT cho một người dùng cụ thể
		return generateToken(user, accessTokenExpiration); //86400000
	}
	
	public String generateRefreshToken(User user) { //Phương thức này dùng để tạo JWT cho một người dùng cụ thể
		return generateToken(user, refreshTokenExpiration); //604800000
	}
	
	private String generateToken(User user, long expireTime) {//Phương thức này dùng để tạo JWT cho một người dùng cụ thể
		String token = Jwts
				.builder() //Tạo đối tượng builder để xây dựng JWT
				.subject(user.getUsername()) //Đặt phần chủ đề (subject) của JWT là tên người dùng
				.issuedAt(new Date(System.currentTimeMillis())) //Đặt thời điểm phát hành token là thời điểm hiện tại.
				.expiration(new Date(System.currentTimeMillis() + expireTime)) // Đặt thời gian hết hạn của token là 24 giờ sau thời điểm phát hành.
				.signWith(getSigninKey()) //Ký token bằng khóa bí mật để bảo mật
				.compact(); //Hoàn thiện việc xây dựng token và chuyển đổi thành chuỗi JWT.
		
		return token;
	}
	
	private SecretKey getSigninKey() { //Phương thức này dùng để lấy khóa bí mật dưới dạng SecretKey từ chuỗi khóa bí mật.
		byte[] keybytes = Decoders.BASE64URL.decode(secretKey); //Giải mã chuỗi khóa bí mật từ định dạng Base64 URL thành mảng byte.
		return Keys.hmacShaKeyFor(keybytes); //Tạo SecretKey bằng mảng byte và thuật toán HMAC SHA-256 từ Keys của thư viện JWT.
	}

}
