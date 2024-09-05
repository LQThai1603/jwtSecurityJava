package com.springSecurityAuthenticationAndAuthorization.SpringJWT.model;

import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;

@Entity
@Table(name = "user")
public class User implements UserDetails{ // interface xac thuc nguoi dung, phan quyen nguoi  dung
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "id")
	private Integer id;
	
	@Column(name = "first name")
	private String firstName;
	
	@Column(name = "last name")
	private String lastName;
	
	@Column(name = "username")
	private String username;
	
	@Column(name = "password")
	private String password;
	
	@Enumerated(value = EnumType.STRING)
	private Role role;

	@OneToMany(mappedBy = "user")
	private List<Token> tokens;
	
	public List<Token> getTokens() {
		return tokens;
	}

	public void setTokens(List<Token> tokens) {
		this.tokens = tokens;
	}

	public Integer getId() {
		return id;
	}

	public void setId(Integer id) {
		this.id = id;
	}

	public String getFirstName() {
		return firstName;
	}

	public void setFirstName(String firstName) {
		this.firstName = firstName;
	}

	public String getLastName() {
		return lastName;
	}

	public void setLastName(String lastName) {
		this.lastName = lastName;
	}
	
	public String getUserName() {
		return username;
	}

	public void setUserName(String userName) {
		this.username = userName;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public Role getRole() {
		return role;
	}

	public void setRole(Role role) {
		this.role = role;
	}
	
	public boolean isEnable() { // xac dinh xem tai khoan cua nguoi dung co duoc kich hoat hay khong
		return true;
	}
	
	public boolean isCredentialsNonExpired() { // xac thuc xem thong tin xac thuc (vi du: mk) co het han hay khong, true -> tai khoan khong bi khoa, van co the dang nhap
		return true;
	}
	
	public boolean isAccountNonLocked() { // kiem tra xem tai khoan co bi khoa khong
		return true;
	}
	
	public boolean isAccountNonExpired() { // kiem tra xem tai khoan con hieu luc hay khong, con -> tiep tuc su dung duoc
		return true;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() { // phương thức này trả về một danh sách các quyền hạn (authorities) mà người dùng này có
		return List.of(new SimpleGrantedAuthority(role.name()));
	}

	@Override
	public String getUsername() {
		return this.username;
	}
}
