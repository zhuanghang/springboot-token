package com.tydic.tcv.jwt;

import com.tydic.tcv.entity.UserEntity;
import com.tydic.tcv.security.SecurityUser;

public class TokenUser extends org.springframework.security.core.userdetails.User {
	private static final long serialVersionUID = 1L;
	private UserEntity user;

	public TokenUser(UserEntity user, SecurityUser sUser) {
		super(user.getAccount(), "", sUser.getAuthorities());
		this.user = user;
	}

	public UserEntity getUser() {
		return user;
	}

	public String getRole() {
		return null;
	}
}
