package com.tydic.tcv.jwt;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import com.google.common.base.Optional;
import com.tydic.tcv.entity.RoleEntity;
import com.tydic.tcv.entity.UserEntity;
import com.tydic.tcv.security.SecurityUser;
import com.tydic.tcv.security.UserAuthentication;
import com.tydic.tcv.tools.Common;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class TokenUtil {
	private static final Logger logger = LoggerFactory.getLogger(TokenUtil.class);
	private static final long VALIDITY_TIME_MS = 48 * 60 * 60 * 1000; // 48小时
	// hours
	//private static final long VALIDITY_TIME_MS_TEMP = 8 * 60 * 60 * 1000; // 8小时
	// hours
	// validity
	private static final String AUTH_HEADER_NAME = "Authorization";

	private String secret = "mrin";

	public Optional<Authentication> verifyToken(HttpServletRequest request) {
		final String token = request.getHeader(AUTH_HEADER_NAME);
		logger.info("请求的token============" + token);
		if (token != null && !token.isEmpty() && !"null".equals(token)) {
			final TokenUser user = parseUserFromToken(token.replace("Bearer", "").trim());
			if (user != null) {
				Authentication authentication = new UserAuthentication(user);
				return Optional.of(authentication);
			}
		}
		return Optional.absent();

	}

	// Get User Info from the Token
	public TokenUser parseUserFromToken(String token) {

		Claims claims = Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();

		UserEntity user = new UserEntity();
		user.setId((String) claims.get("userId"));
		user.setAccount(claims.getSubject());
		String roles = (String) claims.get("role");
		List<RoleEntity> setRole = null;
		if (!Common.isNullOrEmptyString(roles)) {
			setRole = new ArrayList<RoleEntity>();
			String[] roleArr = roles.split(",");
			for (String roleName : roleArr) {
				RoleEntity role = new RoleEntity();
				role.setRole_name(roleName);
				setRole.add(role);
			}
		}
		user.setRoles(setRole);
		SecurityUser securityUser = new SecurityUser(user);
		// 刷新token
		// String refreshToken = createTokenForUser(user);
		return new TokenUser(user, securityUser);
	}

	public String createTokenForUser(UserEntity user) {
		// token过期时间设定
		long expireTime = VALIDITY_TIME_MS;
		// 获取用户角色
		String roles = "";
		List<RoleEntity> setRoles = user.getRoles();
		if (setRoles != null)
			for (RoleEntity role : setRoles) {
				roles += role.getRole_name() + ",";
			}
		if (!Common.isNullOrEmptyString(roles))
			roles = roles.substring(0, roles.lastIndexOf(","));
		return Jwts.builder().setExpiration(new Date(System.currentTimeMillis() + expireTime))
				.setSubject(user.getAccount()).claim("userId", user.getId()).claim("role", roles)
				.signWith(SignatureAlgorithm.HS256, secret).compact();
	}
}
