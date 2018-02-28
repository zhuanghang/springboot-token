package com.tydic.tcv.security;

import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.encoding.Md5PasswordEncoder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import com.tydic.tcv.aop.SystemControllerLog;
import com.tydic.tcv.tools.Common;

/**
 * 
 * @ClassName: AuthenticationProviderCustom
 * @Description: 覆写登录认证逻辑
 * @author zhuanghang
 * @date 2017-4-13 下午04:09:40
 * @version 1.0
 * @注意：方法里面需要注释说明的时候用"//"加注释,注释加在代码前一行 整个方法注销用斜杠星,少量代码注销用"//"
 */
public class AuthenticationProviderCustom implements AuthenticationProvider {
	private final UserDetailsService userDetailsService;
	private final Md5PasswordEncoder passwordEncoder;

	public AuthenticationProviderCustom(UserDetailsService userDetailsService, Md5PasswordEncoder passwordEncoder) {
		this.userDetailsService = userDetailsService;
		this.passwordEncoder = passwordEncoder;
	}

	@SystemControllerLog(description = "登录")
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		UsernamePasswordAuthenticationToken token = (UsernamePasswordAuthenticationToken) authentication;
		String username = token.getName();
		// 从数据库找到的用户
		UserDetails userDetails = null;
		if (!Common.isNullOrEmptyString(username)) {
			userDetails = userDetailsService.loadUserByUsername(username);
		}
		if (userDetails == null) {
			throw new UsernameNotFoundException("用户名/密码无效");
		} else if (!userDetails.isEnabled()) {
			throw new DisabledException("用户已被禁用");
		} else if (!userDetails.isAccountNonExpired()) {
			throw new AccountExpiredException("账号已过期");
		} else if (!userDetails.isAccountNonLocked()) {
			throw new LockedException("账号已被锁定");
		} else if (!userDetails.isCredentialsNonExpired()) {
			throw new LockedException("凭证已过期");
		}
		String password = userDetails.getPassword();
		// 与authentication里面的credentials相比较
		if (!passwordEncoder.isPasswordValid(password, token.getCredentials().toString(), null)) {
			throw new BadCredentialsException("密码校验错误!");
		}
		// 授权
		return new UsernamePasswordAuthenticationToken(userDetails, password, userDetails.getAuthorities());
	}

	@Override
	public boolean supports(Class<?> authentication) {
		// 返回true后才会执行上面的authenticate方法,这步能确保authentication能正确转换类型
		return UsernamePasswordAuthenticationToken.class.equals(authentication);
	}
}
