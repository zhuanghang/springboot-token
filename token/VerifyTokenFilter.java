package com.tydic.tcv.jwt;

import io.jsonwebtoken.JwtException;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

import com.google.common.base.Optional;

public class VerifyTokenFilter extends GenericFilterBean {

	private final TokenUtil tokenUtil;

	// private AuthenticationFailureHandler loginFailureHandler = new
	// SimpleUrlAuthenticationFailureHandler();

	public VerifyTokenFilter(TokenUtil tokenUtil) {
		this.tokenUtil = tokenUtil;
	}

	@Override
	public void doFilter(ServletRequest req, ServletResponse res, FilterChain filterChain) throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;
		try {
			Optional<Authentication> authentication = tokenUtil.verifyToken(request);
			if (authentication.isPresent()) {
				SecurityContextHolder.getContext().setAuthentication(authentication.get());
			} else {
				SecurityContextHolder.getContext().setAuthentication(null);
			}
			filterChain.doFilter(req, res);
		} catch (JwtException e) {
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			throw new JwtException("token验证异常或失效！");
		}
	}

}
