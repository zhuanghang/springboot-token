package com.tydic.tcv.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.encoding.Md5PasswordEncoder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.tydic.tcv.config.RestfulAccessDeniedHandlerImpl;
import com.tydic.tcv.config.RestfulAuthenticationEntryPoint;
import com.tydic.tcv.jwt.TokenUtil;
import com.tydic.tcv.jwt.VerifyTokenFilter;

/**
 * 
 * @ClassName: WebSecurityConfig
 * @Description: springsecurity相关的配置
 * @author zhuanghang
 * @date 2017-4-15 下午08:27:11
 * @version 1.0
 * @注意：方法里面需要注释说明的时候用"//"加注释,注释加在代码前一行 整个方法注销用斜杠星,少量代码注销用"//"
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
// 开启security注解
// 允许进入页面方法前检验
@Order(1)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
	@Autowired
	private TokenUtil tokenUtil;
	// @Autowired
	// private AuthenticationFailureHandler sessionAuthenticationFailureHandler;

	@Bean
	public AuthenticationProvider authenticationProvider() {
		AuthenticationProvider authenticationProvider = new AuthenticationProviderCustom(customUserDetailsService(),
				passwordEncoder());
		return authenticationProvider;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// 允许所有用户访问"/"
		http.authorizeRequests().antMatchers("/api/users/export").permitAll()
				// 其他地址的访问均需验证权限
				.anyRequest().authenticated();
		/*
		 * http.sessionManagement().// sessionAuthenticationFailureHandler(
		 * sessionAuthenticationFailureHandler);
		 *//**
			 * 同一个账号只能在一个地方登陆
			 */
		/*
		 * maximumSessions(1).
		 *//**
			 * 自定义session过期策略，替代默认的{@link ConcurrentSessionFilter.ResponseBodySessionInformationExpiredStrategy}，
			 * 复写onExpiredSessionDetected方法，默认方法只输出异常，没业务逻辑。这里需要返回json
			 *//*
			 * expiredSessionStrategy(new SessionInforExpiredStrategy());
			 */
		http.exceptionHandling().authenticationEntryPoint(new RestfulAuthenticationEntryPoint())
				.accessDeniedHandler(new RestfulAccessDeniedHandlerImpl());
		http.csrf().disable();
		http.addFilterBefore(new VerifyTokenFilter(tokenUtil), UsernamePasswordAuthenticationFilter.class);
		http.addFilterBefore(new GenerateTokenForUserFilter("/api/login", authenticationManager(), tokenUtil),
				UsernamePasswordAuthenticationFilter.class);
	}

	public void configure(WebSecurity web) throws Exception {
		// 设置不拦截规则
		web.ignoring().antMatchers("/v2/**", "/webjars/**", "/swagger-ui.html", "/swagger-resources/**", "/static/**",
				"/public/**", "/resources/**", "/configuration/**", "/dist/**", "/favicon.ico", "/files/**");
	}

	/**
	 * 设置用户密码的加密方式为MD5加密
	 * 
	 * @return
	 */
	@Bean
	public Md5PasswordEncoder passwordEncoder() {
		return new Md5PasswordEncoder();

	}

	/**
	 * 自定义UserDetailsService，从数据库中读取用户信息
	 * 
	 * @return
	 */
	@Bean
	public CustomUserDetailsService customUserDetailsService() {
		return new CustomUserDetailsService();
	}
}
