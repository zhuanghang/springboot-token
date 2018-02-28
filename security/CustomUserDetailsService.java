package com.tydic.tcv.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import com.tydic.tcv.entity.UserEntity;
import com.tydic.tcv.service.UserService;

/**
 * 
 * @ClassName: CustomUserDetailsService
 * @Description: 登录数据库查询
 * @author zhuanghang
 * @date 2017-4-24 下午02:31:49
 * @version 1.0
 * @注意：方法里面需要注释说明的时候用"//"加注释,注释加在代码前一行 整个方法注销用斜杠星,少量代码注销用"//"
 */
public class CustomUserDetailsService implements UserDetailsService {
	private static final Logger logger = LoggerFactory.getLogger(CustomUserDetailsService.class);
	@Autowired
	// 数据库用户操作服务类
	private UserService userService;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		// SystemUser对应数据库中的用户表，是最终存储用户和密码的表，可自定义
		UserEntity user = null;
		user = userService.findUserByAttr(username);
		SecurityUser securityUser = null;
		if (user != null) {
			securityUser = new SecurityUser(user);
			logger.info("登录的用户名：" + user.getAccount());
		}
		return securityUser;

	}
}
