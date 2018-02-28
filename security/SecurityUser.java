package com.tydic.tcv.security;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.tydic.tcv.entity.RoleEntity;
import com.tydic.tcv.entity.UserEntity;

/**
 * 
 * @ClassName: SecurityUser
 * @Description:登录用自定义验证实现类
 * @author zhuanghang
 * @date 2017-4-11 上午10:10:10
 * @version 1.0
 * @注意：方法里面需要注释说明的时候用"//"加注释,注释加在代码前一行 整个方法注销用斜杠星,少量代码注销用"//"
 */
public class SecurityUser extends UserEntity implements UserDetails {
	private static final Logger logger = LoggerFactory.getLogger(SecurityUser.class);
	private static final long serialVersionUID = 1L;
	private UserEntity suser;

	public SecurityUser(UserEntity suser) {
		if (suser != null) {
			this.setId(suser.getId());
			this.setAccount(suser.getAccount());
			this.setPassword(suser.getPassword());
			this.setRoles(suser.getRoles());
			this.suser = suser;
		}

	}

	@Override
	public Collection<GrantedAuthority> getAuthorities() {
		logger.info("权限角色获取开始。。。。。。。。。。。。。。。");
		Collection<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();

		List<RoleEntity> userRoles = this.getRoles();

		if (userRoles != null) {
			for (RoleEntity role : userRoles) {
				String roleName = role.getRole_name();
				SimpleGrantedAuthority authority = new SimpleGrantedAuthority("ROLE_" + roleName);
				authorities.add(authority);
			}
		}
		return authorities;

	}

	@Override
	public boolean isAccountNonExpired() {
		return true;

	}

	@Override
	public boolean isAccountNonLocked() {
		return true;

	}

	@Override
	public boolean isCredentialsNonExpired() {

		return true;

	}

	@Override
	public boolean isEnabled() {

		return true;

	}

	@Override
	public String getUsername() {
		return this.getAccount();
	}

	public UserEntity getSystemUser() {
		return suser;
	}
}
