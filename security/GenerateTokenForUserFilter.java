package com.tydic.tcv.security;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.IOUtils;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StringUtils;

import com.tydic.tcv.config.SpringContextUtil;
import com.tydic.tcv.dao.IPDao;
import com.tydic.tcv.entity.IPEntity;
import com.tydic.tcv.entity.UserEntity;
import com.tydic.tcv.entity.custom.LoginUserEntity;
import com.tydic.tcv.jwt.TokenUtil;
import com.tydic.tcv.tools.Common;
import com.tydic.tcv.tools.ResponseResult;

/**
 * 
 * @ClassName: GenerateTokenForUserFilter
 * @Description: 登录进行用户名和密码获取进行相应的验证
 * @author zhuanghang
 * @date 2017-4-24 下午02:32:24
 * @version 1.0
 * @注意：方法里面需要注释说明的时候用"//"加注释,注释加在代码前一行 整个方法注销用斜杠星,少量代码注销用"//"
 */
public class GenerateTokenForUserFilter extends AbstractAuthenticationProcessingFilter {
	private static final Logger logger = LoggerFactory.getLogger(GenerateTokenForUserFilter.class);
	private TokenUtil tokenUtil;
	private IPDao ipDao = SpringContextUtil.getBean(IPDao.class);

	protected GenerateTokenForUserFilter(String urlMapping, AuthenticationManager authenticationManager,
			TokenUtil tokenUtil) {
		super(new AntPathRequestMatcher(urlMapping));
		setAuthenticationManager(authenticationManager);
		this.tokenUtil = tokenUtil;
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException, JSONException {
		try {
			String jsonString = IOUtils.toString(request.getInputStream(), "UTF-8");
			JSONObject userJSON = new JSONObject(jsonString);
			String username = userJSON.getString("username");
			String password = userJSON.getString("password");
			final UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username,
					password);
			return getAuthenticationManager().authenticate(authToken);
		} catch (Exception e) {
			throw new AuthenticationServiceException(e.getMessage());
		}
	}

	@Override
	protected void successfulAuthentication(HttpServletRequest req, HttpServletResponse res, FilterChain chain,
			Authentication authToken) throws IOException, ServletException {
		IPEntity ipEntity = null;
		SecurityContextHolder.getContext().setAuthentication(authToken);
		SecurityUser securityUsr = (SecurityUser) authToken.getPrincipal();
		UserEntity user = securityUsr.getSystemUser();
		try {
			String ip = Common.getIpAddr(req);
			String mac = Common.getMACAddress(ip);
			if (!StringUtils.isEmpty(mac)) {
				mac = mac.toUpperCase();
			}
			logger.info("IP地址:" + ip + "  mac地址:" + mac);
			Map<String, String> map = new HashMap<String, String>();
			map.put("ip", ip);
			map.put("mac", mac);
			map.put("account_id", user.getId());
			ipEntity = ipDao.getIPMac(map);
		} catch (Exception e) {
			logger.error("获取macIP异常", e);
		}
		ResponseResult<LoginUserEntity> result = new ResponseResult<LoginUserEntity>();
		// if (ipEntity == null) {
		// result.setError("IP或者Mac地址受限!");
		// } else {
		String newToken = this.tokenUtil.createTokenForUser(user);
		LoginUserEntity loginUserEntity = new LoginUserEntity();
		loginUserEntity.setToken(newToken);
		user.setPassword(null);
		loginUserEntity.setUser(user);
		result.setSuccess(loginUserEntity);
		logger.info("====认证成功返回信息=====" + Common.objectToJson(result));
		// }

		// res.setStatus(HttpServletResponse.SC_OK);
		res.setContentType("application/json");
		res.getWriter().write(Common.objectToJson(result));
		res.getWriter().flush();
		res.getWriter().close();
	}

	protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse res,
			AuthenticationException failed) throws IOException, ServletException {
		ResponseResult<String> result = new ResponseResult<String>();
		result.setError(failed.getMessage());
		logger.info("====认证失败返回信息=====" + Common.objectToJson(result));
		res.setStatus(HttpServletResponse.SC_OK);
		res.setContentType("application/json");
		res.getWriter().write(Common.objectToJson(result));
		res.getWriter().flush();
		res.getWriter().close();
	}
}
