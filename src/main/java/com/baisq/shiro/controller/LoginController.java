package com.baisq.shiro.controller;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class LoginController {

	@RequestMapping(value = "/logon", method = RequestMethod.GET)
	public String login(@RequestParam String userName, @RequestParam String passWord) {
		// 获取当前登录用户实例
		Subject currentUser = SecurityUtils.getSubject();
		// 判断当前用户是否已经登陆
		if (!currentUser.isAuthenticated()) {
			// 将登陆名和密码封装成UsernamePasswordToken对象
			UsernamePasswordToken token = new UsernamePasswordToken(userName, passWord);
			try {
				currentUser.login(token);// 登陆的时候需要一个重要的接口realm,所有与数据交互的动作放到realm中;
			} catch (AuthenticationException e) {
				return "error";
			}

		}
		return "success";
	}

}
