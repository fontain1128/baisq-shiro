package com.baisq.shiro;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.realm.AuthenticatingRealm;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.util.ByteSource;


//在spring中注入realm bean的时候需要指定creantialMatcher,因为如果数据库存储的是密文，那么在和前端的token进行比对时需要对前端的token进行加密，
//需要为其指定实例比如HashCreantialsMatcher,以及为实例注入属性值，加密算法以及算法迭代次数。
//Realm需要查询数据库，获取用户名密码，真实的数据,封装一个真实的AuthenticationInfo返回(同时要和前端输入的token进行比对)
//如果是盐值加密，在返回AuthenticationInfo信息时应该传入盐，用于对前端的token中的crential进行盐值加密再和数据库的进行比对
public class SecondRealm extends AuthenticatingRealm {

	/**
	 * 1doGetAuthenticationInfo,获取认证消息,如果数据库中没有数据，返回null,如果得到正确的用户名和密码，返回指定类型的对象
	 * 2AuthenticationInfo 可以使用SimpleAuthenticationInfo封装正确的用户名和密码
	 * 3token参数,就是我们需要认证的token
	 * 
	 */
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken arg0) throws AuthenticationException {
		System.out.println("second realm working!");
		SimpleAuthenticationInfo authInfo = null;
		//1将token 转换成UserNamePasswordToken
		UsernamePasswordToken upToken = (UsernamePasswordToken)arg0;
		//2获取用户名即可
		String userName = upToken.getUsername();
		//3查询数据库,是否存在指定用户名和密码的用户
		//4如果查询到，封装查询结果,返回给我们的调用者
		//5如果没有查询到,抛出一个异常
		try {
			//数据库连接
			Class.forName("com.mysql.jdbc.Driver");
			String url = "jdbc:mysql://127.0.0.1:3306/baisq_shiro?characterEncoding=utf-8&useSSL=true";
			Connection conn = DriverManager.getConnection(url, "root", "123456");
			//查询数据库
			PreparedStatement ps = conn.prepareStatement("select * from sys_user where user_name = ?");
			ps.setString(1, userName);
			ResultSet rs = ps.executeQuery();
			//获取当前的realm类名字
			String realmName = this.getName();
			//获取盐
			ByteSource salt = ByteSource.Util.bytes(userName);
			if(rs.next()){
				Object credential = rs.getString(3);
				//正常情况下不用使用下面的SimpleHash再次对数据库的crential加密，因为数据库存储的都是加密之后的数据
				SimpleHash sh = new SimpleHash("SHA1", credential, salt, 1024);
				//不传入盐值加密
				//authInfo = new SimpleAuthenticationInfo(userName, sh, realmName);
				//传入盐值加密
				authInfo = new SimpleAuthenticationInfo(userName, sh+"122", salt, realmName);
			}else {
				throw new AuthenticationException();
			}
		} catch (ClassNotFoundException | SQLException e) {
			e.printStackTrace();
		}
		
		return authInfo;
	}

	

}
