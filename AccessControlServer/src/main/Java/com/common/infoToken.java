package com.common;


/**
 * 
 * @author Alfredo Guerrero
 *
 */
public class infoToken {
	
	private String userId;
	private String user;
	private String password;
	private String app;
	private String ip;
	
	
	public void set_userId(String userId)
	{
		this.userId = userId;
	}
	
	public void set_user(String user)
	{
		this.user = user;
	}
	
	public void set_password(String password)
	{
		this.password = password;
	}
	
	public void set_app(String app)
	{
		this.app = app;
	}
	
	public void set_ip(String ip)
	{
		this.ip = ip;
	}
	
	
	
	public String get_userId()
	{
		return userId;
	}

	public String get_user()
	{
		return user;
	}
	
	public String get_password()
	{
		return password;
	}
	
	public String app()
	{
		return app;
	}
	
	public String get_ip()
	{
		return ip;
	}
		

}
