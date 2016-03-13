package com.knowitive.ontogov.controller;



import org.json.JSONObject;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.google.gson.Gson;

/**
 * 
 * @author  Alfredo Guerrero
 * @version 1.0.0
 *
 */
@RestController
@RequestMapping("/accessControl")
public class accessControl {
	
	
	/**
	 * 
	 * @author Alfredo Guerrero
	 * 
	 * 
	 * @param name
	 * @param password
	 * @param app
	 * @param ip
	 * @param userid
	 * @return if the Authentification is valid return the Token
	 */
    @RequestMapping(value = "/generate/{user}/{password}/{app}/{ip}/{userid}", method = RequestMethod.GET)
    public JSONObject generate(@PathVariable String user, 
    							   @PathVariable String password,
    							   @PathVariable String app,
    							   @PathVariable String ip,
    							   @PathVariable String userid) {
    	
    	
    	try{

    
        //We can improve this part encrypting the user and password and store it in a data base
        if(user.equals("contpaqi")  && password.equals("1234")){
            
            String jwt = com.common.jwtUtils.createJsonWebToken(user,(long) 1, user, password, app, ip);
            
            JSONObject jo_jwt = new JSONObject();
            jo_jwt.put("JWT", jwt);
        
            return  jo_jwt;
        
        }else{
            
            //INVALID TOKEN IF THE USER AND PASSWORD IS INVALID
            return null;
        }
        
        
    	}catch(Exception ex)
    	{
    		System.out.println(ex.getMessage());
    		return null;
    	}
        
        
        
    }
    
    /**
     * 
     * @author Alfredo Guerrero
     * 
     * @param token
     * @return
     */
    @RequestMapping(value = "/validate", method = RequestMethod.POST)
    public boolean validate(String token) {
    
        System.out.println(token);
        
        if(com.common.jwtUtils.verifyToken(token))
        {
            //VALID
            return true;
            
        }else
        {
            //INVALID
            return false;
        }

           
    }
    
    /**
     * 
     * @author Alfredo Guerrero
     * 
     * @param token
     * @return
     */
    @RequestMapping(value = "/getInfo", method = RequestMethod.POST)
    public String getInfo(String token) {
    
        com.common.infoToken oInfoToken = com.common.jwtUtils.get_info_Token(token);
        
        Gson gson = new Gson();
        
        if(oInfoToken != null){
        
        	gson.toJson(oInfoToken);
        	return gson.toJson(oInfoToken);
        
        
        }else
        {
        	return "";
        }

           
    }
    
    
    
	

}
