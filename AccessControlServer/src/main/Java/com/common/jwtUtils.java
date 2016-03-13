package com.common;

import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.util.Calendar;
import java.util.List;

import org.apache.commons.lang3.StringUtils;

import com.google.common.collect.Lists;
import com.google.gson.JsonObject;

import net.oauth.jsontoken.JsonToken;
import net.oauth.jsontoken.JsonTokenParser;
import net.oauth.jsontoken.crypto.HmacSHA256Signer;
import net.oauth.jsontoken.crypto.HmacSHA256Verifier;
import net.oauth.jsontoken.crypto.SignatureAlgorithm;
import net.oauth.jsontoken.crypto.Verifier;
import net.oauth.jsontoken.discovery.VerifierProvider;
import net.oauth.jsontoken.discovery.VerifierProviders;

/**
 * 
 * @author Alfredo Guerrero
 *
 */
public class jwtUtils {
	
        private static final String AUDIENCE = "NotReallyImportant";

	    private static final String ISSUER = "contpaqi";

	    private static final String SIGNING_KEY = "com.knowitive.ontogov.controller!#$%&/()=?¡";

	    /**
	     * Creates a json web token which is a digitally signed token that contains a payload .
	     * @param userId
	     * @param durationDays
	     * @return
	     */
	    public static String createJsonWebToken(String userId, Long durationDays,String user, String password, String app, String ip)    {
	        //Current time and signing algorithm
	        Calendar cal = Calendar.getInstance();
	        HmacSHA256Signer signer;
	        
	        try {
	            
	        	signer = new HmacSHA256Signer(ISSUER, null, SIGNING_KEY.getBytes());
	            
	        } catch (InvalidKeyException e) {
	            
	        	throw new RuntimeException(e);
	        }

	        //Configure JSON token
	        JsonToken token = new net.oauth.jsontoken.JsonToken(signer);
	        token.setAudience(AUDIENCE);
	        token.setIssuedAt(new org.joda.time.Instant(cal.getTimeInMillis()));
	        token.setExpiration(new org.joda.time.Instant(cal.getTimeInMillis() + 1000L * 60L * 60L * 24L * durationDays));
	        token.setParam("userId"  , userId);
	        token.setParam("user"    , user);
	        token.setParam("password", password);
	        token.setParam("app"     , app);
	        token.setParam("ip"      , ip);
	        
	     

	        //Configure request object, which provides information of the item
	        JsonObject request = new JsonObject();
	        request.addProperty("userId", userId);

	        JsonObject payload = token.getPayloadAsJsonObject();
	        payload.add("info", request);

	        try {
	            return token.serializeAndSign();
	        } catch (SignatureException e) {
	            throw new RuntimeException(e);
	        }
	    }

	    /**
	     * Verifies a json web token's validity. 
	     * @param token
	     * @return
	     * @throws SignatureException
	     * @throws InvalidKeyException
	     */
	    public static boolean verifyToken(String token)  
	    {
	        try {
	            final Verifier hmacVerifier = new HmacSHA256Verifier(SIGNING_KEY.getBytes());

	            VerifierProvider hmacLocator = new VerifierProvider() {

	                public List<Verifier> findVerifier(String id, String key){
	                    return Lists.newArrayList(hmacVerifier);
	                }
	            };
	            
	            
	            VerifierProviders locators = new VerifierProviders();
	            locators.setVerifierProvider(SignatureAlgorithm.HS256, hmacLocator);
	            net.oauth.jsontoken.Checker checker = new net.oauth.jsontoken.Checker(){

	                public void check(JsonObject payload) throws SignatureException {
	                    // don't throw - allow anything
	                }

	            };
	            //Ignore Audience does not mean that the Signature is ignored
	            JsonTokenParser parser = new JsonTokenParser(locators, checker);
	            JsonToken jt;
	            
	            try {
	            	token = token.trim();
	                jt = parser.verifyAndDeserialize(token);
	                
	            } catch (SignatureException e) {
	            	
	            	return false;
	                //throw new RuntimeException(e);
	            }
	            
	            JsonObject payload      = jt.getPayloadAsJsonObject();
	            String     issuer       = payload.getAsJsonPrimitive("iss").getAsString();
	            String     userIdString = payload.getAsJsonObject("info").getAsJsonPrimitive("userId").getAsString();
	            
	            
	            if (issuer.equals(ISSUER) && !StringUtils.isBlank(userIdString))
	            {
	                return true;
	            }
	            else
	            {
	                return false;
	            }
	            
	        } catch (Exception e1) {
	        	
	        	return false;
	            //throw new RuntimeException(e1);
	            
	        }
	    }
	 
	    /**
	     * Get the info that contain the Token
	     * @param token
	     * @return
	     */
	    public static com.common.infoToken  get_info_Token(String token)
	    {
	        try {
	            final Verifier hmacVerifier = new HmacSHA256Verifier(SIGNING_KEY.getBytes());

	            VerifierProvider hmacLocator = new VerifierProvider() {

	                public List<Verifier> findVerifier(String id, String key){
	                    return Lists.newArrayList(hmacVerifier);
	                }
	            };
	            
	            
	            VerifierProviders locators = new VerifierProviders();
	            locators.setVerifierProvider(SignatureAlgorithm.HS256, hmacLocator);
	            net.oauth.jsontoken.Checker checker = new net.oauth.jsontoken.Checker(){

	                public void check(JsonObject payload) throws SignatureException {
	                    // don't throw - allow anything
	                }

	            };
	            //Ignore Audience does not mean that the Signature is ignored
	            JsonTokenParser parser = new JsonTokenParser(locators, checker);
	            JsonToken jt;
	            
	            try {
	            	token = token.trim();
	                jt = parser.verifyAndDeserialize(token);
	                
	            } catch (SignatureException e) {
	            	
	            	return null;
	             
	            }
	            
	            com.common.infoToken t = new com.common.infoToken();
	            
	            JsonObject payload      = jt.getPayloadAsJsonObject();
	            String     issuer       = payload.getAsJsonPrimitive("iss").getAsString();
	            
	            t.set_userId(payload.getAsJsonObject("info").getAsJsonPrimitive("userId").getAsString());
	            t.set_user(payload.getAsJsonPrimitive("user").getAsString());
	            t.set_password(payload.getAsJsonPrimitive("password").getAsString());
	            t.set_app(payload.getAsJsonPrimitive("app").getAsString());
	            t.set_ip(payload.getAsJsonPrimitive("ip").getAsString());
	            
	            
	            if (issuer.equals(ISSUER) && !StringUtils.isBlank(t.get_userId()))
	            {
	                return t;
	            }
	            else
	            {
	                return null;
	            }
	            
	        } catch (Exception e1) {
	        	
	        	return null;
	            
	        }
	    	
	    			
	    }
	    
}
