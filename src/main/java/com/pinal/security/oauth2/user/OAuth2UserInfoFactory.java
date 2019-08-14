package com.pinal.security.oauth2.user;

import java.util.Map;

import com.pinal.enums.AuthProvider;

public class OAuth2UserInfoFactory {
	
	public static OAuth2UserInfo getOauth2UserInfo(String registrationId,Map<String,Object> attributes) {
		if(registrationId.equalsIgnoreCase(AuthProvider.google.toString())) {
			return new GoogleOAuth2UserInfo(attributes);
		}else {
			System.out.println("not supported");
		}
		return null;
	}
}
