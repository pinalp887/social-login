package com.pinal.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import com.pinal.entites.User;
import com.pinal.enums.AuthProvider;
import com.pinal.repository.UserRepository;
import com.pinal.security.UserPrincipal;
import com.pinal.security.oauth2.user.OAuth2UserInfo;
import com.pinal.security.oauth2.user.OAuth2UserInfoFactory;
@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {
	@Autowired
	private UserRepository userRepository;
	
	@Override
	public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
		OAuth2User auth2User=super.loadUser(userRequest);
		try {
			return processOauth2User(userRequest, auth2User);
		} catch (AuthenticationException  e) {
			 throw e;
		}catch(Exception ex) {
			throw ex;	
		}
	}
	
	private OAuth2User processOauth2User(OAuth2UserRequest oAuth2UserRequest,OAuth2User oAuth2user) {
		OAuth2UserInfo auth2UserInfoo=OAuth2UserInfoFactory.getOauth2UserInfo(oAuth2UserRequest.getClientRegistration().getRegistrationId(),oAuth2user.getAttributes());
		if(StringUtils.isEmpty(auth2UserInfoo.getEmail())) {
			System.out.println("email is empty ");
		}
		User user=userRepository.findByEmail(auth2UserInfoo.getEmail());
		if(user !=null) {
			if(!user.getAuthProvider().equals(AuthProvider.valueOf(oAuth2UserRequest.getClientRegistration().getRegistrationId()))) {
				System.out.println("not access");
			}
			user=updateExistingUser(user, auth2UserInfoo);
		}else {
			user=registerNewUser(oAuth2UserRequest, auth2UserInfoo);
		}
		return UserPrincipal.create(user, oAuth2user.getAttributes());
	}
	
	private User registerNewUser(OAuth2UserRequest auth2UserRequest, OAuth2UserInfo oAuth2user) {
		User user=new User();
		user.setAuthProvider(AuthProvider.valueOf(auth2UserRequest.getClientRegistration().getRegistrationId()));
		user.setProvideId(oAuth2user.getId());
		user.setName(oAuth2user.getName());
		user.setEmail(oAuth2user.getEmail());
		user.setImageUrl(oAuth2user.getImageUrl());
		return userRepository.save(user);
	}
	
	private User updateExistingUser(User user,OAuth2UserInfo auth2UserInfo) {
		user.setName(auth2UserInfo.getName());
		user.setImageUrl(auth2UserInfo.getImageUrl());
		return userRepository.save(user);
	}
	
}
