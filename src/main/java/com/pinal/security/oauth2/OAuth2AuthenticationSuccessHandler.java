package com.pinal.security.oauth2;

import static com.pinal.security.oauth2.HttpCookieOAuth2AuthorizationRequestRepository.REDIRECT_URI_PARAM_COOKIE_NAME;

import java.io.IOException;
import java.net.URI;
import java.util.Optional;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import com.pinal.app.config.AppProperties;
import com.pinal.security.TokenProvider;
import com.pinal.security.oauth2.util.CookieUtils;
@Component
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

	private TokenProvider provider;

	private AppProperties appProperties;

	private HttpCookieOAuth2AuthorizationRequestRepository cookieOAuth2AuthorizationRequestRepository;

	@Autowired
	OAuth2AuthenticationSuccessHandler(TokenProvider provider, AppProperties appProperties,HttpCookieOAuth2AuthorizationRequestRepository cookieOAuth2AuthorizationRequestRepository) {
		this.provider=provider;
		this.appProperties=appProperties;
		this.cookieOAuth2AuthorizationRequestRepository=cookieOAuth2AuthorizationRequestRepository;
	}
	
	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {
		String targetUrl=determineTargetUrl(request, response,authentication);
		if(response.isCommitted()) {
			logger.debug("response has already been commited, unable to redirect to "+targetUrl);
			return;
		}
		clearAuthenticationAttributes(request, response);
		getRedirectStrategy().sendRedirect(request, response, targetUrl);
		super.onAuthenticationSuccess(request, response, authentication);
	}
	
	protected String determineTargetUrl(HttpServletRequest httpServletRequest,HttpServletResponse httpServletResponse,Authentication authentication) {
		Optional<String> redirectUri=CookieUtils.getCookie(httpServletRequest, REDIRECT_URI_PARAM_COOKIE_NAME).map(Cookie::getValue);
		if(redirectUri.isPresent() && !isAuthorizedRedirectUri(redirectUri.get()) ) {
			System.out.println("Sorry! We've got an Unauthorized Redirect URI and can't proceed with the authentication");
		}
		String targetUrl=redirectUri.orElse(getDefaultTargetUrl());
		String token=provider.generateToken(authentication);
		return UriComponentsBuilder.fromUriString(targetUrl).queryParam("token", token).build().toUriString();
	}
	
	protected void clearAuthenticationAttributes(HttpServletRequest request,HttpServletResponse response) {
		super.clearAuthenticationAttributes(request);
		cookieOAuth2AuthorizationRequestRepository.removeAuthorizationRequestCookies(request, response);
	}
	private boolean isAuthorizedRedirectUri(String uri) {
		URI clientRedirectUri=URI.create(uri);
		return appProperties.getAuth2().getAuthorizedRedirectUris().stream().anyMatch(authorizedRedirectUri->{
			URI authoRizedURI=URI.create(authorizedRedirectUri);
			if(authoRizedURI.getHost().equalsIgnoreCase(clientRedirectUri.getHost()) && authoRizedURI.getPort() == clientRedirectUri.getPort()){
				return true;
			}	
			return false;
		});
	}
}
