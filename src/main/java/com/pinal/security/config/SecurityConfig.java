package com.pinal.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.pinal.security.oauth2.HttpCookieOAuth2AuthorizationRequestRepository;
import com.pinal.security.oauth2.OAuth2AuthenticationFailureHandler;
import com.pinal.security.oauth2.OAuth2AuthenticationSuccessHandler;
import com.pinal.security.oauth2.RestAuthenticationEntryPoint;
import com.pinal.security.oauth2.filter.TokenAuthenticationFilter;
import com.pinal.service.CustomOAuth2UserService;
import com.pinal.service.CustomUserDetailsService;
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity	(securedEnabled = true,jsr250Enabled = true,prePostEnabled = true)
@EnableOAuth2Sso
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	@Autowired
	private CustomUserDetailsService customUserDetailsService;
	@Autowired
	private CustomOAuth2UserService oAuth2UserService;
	@Autowired
	private OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;
	@Autowired
	private OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler;
	@Autowired
	private HttpCookieOAuth2AuthorizationRequestRepository httpCookieOAuth2AuthorizationRequestRepository;
	
	@Bean
	public TokenAuthenticationFilter tokenAuthenticationFilter() {
		return new TokenAuthenticationFilter();
	}
	
	@Bean
	public HttpCookieOAuth2AuthorizationRequestRepository cookieOAuth2AuthorizationRequestRepository() {
		return new HttpCookieOAuth2AuthorizationRequestRepository();
	}
	
	@Override
	public void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(customUserDetailsService).passwordEncoder(encoder());
	}
	
	@Bean
	public PasswordEncoder encoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean(BeanIds.AUTHENTICATION_MANAGER)
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.cors().and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and().csrf().disable().formLogin().disable()
		.httpBasic().disable().exceptionHandling().authenticationEntryPoint(new RestAuthenticationEntryPoint()).and().authorizeRequests()
		.antMatchers("/","/error","/**/*.png","/**/*.jpg","/**/*.svg").permitAll().antMatchers("/auth/**","/oauth/**").permitAll().anyRequest().authenticated()
		.and()
		.oauth2Login().authorizationEndpoint()
		.baseUri("/oauth2/authorize")
		.authorizationRequestRepository(cookieOAuth2AuthorizationRequestRepository())
		.and().redirectionEndpoint().baseUri("/oauth2/callback/*").and()
		.userInfoEndpoint().userService(oAuth2UserService).and()
		.successHandler(oAuth2AuthenticationSuccessHandler)
		.failureHandler(oAuth2AuthenticationFailureHandler);
		http.addFilterBefore(tokenAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
	}
	
	
}
