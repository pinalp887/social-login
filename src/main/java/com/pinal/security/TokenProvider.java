package com.pinal.security;

import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import com.pinal.app.config.AppProperties;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;

@Service
public class TokenProvider {

	private static final Logger LOGGER = LoggerFactory.getLogger(TokenProvider.class);

	private AppProperties appProperties;

	public TokenProvider(AppProperties appProperties) {
		this.appProperties = appProperties;
	}

	public String generateToken(Authentication authentication) {
		UserPrincipal principal = (UserPrincipal) authentication.getPrincipal();

		Date date = new Date();
		Date expiryDate = new Date(date.getTime() + appProperties.getAuth().getTokenExpirationMsec());
		return Jwts.builder().setSubject(Long.toString(principal.getId())).setIssuedAt(new Date())
				.setExpiration(expiryDate).signWith(SignatureAlgorithm.HS512, appProperties.getAuth().getTokenSecret())
				.compact();
	}
	
	public Long getUserIdFromToken(String token) {
		Claims claims=Jwts.parser().setSigningKey(appProperties.getAuth().getTokenSecret()).parseClaimsJws(token).getBody();
		return Long.parseLong(claims.getSubject());
	}
	
	public boolean validateToken(String token) {
		try {
			Jwts.parser().setSigningKey(appProperties.getAuth().getTokenSecret()).parseClaimsJws(token);
			return true;
		} catch (SignatureException e) {
			LOGGER.error("INVALID JWT SIGNATURE.");
		}catch(MalformedJwtException e) {
			LOGGER.error("INVALIDA JWT TOKEN.");
		}catch (ExpiredJwtException e) {
			LOGGER.error("EXPIRED JWT TOKEN.");
		}catch (UnsupportedJwtException e) {
			LOGGER.error("UNSUPPORTED JWT EXCEPTION.");
		}catch (IllegalArgumentException e) {
			LOGGER.error("JWT TOKEN IS EMPTY");
		}
		return false;
	}
}
