package com.pinal.security.oauth2.controller;

import java.net.URI;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import com.pinal.entites.User;
import com.pinal.enums.AuthProvider;
import com.pinal.repository.UserRepository;
import com.pinal.security.TokenProvider;
import com.pinal.security.oauth2.user.ApiResponse;
import com.pinal.security.oauth2.user.AuthResponse;
import com.pinal.security.oauth2.user.LoginRequest;
import com.pinal.security.oauth2.user.SignUpRequest;

@RestController
@RequestMapping("/auth")
public class CurrentUser {
	@Autowired
	private AuthenticationManager authenticationManager;
	@Autowired
	private UserRepository userRepository;
	@Autowired
	private PasswordEncoder encoder;
	@Autowired
	private TokenProvider provider;
	
	
	@PostMapping("/login")
	public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest request){
		Authentication authentication=authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));
		SecurityContextHolder.getContext().setAuthentication(authentication);
		String token=provider.generateToken(authentication);
		return ResponseEntity.ok(new AuthResponse(token));
	}
	@PostMapping("/signup")
	public ResponseEntity<?> registerUser(@RequestBody SignUpRequest request){
		if(userRepository.existsByEmail(request.getEmail())) {
			System.out.println("email already rgistered.");
		}
		User user=new User();
		user.setName(request.getName());
		user.setEmail(request.getEmail());
		user.setPassword(request.getPassword());
		user.setProvideId(AuthProvider.google.toString());
		user.setPassword(encoder.encode(user.getPassword()));
		User res=userRepository.save(user);
		
		URI location = ServletUriComponentsBuilder
                .fromCurrentContextPath().path("/user/me")
                .buildAndExpand(res.getId()).toUri();
		return ResponseEntity.created(location)
                .body(new ApiResponse(true, "User registered successfully@"));
	}
	
	@GetMapping("/error")
	public String error() {
		return "error";
	}
}
