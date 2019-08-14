package com.pinal.service;

import javax.transaction.Transactional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.pinal.entites.User;
import com.pinal.repository.UserRepository;
import com.pinal.security.UserPrincipal;
@Service
public class CustomUserDetailsService implements UserDetailsService {
	@Autowired
	private UserRepository userRepository;
	
	@Override
	@Transactional
	public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
		User user=userRepository.findByEmail(email);
		if(user == null)
			throw new UsernameNotFoundException("User is noe found with this email address "+email);
		return UserPrincipal.create(user);
	}

	public UserDetails loadUserById(Long id) {
		User user=userRepository.findById(id).get();
		if(user == null)
			throw new UsernameNotFoundException("User is noe found with this id "+id);
		return UserPrincipal.create(user);
	}
}
