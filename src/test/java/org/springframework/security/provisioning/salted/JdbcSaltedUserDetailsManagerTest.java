package org.springframework.security.provisioning.salted;

import static org.junit.Assert.*;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.transaction.annotation.Transactional;

@Transactional
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = {"classpath:/META-INF/spring/applicationContext.xml", 
		"classpath:/META-INF/spring/context-security-authentication.xml"})
public class JdbcSaltedUserDetailsManagerTest {
	
	protected Logger logger = Logger.getLogger(getClass());
	
	@Autowired
	protected JdbcSaltedUserDetailsManager userDetailsManager;
	
	@Autowired
	@Qualifier("authenticationManager")
	protected AuthenticationManager authenticationManager;
	
	protected String username = "user1";
	protected String password = "password";
	protected String authorityUser = "ROLE_USER";
	protected String authorityAdmin = "ROLE_ADMIN";
	
	@Before
	public void setUp() throws Exception {
		logger.setLevel(Level.INFO);
		userDetailsManager.setEnableAuthorities(true);
		userDetailsManager.setEnableGroups(false);
	}
	
	protected void assertUserDetails(boolean updated) {
		UserDetails userDetails = userDetailsManager.loadUserByUsername(username);
		assertNotNull(userDetails);
		assertNotNull(userDetails.getUsername());
		assertEquals(username, userDetails.getUsername());
		if (updated) {
			assertEquals(2, userDetails.getAuthorities().size());
			String auth1 = ((GrantedAuthority)userDetails.getAuthorities().toArray()[0]).getAuthority();
			String auth2 = ((GrantedAuthority)userDetails.getAuthorities().toArray()[1]).getAuthority();
			if ((!auth1.equals(authorityUser) && !auth1.equals(authorityAdmin)) ||
					(!auth2.equals(authorityUser) && !auth2.equals(authorityAdmin))) {
				fail("Wrong authorities");
			}
		} else {
			assertEquals(1, userDetails.getAuthorities().size());
			assertEquals(authorityUser, ((GrantedAuthority)userDetails.getAuthorities().toArray()[0]).getAuthority());
		}
		
		logger.info(userDetails);
		logger.info("Stored password [" + userDetails.getPassword() + "], " +
				"salt [" + ((SaltedUser)userDetails).getSalt() + "]");
	}
	
	protected UserDetails createUser() {
		User user = new User(username, password, true, true, true, true, 
				AuthorityUtils.createAuthorityList(authorityUser));
		userDetailsManager.createUser(user);
		return user;
	}
	
	protected UserDetails updateUser() {
		User user = new User(username, password + password, true, true, 
				true, true, AuthorityUtils.createAuthorityList(authorityUser, authorityAdmin));
		userDetailsManager.updateUser(user);
		return user;
	}

	@Test
	public void testCreateUserUserDetails() {
		createUser();
		assertUserDetails(false);
		
		authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
		try {
			authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, "wrong_password"));
			fail("Login with wrong password happens");
		} catch (BadCredentialsException e) {
			// Expected
		}
	}

	@Test
	public void testUpdateUserUserDetails() {
		updateUser();
		assertUserDetails(true);
		
		authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password + password));
		try {
			authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
			fail("Login with wrong password happens");
		} catch (BadCredentialsException e) {
			// Expected
		}
	}

	@Test
	public void testChangePasswordStringString() {
		
		Authentication auth = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(username, password + password));
		SecurityContext securityContext = SecurityContextHolder.getContext();
	    securityContext.setAuthentication(auth);
		try {
			userDetailsManager.changePassword(password, password);
			fail("Wrong old password is used");
		} catch (BadCredentialsException e) {
			// Expected
		}
		
		userDetailsManager.changePassword(password + password, password);
		
		assertUserDetails(true);
		
		authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
	}
	
	public void testUserExistsString() {
		assertEquals(true, userDetailsManager.userExists(username));
	}
	
	@Test
	public void testDeleteUserString() {
		userDetailsManager.deleteUser(username);
		try {
			userDetailsManager.loadUserByUsername(username);
			fail("User was not removed");
		} catch (UsernameNotFoundException e) {
			// Expected
		}
		try {
			authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
			fail("Authenticated after removing user");
		} catch (BadCredentialsException e) {
			// Expected
		}
	}

}
