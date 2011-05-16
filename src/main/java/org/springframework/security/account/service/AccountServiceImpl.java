package org.springframework.security.account.service;

import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.springframework.security.account.domain.AccountDetails;
import org.springframework.security.account.repository.AccountRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.GrantedAuthorityImpl;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Assert;

/**
 * @author Denis Borisenko
 *
 */
@Service
public class AccountServiceImpl implements AccountService {
	
	private UserDetailsManager userDetailsManager;

	public UserDetailsManager getUserDetailsManager() {
		return userDetailsManager;
	}
	public void setUserDetailsManager(UserDetailsManager userDetailsManager) {
		this.userDetailsManager = userDetailsManager;
	}
	
	private AccountRepository accountRepository;

	public AccountRepository getAccountRepository() {
		return accountRepository;
	}
	public void setAccountRepository(AccountRepository accountRepository) {
		this.accountRepository = accountRepository;
	}
	
	private List<String> creationAuthorities = Collections.emptyList();
	
	public List<String> getCreationAuthorities() {
		return creationAuthorities;
	}
	public void setCreationAuthorities(List<String> creationAuthorities) {
		this.creationAuthorities = creationAuthorities;
	}

	private boolean creationUserEnable = false;
	
	public boolean isCreationUserEnable() {
		return creationUserEnable;
	}
	public void setCreationUserEnable(boolean creationUserEnable) {
		this.creationUserEnable = creationUserEnable;
	}
	
	@Transactional
	@Override
	public void createAccount(AccountDetails account, String password, Collection<String> authorities) {
		Assert.notNull(account, "Argument [account] cannot be null");
		Assert.hasText(password, "Argument [password] must have value");
		Assert.hasText(account.getUsername(), "Argument [account.getUsername()] must return value");
		
		getAccountRepository().persist(account);
		
		List<GrantedAuthority> grantedAuthorities = createGrantedAuthorities(authorities);
		
		User user = new User(account.getUsername(), password, 
				creationUserEnable, true, true, true, grantedAuthorities);
		userDetailsManager.createUser(user);
	}
	
	protected List<GrantedAuthority> createGrantedAuthorities(Collection<String> authorities) {
		
		List<GrantedAuthority> grantedAuthorities = AuthorityUtils.NO_AUTHORITIES;
		if (creationAuthorities != null) {
			for (String role : creationAuthorities) {
				grantedAuthorities.add(new GrantedAuthorityImpl(role));
			}
		}
		if (authorities != null) {
			for (String role : authorities) {
				grantedAuthorities.add(new GrantedAuthorityImpl(role));
			}
		}
		return grantedAuthorities;
	}
}
