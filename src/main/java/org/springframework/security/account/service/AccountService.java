package org.springframework.security.account.service;

import java.util.Collection;

import org.springframework.security.account.domain.AccountDetails;

/**
 * @author Denis Borisenko
 *
 */
public interface AccountService {
	
	void createAccount(AccountDetails account, String password, Collection<String> authorities);
}
