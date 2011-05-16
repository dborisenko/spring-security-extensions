package org.springframework.security.account.repository;

import org.springframework.security.account.domain.AccountDetails;

/**
 * @author Denis Borisenko
 *
 */
public interface AccountRepository {
	
	void persist(AccountDetails account);
	AccountDetails merge(AccountDetails account);
}
