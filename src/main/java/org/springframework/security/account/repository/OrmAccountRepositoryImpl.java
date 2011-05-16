package org.springframework.security.account.repository;

import org.springframework.security.account.domain.Account;
import org.springframework.security.account.domain.AccountDetails;
import org.springframework.stereotype.Repository;
import org.springframework.util.Assert;

/**
 * @author Denis Borisenko
 *
 */
@Repository
public class OrmAccountRepositoryImpl implements AccountRepository {

	@Override
	public void persist(AccountDetails account) {
		Assert.notNull(account, "Argument [account] cannot be null");
		Assert.isTrue(account instanceof Account,
				"Argument [account] must have type [Account]");

		Account acc = (Account) account;
		acc.persist();
	}

	@Override
	public AccountDetails merge(AccountDetails account) {
		Assert.notNull(account, "Argument [account] cannot be null");
		Assert.isTrue(account instanceof Account,
				"Argument [account] must have type [Account]");

		Account acc = (Account) account;
		return acc.merge();
	}

}
