package org.springframework.security.provisioning.salted;


import org.apache.log4j.Level;
import org.junit.Before;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.GroupManager;

public class JdbcSaltedUserDetailsManagerEnableGroupsTest extends JdbcSaltedUserDetailsManagerTest {

	@Autowired
	protected GroupManager groupManager;
	
	protected String groupUsers = "UsersGroup";
	protected String groupAdmins = "AdminsGroup";
	
	@Override
	@Before
	public void setUp() throws Exception {
		logger.setLevel(Level.INFO);
		userDetailsManager.setEnableAuthorities(false);
		userDetailsManager.setEnableGroups(true);
	}
	
	@Override
	protected UserDetails createUser() {
		UserDetails user = super.createUser();
		
		groupManager.createGroup(groupUsers, AuthorityUtils.createAuthorityList(authorityUser));
		groupManager.addUserToGroup(user.getUsername(), groupUsers);
		return user;
	}
	
	@Override
	protected UserDetails updateUser() {
		UserDetails user = super.updateUser();
		
		groupManager.createGroup(groupAdmins, AuthorityUtils.createAuthorityList(authorityUser, authorityAdmin));
		groupManager.addUserToGroup(user.getUsername(), groupAdmins);
		return user;
	}

}
