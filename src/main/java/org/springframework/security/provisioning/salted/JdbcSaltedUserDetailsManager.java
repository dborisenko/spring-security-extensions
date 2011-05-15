package org.springframework.security.provisioning.salted;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;

import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.dao.SaltSource;
import org.springframework.security.authentication.encoding.PasswordEncoder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.util.Assert;

/**
 * @author Denis Borisenko
 *
 */
public class JdbcSaltedUserDetailsManager extends JdbcUserDetailsManager {
	
	public static final String DEF_CREATE_USER_SQL =
        "insert into users (username, password, enabled, salt) values (?,?,?,?)";
	public static final String DEF_USERS_BY_USERNAME_QUERY =
        "select username,password,enabled,salt " +
        "from users " +
        "where username = ?";
	public static final String DEF_INSERT_AUTHORITY_SQL =
        "insert into authorities (username, authority) values (?,?)";
	
	private String createUserSql = DEF_CREATE_USER_SQL;
	private String createAuthoritySql = DEF_INSERT_AUTHORITY_SQL;
	
	private PasswordEncoder passwordEncoder;
	private SaltSource saltSource;
	private SaltGenerator saltGenerator;
	private int minPasswordSize = 8;
	
	public int getMinPasswordSize() {
		return minPasswordSize;
	}
	public void setMinPasswordSize(int minPasswordSize) {
		this.minPasswordSize = minPasswordSize;
	}
	
	public SaltGenerator getSaltGenerator() {
		return saltGenerator;
	}
	public void setSaltGenerator(SaltGenerator saltGenerator) {
		this.saltGenerator = saltGenerator;
	}
	
	public PasswordEncoder getPasswordEncoder() {
		return passwordEncoder;
	}
	public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
		this.passwordEncoder = passwordEncoder;
	}

	public SaltSource getSaltSource() {
		return saltSource;
	}
	public void setSaltSource(SaltSource saltSource) {
		this.saltSource = saltSource;
	}
	
	public JdbcSaltedUserDetailsManager() {
		super();
		init();
	}
	
	protected void init() {
		setUsersByUsernameQuery(DEF_USERS_BY_USERNAME_QUERY);
		setCreateUserSql(DEF_CREATE_USER_SQL);
		setCreateAuthoritySql(DEF_INSERT_AUTHORITY_SQL);
		createUserSql = DEF_CREATE_USER_SQL;
		createAuthoritySql = DEF_INSERT_AUTHORITY_SQL;
	}
	
	@Override
	public void createUser(UserDetails user) {
		Assert.notNull(user, "[user] - this argument is required; it must not be null");
		Assert.hasText(user.getUsername(), "Username may not be empty or null");
		Assert.hasText(user.getPassword(), "Password may not be empty or null");
		Assert.isTrue(user.getPassword().length() >= getMinPasswordSize(), 
				"Minimum password size is " + getMinPasswordSize() + " symbols");
		
		String salt = saltGenerator.nextSalt();
		final SaltedUser saltedUser = new SaltedUser(user, salt);
		final String encodedPassword = getPasswordEncoder().encodePassword(user.getPassword(), 
				getSaltSource().getSalt(saltedUser));
		
        getJdbcTemplate().update(createUserSql, new PreparedStatementSetter() {
            public void setValues(PreparedStatement ps) throws SQLException {
                ps.setString(1, saltedUser.getUsername());
                ps.setString(2, encodedPassword);
                ps.setBoolean(3, saltedUser.isEnabled());
                ps.setString(4, saltedUser.getSalt());
            }
        });
        
        if (getEnableAuthorities()) {
            insertUserAuthorities(user);
        }
	}
	
	@Override
	public void updateUser(UserDetails user) {
		Assert.notNull(user, "[user] - this argument is required; it must not be null");
		Assert.hasText(user.getUsername(), "Username may not be empty or null");
		
		UserDetails userDetails = loadUserByUsername(user.getUsername());
		String encodedPassword = getPasswordEncoder().encodePassword(user.getPassword(), 
				getSaltSource().getSalt(userDetails));
		
		User userToUpdate = new User(user.getUsername(), encodedPassword, user.isEnabled(), 
				user.isAccountNonExpired(), user.isCredentialsNonExpired(), user.isAccountNonLocked(), 
				user.getAuthorities());
		super.updateUser(userToUpdate);
	}
	
	@Override
	public void changePassword(String oldPassword, String newPassword)
			throws AuthenticationException {
		
		Assert.hasText(oldPassword, "String argument [oldPassword] must have text; it must not be null, empty, or blank");
		Assert.hasText(newPassword, "String argument [newPassword] must have text; it must not be null, empty, or blank");
		
		Authentication currentUser = SecurityContextHolder.getContext().getAuthentication();

        if (currentUser == null) {
            // This would indicate bad coding somewhere
            throw new AccessDeniedException("Can't change password as no Authentication object found in context " +
                    "for current user.");
        }

        String username = currentUser.getName();
        
		SaltedUser user = (SaltedUser) loadUserByUsername(username);
		
		String encodedNewPassword = getPasswordEncoder().encodePassword(newPassword, getSaltSource().getSalt(user));
		super.changePassword(oldPassword, encodedNewPassword);
	}
	
	@Override
	protected UserDetails createUserDetails(String username,
			UserDetails userFromUserQuery,
			List<GrantedAuthority> combinedAuthorities) {
		
		Assert.hasText(username, "String argument [username] must have text; it must not be null, empty, or blank");
		Assert.notNull(userFromUserQuery, "[userFromUserQuery] - this argument is required; it must not be null");
		
		String returnUsername = userFromUserQuery.getUsername();

        if (!isUsernameBasedPrimaryKey()) {
            returnUsername = username;
        }

        return new SaltedUser(returnUsername, userFromUserQuery.getPassword(), userFromUserQuery.isEnabled(),
                true, true, true, combinedAuthorities, ((SaltedUser)userFromUserQuery).getSalt());
	}
	
	@Override
	protected List<UserDetails> loadUsersByUsername(String username) {
		
		Assert.hasText(username, "String argument [username] must have text; it must not be null, empty, or blank");
		
		return getJdbcTemplate().query(getUsersByUsernameQuery(), new String[] {username}, new RowMapper<UserDetails>() {
            public UserDetails mapRow(ResultSet rs, int rowNum) throws SQLException {
                String username = rs.getString(1);
                String password = rs.getString(2);
                boolean enabled = rs.getBoolean(3);
                String salt = rs.getString(4);
                return new SaltedUser(username, password, enabled, true, true, true, AuthorityUtils.NO_AUTHORITIES, salt);
            }

        });
	}
	
	private void insertUserAuthorities(UserDetails user) {
        for (GrantedAuthority auth : user.getAuthorities()) {
            getJdbcTemplate().update(createAuthoritySql, user.getUsername(), auth.getAuthority());
        }
    }
}
