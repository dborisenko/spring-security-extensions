package org.springframework.security.provisioning.salted;

/**
 * @author Denis Borisenko
 *
 */
public interface SaltGenerator {
	
	String nextSalt();
}
