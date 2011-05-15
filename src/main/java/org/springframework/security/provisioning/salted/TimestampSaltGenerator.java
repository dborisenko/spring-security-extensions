package org.springframework.security.provisioning.salted;

import java.util.Date;

/**
 * @author Denis Borisenko
 *
 */
public class TimestampSaltGenerator implements SaltGenerator {

	@Override
	public String nextSalt() {
		return "" + new Date().getTime();
	}

}
