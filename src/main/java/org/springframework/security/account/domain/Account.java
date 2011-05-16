package org.springframework.security.account.domain;

import org.springframework.roo.addon.entity.RooEntity;
import org.springframework.roo.addon.javabean.RooJavaBean;
import org.springframework.roo.addon.tostring.RooToString;
import javax.validation.constraints.NotNull;
import javax.persistence.Column;
import javax.validation.constraints.Size;
import javax.validation.constraints.Pattern;

/**
 * @author Denis Borisenko
 *
 */
@RooJavaBean
@RooToString
@RooEntity(finders = { "findAccountsByEmail", "findAccountsByUsername" })
public class Account implements AccountDetails {

    @NotNull
    @Column(unique = true)
    @Size(max = 64)
    @Pattern(regexp = "^[A-Z0-9_]+$", flags = { Pattern.Flag.CASE_INSENSITIVE })
    private String username;

    @NotNull
    @Column(unique = true)
    @Size(max = 64)
    @Pattern(regexp = "^[A-Z0-9._%-]+@[A-Z0-9.-]+\\.[A-Z]{2,4}$", flags = { Pattern.Flag.CASE_INSENSITIVE })
    private String email;

    @Size(max = 25)
    private String firstName;

    @Size(max = 25)
    private String lastName;

}
