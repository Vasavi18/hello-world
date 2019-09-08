package com.difz.bsve.auth.data.dao;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.query.Param;

import com.difz.bsve.auth.data.model.UserAuthentication;


/**
 * DAO implementation to enable access to UserAuthentication table.
 */
public interface UserAuthenticationDAO extends JpaRepository<UserAuthentication, String> {

	UserAuthentication findByUserName(@Param("userName") String userName);
}
