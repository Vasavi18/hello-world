/**
 * 
 */
package com.exide.sfcrm.authentication;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;

import javax.json.JsonException;
import javax.security.auth.login.LoginException;

import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Configurable;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.exide.sfcrm.constants.ApplicationConstants;
import com.exide.sfcrm.constants.MessageConstants;
import com.exide.sfcrm.model.UserGroup;
import com.exide.sfcrm.service.UserManagementService;
import com.exide.sfcrm.util.CommonUtil;
import com.fasterxml.jackson.core.JsonProcessingException;

/**
 * @author saurabhp
 *
 */
@Service
@Configurable
public class CustomAuthenticationProvider implements UserDetailsService, AuthenticationProvider    {
      
	
	private static final Logger LOGGER = LoggerFactory
			.getLogger(CustomAuthenticationProvider.class);


	@Autowired
	private UserManagementService userService;
	
	@Autowired
	private ActiveDirectoryUser activeDirectory;
	
	@Autowired
	private CommonUtil commonUtil;
	
	/**
	 * Load user by username.
	 */
	@Override
	public UserDetails loadUserByUsername(String username)
			throws UsernameNotFoundException {

		com.exide.sfcrm.authentication.UserDetails userDetails = null;
		try {
			com.exide.sfcrm.model.User user = userService.getUserByName(username);
			
			Set<UserGroup> userGroups = userService.getAllUserGroupBasedOnId(user.getId());

			if (user.getIsActiveUser()) {

				List<SimpleGrantedAuthority> authList = new ArrayList<>();
				//String role = "";
				for(UserGroup userGroup : userGroups){
					
					/*if("" == role){
						role = userGroup.getName();
					}else{
						role = role + ",ROLE_" +  userGroup.getName();
					}*/
					
					authList.add(new SimpleGrantedAuthority("ROLE_"
							+ userGroup.getName().toUpperCase()));
					
				}
				
				
				userDetails = new com.exide.sfcrm.authentication.UserDetails(
						user.getUserName(), user.getPassword(), authList);
				userDetails.setUser(user);
			}

			

		} catch (Exception e) {
			LOGGER.error("Error occured while loading user by username", e);
			///userDetails.setErrorMsg("Invalid UserName");
		}

		if (null == userDetails) {
			throw new UsernameNotFoundException("User not found");
		}
		return userDetails;
	}

	 @Override
	    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
	        String username = authentication.getName();
	        String password = (String) authentication.getCredentials();
	        boolean  isLdapUser = false; 
	        UserDetails userDetails = loadUserByUsername(username);
	        com.exide.sfcrm.authentication.UserDetails loggedInUserDetails = (com.exide.sfcrm.authentication.UserDetails)userDetails;
			//System.out.println("UserDetails : "+ loggedInUserDetails + (null != loggedInUserDetails.getUser() ? "Yes" : "No"));
			
			JSONObject ldapUser = null;
	  /*      try {
	        	ldapUser = activeDirectory.userDetails(username,password);	
				if(null != loggedInUserDetails.getUser() && loggedInUserDetails.getUser().isAdUser() && null != ldapUser ){
		        	isLdapUser = true;
		        }
				if((!isLdapUser && loggedInUserDetails.getUser().isAdUser() ) 
		        		|| (!isLdapUser && !loggedInUserDetails.getUser().isAdUser() && !password.equals(userDetails.getPassword()))
		        		|| (isLdapUser && !"".equals(userDetails.getPassword()) && null == ldapUser)){
		        	
		        	throw new BadCredentialsException("Wrong password.");
		        }	
			} catch (LoginException | JSONException e) {
				LOGGER.error("Exception occured while connecting LDAP : "+e);
			}*/
	        Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();
	        return new UsernamePasswordAuthenticationToken(userDetails, userDetails.getPassword(), authorities);
	    }

      @Override
	    public boolean supports(Class<?> authentication) {
	    	return (UsernamePasswordAuthenticationToken.class
	                .isAssignableFrom(authentication));
	    }
}
