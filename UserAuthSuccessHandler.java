/**
 * 
 */
package com.exide.sfcrm.authentication;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import com.exide.sfcrm.constants.PropertyConstants;

/**
 * @author saurabhp
 *
 */
@Component
public class UserAuthSuccessHandler implements AuthenticationSuccessHandler {

	@Autowired
	private PropertyConstants propertyConstants;
	
	/**
	 * 
	 */
	@Override
	public void onAuthenticationSuccess(HttpServletRequest request,
			HttpServletResponse response, Authentication authentication) throws IOException,
			ServletException {
		
//        Set<String> roles = AuthorityUtils.authorityListToSet(authentication.getAuthorities());
        
            response.sendRedirect(propertyConstants.APP_CONTEXT+"/dashboard");   
    }

}
