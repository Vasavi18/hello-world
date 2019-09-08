/**
 * 
 */
package com.exide.sfcrm.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.exide.sfcrm.authentication.UserAuthSuccessHandler;
import com.exide.sfcrm.constants.PropertyConstants;

/**
 * @author saurabhp
 *
 */
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	
	@Autowired
	UserAuthSuccessHandler userAuthSuccessHandler;
	
	@Autowired
	private PropertyConstants propertyConstants;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		
//		http
//			.authorizeRequests()
//
//				//.antMatchers("/").permitAll()
//				.antMatchers("/css/**", "/index").permitAll()
//				//comment the below line
//				.antMatchers(propertyConstants.APP_CONTEXT+"/login").permitAll()
//				.antMatchers(propertyConstants.APP_CONTEXT).permitAll()
//				.antMatchers("/user/**").access("hasRole('ROLE_ADMINISTRATOR') or hasRole('ROLE_USER')")
//				//.antMatchers("/user/userDetail").access("hasRole('ROLE_ADMINISTRATOR') or hasRole('ROLE_USER')")
//				///.and()
//				//.cors()
//				//.and()
//				//.csrf()
//				//.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//				.and()
//			.formLogin()
//				.loginProcessingUrl("/loginSuccess")
//				.successHandler(userAuthSuccessHandler)
//				.loginPage(propertyConstants.APP_CONTEXT+"/login")
//				.usernameParameter("username")
//				.passwordParameter("password")
//				.failureUrl(propertyConstants.APP_CONTEXT+"/login?error=true")
//				.and()
//				.logout()
//				.logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
//				.logoutSuccessUrl("/").and().exceptionHandling()
//				.and().csrf().disable()
//				;

		http	
		         .csrf().disable()
				.authorizeRequests()
				.antMatchers("/assets/**/*", "/*.js").permitAll()
				.antMatchers("/login").permitAll()
				//.anyRequest().authenticated()
				.and()
				.formLogin()
				.loginPage("/login")
				//.successHandler(userAuthSuccessHandler)
				.loginProcessingUrl("/login")
				.defaultSuccessUrl("/")
				.permitAll()
				//.and()
				/*.csrf()
				.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())*/
                .and()
				.sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .and()
				.httpBasic();
	}
	
}
