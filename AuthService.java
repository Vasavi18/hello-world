package com.difz.bsve.user.service;

import com.difz.bsve.oauth.util.BsveOAuthServiceException;
import com.difz.harbinger.common.dto.APIAccessCredentials;
import com.difz.harbinger.common.dto.AuthCredentials;
import com.difz.harbinger.common.dto.AuthResult;
import com.difz.harbinger.common.dto.AuthSession;
import com.difz.harbinger.common.dto.AuthorizationRequest;
import com.difz.harbinger.common.dto.AuthorizationResponse;
import com.difz.harbinger.common.dto.BsveRequestParametersDTO;
import com.difz.harbinger.common.dto.ServiceRequest;
import com.difz.harbinger.common.dto.ServiceResponse;
import com.difz.harbinger.common.dto.UserAuthenticationBO;

public interface AuthService {

	public static final Integer LOGIN_RETRIES_COUNT = 5;

	public abstract AuthResult getUserForAccessKey(String accessKey,
			BsveRequestParametersDTO bsveRequestParametersDTO);

	public abstract AuthResult getUserForTicket(String ticket);

	public abstract ServiceResponse<AuthResult> authenticate(
			ServiceRequest<AuthCredentials> request) throws Exception;

	/**
	 * Logout a user from Harbinger session. On successful validation of the
	 * received user credentials This method will perform the following logout
	 * operations.
	 * <ul>
	 * <li>Clear the auth ticket</li>
	 * <li>Clear the ticket expiry time</li>
	 * </ul>
	 * 
	 * @param request
	 *            The {@link ServiceRequest} object with the current access
	 *            token as data in the form of {@link AuthSession}.
	 * @param message
	 *            - message describing the initiation of logout
	 * @return A {@link ServiceResponse} object with a boolean value indicating
	 *         whether the logout is successful or not.
	 */
	public abstract ServiceResponse<String> logout(
			ServiceRequest<AuthSession> request, String message);

	public abstract ServiceResponse<String> updatePasswordWithCurrentPasswordCheck(
			ServiceRequest<AuthCredentials> request, String originHost,
			String authTicket);

	public abstract ServiceResponse<String> updatePassword(
			ServiceRequest<AuthCredentials> request);

	public abstract ServiceResponse<String> updateSecurityQuestionnaire(
			ServiceRequest<AuthCredentials> request, String originHost,
			String authTicket);

	public abstract ServiceResponse<String> updatePasswordAndSecurityQuestionnaire(
			ServiceRequest<AuthCredentials> request);

	// check security question and answer for user name
	public abstract ServiceResponse<Boolean> checkSecurityQuestionnaire(
			ServiceRequest<AuthCredentials> request, String originHost);

	public abstract ServiceResponse<String> activate(
			ServiceRequest<AuthCredentials> request, String originHost,
			String authTicket);

	public abstract ServiceResponse<String> deactivate(
			ServiceRequest<AuthCredentials> request, String originHost,
			String authTicket);

	public abstract ServiceResponse<String> unlock(
			ServiceRequest<AuthCredentials> request);

	/**
	 * This method generates a new access token, stores it in db and returns in
	 * response
	 * 
	 * @param request
	 * @return response
	 */
	public abstract AuthorizationResponse generateAccessToken(
			AuthorizationRequest request);

	/**
	 * This method would generate the access credentials required to access any
	 * API of Harbinger system.<BR>
	 * It first validate the logged in user against login credentials and after
	 * successful authentication, will generate access key and secret key.
	 * 
	 * @param request
	 *            ServiceRequest<{@link AuthCredentials}>
	 * @return {@link APIAccessCredentials} embedded in {@link ServiceResponse}.
	 * @throws BsveOAuthServiceException
	 * @throws Exception
	 */
	public abstract ServiceResponse<APIAccessCredentials> generateAPIAccessCredentials(
			ServiceRequest<AuthCredentials> request)
			throws BsveOAuthServiceException, Exception;

	void invalidateAuthTicket(String ticket);

	/**
	 * This method returns the user details in the form of {@link AuthResult}
	 * for the given access credentials.
	 * 
	 * @param apiCredentials
	 *            API access credentials
	 * @return response with {@link AuthResult}
	 */
	public abstract ServiceResponse<AuthResult> getUserDetails(
			APIAccessCredentials apiCredentials);

	public abstract ServiceResponse<APIAccessCredentials> generateAPISecurityDetails(
			String userName);

	public abstract ServiceResponse<APIAccessCredentials> getAPISecurityDetails(
			String userName);

	/**
	 * Validate a user a user credentials. This service is typically used by Ui
	 * tha would like to reopen a closed browser session after closing the
	 * browser without logging out. On a successful valiation, this method will
	 * extend the access token validity.
	 * 
	 * @param request
	 *            The {@link ServiceRequest} object with the current access
	 *            token as data in the form of {@link AuthSession}.
	 * @return A {@link ServiceResponse} object with a boolean value indicating
	 *         whether the user session is valid or not.
	 */
	public abstract ServiceResponse<Boolean> validate(
			ServiceRequest<AuthSession> request);

	/**
	 * This Method is used to get the UserAuthentication Details
	 * 
	 * @param userName
	 * @return
	 */

	public abstract ServiceResponse<UserAuthenticationBO> getAuthUserDetails(
			String userName);

	/**
	 * This method is used to save the UserAuthentication Details of new user
	 * 
	 * @param userAuthenticationBO
	 * @return
	 */
	public abstract ServiceResponse<String> saveUserAuthEntry(
			UserAuthenticationBO userAuthenticationBO);

	/**
	 * This method is used to update the UserAuthentication Details
	 * 
	 * @param userAuthenticationBO
	 * @return
	 */
	public abstract ServiceResponse<String> updateAuthDetails(
			UserAuthenticationBO userAuthenticationBO);

}