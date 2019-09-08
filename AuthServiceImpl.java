package com.difz.bsve.user.service.impl;

import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.UUID;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import com.difz.bsve.auth.data.dao.AuthenticationDAO;
import com.difz.bsve.auth.data.dao.AuthorizationDAO;
import com.difz.bsve.auth.data.dao.ClientUserDAO;
import com.difz.bsve.auth.data.dao.TenancyMasterDAO;
import com.difz.bsve.auth.data.dao.UserAuthenticationDAO;
import com.difz.bsve.auth.data.dao.UserDao;
import com.difz.bsve.auth.data.model.Authentication;
import com.difz.bsve.auth.data.model.Authorization;
import com.difz.bsve.auth.data.model.ClientUser;
import com.difz.bsve.auth.data.model.User;
import com.difz.bsve.auth.data.model.UserAuthentication;
import com.difz.bsve.auth.data.model.UserDetail;
import com.difz.bsve.auth.data.model.UserDetailView;
import com.difz.bsve.oauth.dto.BSPAccessTokenDetailsBO;
import com.difz.bsve.oauth.jdbc.ClientDetailsDao;
import com.difz.bsve.oauth.util.BSPOAuthUtils;
import com.difz.bsve.oauth.util.BsveAuthConstants;
import com.difz.bsve.oauth.util.BsveOAuthServiceException;
import com.difz.bsve.user.dto.ActivityLogDTO;
import com.difz.bsve.user.service.ActivityLogService;
import com.difz.bsve.user.service.AuthService;
import com.difz.bsve.user.service.BSVEAuthenticate;
import com.difz.bsve.user.service.TenancyMasterService;
import com.difz.bsve.user.util.AccountStatus;
import com.difz.bsve.user.util.UserUtils;
import com.difz.harbinger.common.config.ContainerConfig;
import com.difz.harbinger.common.crypto.DigestUtils;
import com.difz.harbinger.common.dto.APIAccessCredentials;
import com.difz.harbinger.common.dto.AuthCredentials;
import com.difz.harbinger.common.dto.AuthResult;
import com.difz.harbinger.common.dto.AuthSession;
import com.difz.harbinger.common.dto.AuthorizationRequest;
import com.difz.harbinger.common.dto.AuthorizationResponse;
import com.difz.harbinger.common.dto.BsveRequestParametersDTO;
import com.difz.harbinger.common.dto.ClientAgentDTO;
import com.difz.harbinger.common.dto.ServiceRequest;
import com.difz.harbinger.common.dto.ServiceResponse;
import com.difz.harbinger.common.dto.UserAuthenticationBO;
import com.difz.harbinger.common.dto.UserBO;
import com.difz.harbinger.common.exception.HarbingerDomainException;
import com.difz.harbinger.common.util.DateTool;
import com.difz.harbinger.common.util.MessageBundle;
import com.difz.harbinger.common.util.MessageConstants;

/**
 * Service implementation to handle all authentication functionalities.
 */
public class AuthServiceImpl implements AuthService {

	private static final Logger LOGGER = LoggerFactory
			.getLogger(AuthServiceImpl.class);

	private static final MessageBundle MESSAGEBUNDLE = MessageBundle
			.getInstance();

	private static final String BSVE_OAUTH_SERVICE_END_POINT = ContainerConfig
			.getBsveOAuthServiceEndPoint();

	/**
	 * The time validity of the Auth ticket
	 */
	private static final Long AUTH_TICKET_VALIDITY_TIME = 1000l * 60 * 60;

	/**
	 * The increment in time while extending the Auth ticket.
	 */
	private static final Long AUTH_TICKET_RENEW_WINDOW = 1000l * 60 * 20;

	private static final String[] REQUIRED_KEYS = { "apikey", "timestamp",
			"nonce", "signature" };

	/**
	 * Prefix used for access key;
	 */
	private static final String ACCESS_KEY_PREFIX = "AK";
	/**
	 * Prefix used for secret key;
	 */
	private static final String SCRET_KEY_PREFIX = "SK";
	private static final String THIRD_PARTY_USER = "Third Party User";

	@Autowired
	private AuthenticationDAO authenticationDAO;

	@Autowired
	private UserDao userDao;

	@Autowired
	private ClientUserDAO clientUserDAO;

	@Autowired
	private ActivityLogService activityLogService;

	@Autowired
	private TenancyMasterDAO tenancyMasterDao;

	@Autowired
	private ClientDetailsDao clientDetailsDao;

	@Autowired
	private TenancyMasterService tenancyMasterService;

	@Autowired
	private AuthorizationDAO authorizationDao;

	@Autowired
	private UserAuthenticationDAO userAuthenticationDAO;

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.difz.harbinger.user.service.AuthService#getUserForAccessKey(java.
	 * lang.String)
	 */
	@Override
	public AuthResult getUserForAccessKey(String accessKey,
			BsveRequestParametersDTO bsveRequestParametersDTO) {

		AuthResult authResult = null;

		// Split the keys
		Map<String, String> keys = readAuthenticationHeader(accessKey);
		if (!validateAccessKey(keys)) {
			LOGGER.trace("The access key {} does not contain required keys",
					accessKey);
			return null;
		}

		Authentication authentication = authenticationDAO.findByAccessKey(keys
				.get("apikey"));
		String action = null;
		ActivityLogDTO activityLogDTO = null;
		if (authentication != null) {
			ClientAgentDTO clientAgentDTO = new ClientAgentDTO();
			clientAgentDTO.setHost(bsveRequestParametersDTO.getHost());
			clientAgentDTO.setIpAddress(bsveRequestParametersDTO
					.getRemoteAddress());
			clientAgentDTO
					.setUserAgent(bsveRequestParametersDTO.getUserAgent());
			if (isAccessKeyValid(authentication, keys)) {
				authResult = new AuthResult();
				fillUserDetails(authResult, authentication.getUserName());
				action = MESSAGEBUNDLE
						.getMessage(MessageConstants.MSG_USER_AUDIT_API_KEYS_VALIDATION_SUCCESS);
				activityLogDTO = UserUtils.buildUserActivityLogDTO(action,
						authResult.getUserName(), authResult.getUserName(),
						clientAgentDTO, authResult.getTenancy(),
						authResult.getRole());
				LOGGER.debug("API keys are valid for user: {}",
						authentication.getUserName());
			} else {
				action = MESSAGEBUNDLE
						.getMessage(MessageConstants.MSG_USER_AUDIT_API_KEYS_VALIDATION_FAILURE);
				activityLogDTO = UserUtils.buildUserActivityLogDTO(action,
						authentication.getUserName(),
						authentication.getUserName(), clientAgentDTO, null,
						null);
				LOGGER.debug("API keys are Invalid for user: {}",
						authentication.getUserName());
			}
			activityLogDTO.setMessage(bsveRequestParametersDTO.getUrl());
			LOGGER.trace(
					"Persisting API keys usage Activity details for user: {}",
					authentication.getUserName());
			activityLogService.addActivity(activityLogDTO);
		} else {
			LOGGER.trace("API Keys are invalid");
			authResult = null;
		}

		return authResult;
	}

	private boolean isAccessKeyValid(Authentication authentication,
			Map<String, String> keys) {
		String clientSignature = keys.get("signature").toLowerCase();
		String serverSignature = signature(keys.get("apikey"),
				authentication.getSecretKey(), authentication.getUserName()
						.toLowerCase(), keys.get("timestamp"),
				keys.get("nonce"));
		LOGGER.trace("Client Signature = {}, Server signature = {}",
				clientSignature, serverSignature);
		return clientSignature.equals(serverSignature);
	}

	private boolean validateAccessKey(Map<String, String> keys) {
		for (String key : REQUIRED_KEYS) {
			if (!keys.containsKey(key)) {
				LOGGER.trace("Missing required key {}", key);
				return false;
			}
		}
		return true;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.difz.harbinger.user.service.AuthService#getUserForTicket(java.lang
	 * .String)
	 */
	@Override
	public AuthResult getUserForTicket(String ticket) {

		AuthResult authResult;

		Authentication authentication = authenticationDAO.findByTicket(ticket);
		if (authentication != null
				&& validateAndExtendAuthTicket(authentication,
						AUTH_TICKET_VALIDITY_TIME)) {
			authResult = buildAuthResult(authentication.getUserName(), ticket);
		} else {
			authResult = null;
		}

		return authResult;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.difz.harbinger.user.service.AuthService#authenticate(com.difz.harbinger
	 * .common.dto.ServiceRequest)
	 */
	@Override
	public ServiceResponse<AuthResult> authenticate(
			ServiceRequest<AuthCredentials> request) throws Exception {
		LOGGER.trace("Inside AuthServiceImpl for validating user authentication");
		ServiceResponse<AuthResult> response = new ServiceResponse<AuthResult>();

		AuthCredentials credentials = request.getData();
		if (UserUtils.validateCredentials(response, credentials, false, false)) {

			String userName = credentials.getUserName();
			String password = credentials.getPassword();
			String tenantName = credentials.getTenant();
			String tenantId = "";
			String oauthString = null;
			Authentication authentication = authenticationDAO.findOne(userName);
			Authorization authorization = authorizationDao
					.findByUserName(userName);
			try {
				// check if user belongs to that tenant
				if (StringUtils.isNotBlank(tenantName)) {
					if (!tenancyMasterService.checkUserTenant(userName,
							tenantName)) {
						LOGGER.info("No Tenant Found for the user " + userName);
						response.setStatus(ServiceResponse.FAILED_2);
						response.addMessage(MESSAGEBUNDLE
								.getMessage(MessageConstants.MSG_USER_TENANT_NOT_FOUND));
						return response;
					} else {
						tenantId = tenancyMasterService
								.getTenantIdByName(tenantName);
					}
				}
				// Get the default tenant if tenant not provided
				else {
					tenantId = tenancyMasterService.getDefaultTenant(userName);
					if (StringUtils.isBlank(tenantId)) {
						tenantId = userDao.getTenantIdByUserName(userName);
					}
				}
				oauthString = BSVEAuthenticate.authenticate(
						userName.toLowerCase(), password, tenantId,
						BSVE_OAUTH_SERVICE_END_POINT);
			} catch (Exception e) {
				LOGGER.error("Error while validating user authentication ",
						userName, e);
				String action = MESSAGEBUNDLE
						.getMessage(MessageConstants.MSG_USER_LOGIN_FAILED);
				ActivityLogDTO activityLogDTO = UserUtils
						.buildUserActivityLogDTO(
								action,
								userName,
								userName,
								request.getData().getClientAgentDTO(),
								tenantId,
								(authorization != null ? authorization
										.getRole() : ""));
				activityLogDTO
						.setMessage(MESSAGEBUNDLE
								.getMessage(MessageConstants.MSG_USERNAME_PASSWORD_INCORRECT));
				activityLogService.addActivity(activityLogDTO);

				if (null != authentication
						&& AccountStatus.ACTIVE.getId().equals(
								authentication.getStatus())) {
					updateFailedLoginAttempts(response, authentication);
				} else {
					response.setStatus(ServiceResponse.FAILED_2);
					response.addMessage(MESSAGEBUNDLE
							.getMessage(MessageConstants.MSG_USERNAME_PASSWORD_INCORRECT));
				}

				return response;
			}

			if (oauthString == null || authentication == null) {

				response.setStatus(ServiceResponse.FAILED_2);
				response.addMessage(MESSAGEBUNDLE
						.getMessage(MessageConstants.MSG_USERNAME_PASSWORD_INCORRECT));

				String action = MESSAGEBUNDLE
						.getMessage(MessageConstants.MSG_USER_LOGIN_FAILED);
				ActivityLogDTO activityLogDTO = UserUtils
						.buildUserActivityLogDTO(action, authentication
								.getUserName(), authentication.getUserName(),
								request.getData().getClientAgentDTO(),
								tenantId, authorization.getRole());
				activityLogService.addActivity(activityLogDTO);

				return response;

			} else {
				String authStatus = authentication.getStatus().toUpperCase();

				if ("A".equals(authStatus) || "R".equals(authStatus)
						|| "N".equals(authStatus)) {

					if ("N".equals(authStatus)) {
						// Check users account expiry date.
						int result = DateTool.compareDates(new Date(),
								authentication.getAccountExpiry());

						if (result == 1) {
							response.setStatus(ServiceResponse.FAILED_2);
							response.addMessage(MESSAGEBUNDLE
									.getMessage(MessageConstants.MSG_AUTHENTICATION_ACCOUNT_EXPIRED));
							return response;
						}
					}

					// Allocate new ticket and create a user
					AuthResult authResult = buildAuthResult(userName,
							oauthString);

					String action = MESSAGEBUNDLE
							.getMessage(MessageConstants.MSG_USER_LOGIN);
					ActivityLogDTO activityLogDTO = UserUtils
							.buildUserActivityLogDTO(action, authentication
									.getUserName(), authentication
									.getUserName(), request.getData()
									.getClientAgentDTO(), tenantId,
									authorization.getRole());
					if ("N".equals(authStatus) || "R".equals(authStatus)) {
						response.setStatus(ServiceResponse.SUCCESS_2);
						response.addMessage(MESSAGEBUNDLE
								.getMessage(MessageConstants.MSG_AUTHENTICATION_SUCCESSFUL_FIRSTLOGIN));
						activityLogDTO
								.setAction(MESSAGEBUNDLE
										.getMessage(MessageConstants.MSG_FIRST_TIME_USER_LOGIN));
						activityLogService.addActivity(activityLogDTO);
					} else {
						response.setStatus(ServiceResponse.SUCCESS);
						response.addMessage(MESSAGEBUNDLE
								.getMessage(MessageConstants.MSG_AUTHENTICATION_SUCCESSFUL));
						if (credentials.getClientUserBO() != null
								&& credentials.getClientUserBO().getSource() != null) {
							activityLogDTO.setAction(THIRD_PARTY_USER + " "
									+ activityLogDTO.getAction());
						}
						activityLogService.addActivity(activityLogDTO);
					}
					// updating login details.
					authentication.setFailedLoginAttempts(0);
					authentication.setTicketExpiry(new Date(System
							.currentTimeMillis() + AUTH_TICKET_VALIDITY_TIME));
					authentication.setLastLoginDateTime(new Date());
					authenticationDAO.saveAndFlush(authentication);

					response.setData(authResult);

				} else if (AccountStatus.LOCKED.getId().equals(authStatus)) {
					response.setStatus(ServiceResponse.FAILED_5);
					response.addMessage(MESSAGEBUNDLE
							.getMessage(MessageConstants.MSG_ACCOUNT_LOCKED));
				} else {
					response.setStatus(ServiceResponse.FAILED_4);
					response.addMessage(MESSAGEBUNDLE
							.getMessage(MessageConstants.MSG_ACCOUNT_INACTIVE));
				}

			}

			if (credentials.getClientUserBO() != null
					&& credentials.getClientUserBO().getSource() != null) {
				ClientUser clientUser = clientUserDAO.findByUserName(userName);
				if (clientUser != null) {
					clientUser.setTrusted(true);
					clientUserDAO.saveAndFlush(clientUser);
				} else {

					LOGGER.debug("The Client User does not exist.. Hence storing the client user details here..");
					ClientUser clientUser1 = new ClientUser();
					clientUser1.setUserName(userName);
					clientUser1.setHasBsveAccount(true);
					clientUser1.setSource(credentials.getClientUserBO()
							.getSource());
					clientUser1.setCreateDateTime(DateTool.now());
					clientUser1.setModifiedDateTime(DateTool.now());
					clientUser1.setTrusted(true);
					StringBuilder builder = new StringBuilder();
					builder.append(BsveAuthConstants.ACCESS_TOKEN + ":"
							+ credentials.getClientUserBO().getAccessToken()
							+ ";" + BsveAuthConstants.REFRESH_TOKEN + ":"
							+ credentials.getClientUserBO().getRefreshToken());
					clientUser1.setToken(builder.toString());
					clientUserDAO.save(clientUser1);
				}
				String action = MESSAGEBUNDLE
						.getMessage(MessageConstants.BSP_USER_TRUST_TO_ACCESS_BSVE);
				ActivityLogDTO activityLogDTO = UserUtils
						.buildUserActivityLogDTO(action, authentication
								.getUserName(), authentication.getUserName(),
								request.getData().getClientAgentDTO(),
								tenantId, authorization.getRole());
				activityLogService.addActivity(activityLogDTO);
			}
		}

		return response;
	}

	public void invalidateAuthTicket(String ticket) {
		// There is nothing to do. This is provided for facilitating cache
		// invalidation

	}

	private AuthResult buildAuthResult(String userName, String ticket) {
		// Create and fill authresult for the user
		AuthResult authResult = new AuthResult();
		fillUserDetails(authResult, userName);
		authResult.setTicket(ticket);
		// get tenant information for ticket.
		authResult.setTenancy(getTenantIdFromTicket(ticket));
		authResult.setTenantName(tenancyMasterService
				.getTenantNameById(authResult.getTenancy()));
		return authResult;
	}

	private String getTenantIdFromTicket(String ticket) {
		byte[] encodedBytes = Base64.decodeBase64(ticket);
		String tokenStrVal = new String(encodedBytes);
		String tokenSplit[] = tokenStrVal.split("\\\\");
		return tokenSplit[1];
	}

	private void fillUserDetails(AuthResult authResult, String userName) {
		// Get the user details
		User user = userDao.findByUserName(userName);
		fillUserDetails(authResult, user);
	}

	private void fillUserDetails(AuthResult authResult, User user) {
		if (user != null) {
			authResult.setTenancy(user.getTenantId());
			authResult.setUserName(user.getUserName());
			authResult.setFirstName(user.getFirstName());
			authResult.setLastName(user.getLastName());
			authResult.setMiddleName(user.getMiddleName());

			// fetch roles associated with the user
			Authorization authorization = user.getAuthorization();
			if (authorization != null) {
				authResult.setRole(authorization.getRole());
			}

			// Get the tenant name
			// FIXME Add a tenant name later, for now use Description;
			String tenantName = tenancyMasterService.getTenantNameById(user
					.getTenantId());
			if (tenantName == null || tenantName.isEmpty()) {
				authResult.setTenantName("");
			} else {
				authResult.setTenantName(tenantName);
			}
		}
	}

	private void updateFailedLoginAttempts(
			ServiceResponse<AuthResult> response, Authentication authentication) {
		// increment failed-attempts count to enable account locking after max
		// retries
		Integer failedLoginAttempts = authentication.getFailedLoginAttempts();

		failedLoginAttempts = failedLoginAttempts + 1;

		if (failedLoginAttempts < LOGIN_RETRIES_COUNT) {
			authentication.setFailedLoginAttempts(failedLoginAttempts);

			response.setStatus(ServiceResponse.FAILED_3);
			response.addMessage(MESSAGEBUNDLE
					.getMessage(MessageConstants.MSG_USERNAME_PASSWORD_INCORRECT));

		} else {
			// max number of retries reached.. lock the account
			authentication.setStatus(AccountStatus.LOCKED.getId());

			// reset failed attempts count to enable fresh start after unlock
			authentication.setFailedLoginAttempts(0);

			String action = MESSAGEBUNDLE
					.getMessage(MessageConstants.MSG_USER_AUDIT_SERVICE_ACTION_LOCK);
			ActivityLogDTO activityLogDTO = UserUtils.buildUserActivityLogDTO(
					action, authentication.getUserName(),
					authentication.getUserName());
			activityLogService.addActivity(activityLogDTO);

			response.setStatus(ServiceResponse.FAILED_5);
			response.addMessage(MESSAGEBUNDLE
					.getMessage(MessageConstants.MSG_INCORRECT_PASSWORD_ACCOUNT_LOCKED));
		}

		authenticationDAO.save(authentication);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.difz.harbinger.user.service.AuthService#logout(com.difz.harbinger
	 * .common.dto.ServiceRequest)
	 */
	@Override
	public ServiceResponse<String> logout(ServiceRequest<AuthSession> request,
			String message) {

		String userName = request.getData().getUserName();

		ServiceResponse<String> response = new ServiceResponse<String>();
		if (StringUtils.isBlank(userName)) {

			response.setStatus(ServiceResponse.FAILED);
			response.addMessage(MESSAGEBUNDLE
					.getMessage(MessageConstants.MSG_LOGOUT_AUTHTICKET_NULL));

		} else {

			Authentication authentication = authenticationDAO
					.findByUserName(userName);

			if (authentication == null) {

				response.setStatus(ServiceResponse.SUCCESS_2);
				response.addMessage(MESSAGEBUNDLE
						.getMessage(MessageConstants.MSG_LOGOUT_AUTHTICKET_INVALID));

			} else {

				authentication.setTicket(null);
				authentication.setTicketExpiry(null);
				authentication.setLastLogoutDateTime(new Date());

				authenticationDAO.save(authentication);
				Authorization authorization = authorizationDao
						.findByUserName(userName);
				String tenantId = null;
				String oauthTicket = request.getData().getAuthTicket();
				if (oauthTicket
						.indexOf(BSPOAuthUtils.THIRD_PARTY_TOKEN_IDENTIFIER) > 0) {
					try {
						BSPAccessTokenDetailsBO userDetails = BSPOAuthUtils
								.getUserDetailsFromToken(oauthTicket);
						if (userDetails != null
								&& !StringUtils.isBlank(userDetails
										.getTenantId())) {
							tenantId = userDetails.getTenantId();
						}
					} catch (Exception e) {
						LOGGER.error("Exception while validating oAuth BSP token"
								+ e);
					}
				} else {
					tenantId = getTenantIdFromTicket(request.getData()
							.getAuthTicket());
				}
				if (StringUtils.isBlank(tenantId)) {
					tenantId = userDao.getTenantIdByUserName(userName);
				}

				String action = MESSAGEBUNDLE
						.getMessage(MessageConstants.MSG_USER_LOGOUT);
				ActivityLogDTO activityLogDTO = UserUtils
						.buildUserActivityLogDTO(action, authentication
								.getUserName(), authentication.getUserName(),
								request.getData().getClientAgentDTO(),
								tenantId, authorization.getRole());
				activityLogDTO.setMessage(message);
				// Bug Fix - Remove Last Transaction activity when user logout
				// from the System
				activityLogService
						.removeActivityLogForUserTransaction(
								authentication.getUserName(),
								MESSAGEBUNDLE
										.getMessage(MessageConstants.MSG_USER_LAST_TRANSACTION),
								null);

				activityLogService.addActivity(activityLogDTO);
				response.setStatus(ServiceResponse.SUCCESS);
				response.addMessage(MESSAGEBUNDLE
						.getMessage(MessageConstants.MSG_LOGOUT_SUCCESSFUL));

			}

		}

		return response;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.difz.harbinger.user.service.AuthService#
	 * updatePasswordWithCurrentPasswordCheck(com.difz.harbinger.common.
	 * dto.ServiceRequest)
	 */
	@Override
	public ServiceResponse<String> updatePasswordWithCurrentPasswordCheck(
			ServiceRequest<AuthCredentials> request, String originHost,
			String authTicket) {
		ServiceResponse<String> response = new ServiceResponse<String>();

		AuthCredentials credentials = request.getData();

		if (UserUtils.validateCredentials(response, credentials, false, false)
				&& UserUtils.validatePassword(response,
						credentials.getNewPassword())) {

			boolean validPassword = clientDetailsDao.doesPasswordMatch(
					credentials.getUserName(), credentials.getPassword());
			String updater = StringUtils.isNotBlank(credentials
					.getLastUpdatedBy()) ? credentials.getLastUpdatedBy()
					: credentials.getUserName();
			Authorization authorization = authorizationDao
					.findByUserName(updater);
			String tenantId = null;

			if (StringUtils.isNotBlank(authTicket)) {
				tenantId = getTenantIdFromTicket(authTicket);
			} else {
				tenantId = userDao.getTenantIdByUserName(credentials
						.getUserName());
			}

			String action = MESSAGEBUNDLE
					.getMessage(MessageConstants.MSG_PASSWORD_CHANGE_SUCCESSFUL);
			ActivityLogDTO activityLogDTO = UserUtils.buildUserActivityLogDTO(
					action, credentials.getUserName(), credentials
							.getUserName(), request.getData()
							.getClientAgentDTO(), originHost, tenantId,
					authorization.getRole());

			if (validPassword) {
				String checkKeyNew = DigestUtils.sha1(credentials
						.getNewPassword());

				authenticationDAO.updateCheckKeyByUserName(
						credentials.getUserName(), checkKeyNew);

				// Update user password in OAuth system.
				LOGGER.info("Updating password for user: {} into OAuth system",
						credentials.getUserName());
				clientDetailsDao.modifyCredentials(credentials.getUserName(),
						credentials.getNewPassword());

				// sync new password to openfire server
				// OpenFireSyncUtil.syncUserInfo(credentials.getUserName(),
				// checkKeyNew, OpenFireSyncUtil.EDIT_OPERATION);

				response.setStatus(ServiceResponse.SUCCESS);
				response.addMessage(MESSAGEBUNDLE
						.getMessage(MessageConstants.MSG_PASSWORD_CHANGE_SUCCESSFUL));

				activityLogDTO
						.setAction(MESSAGEBUNDLE
								.getMessage(MessageConstants.MSG_PASSWORD_CHANGE_SUCCESSFUL));
				activityLogService.addActivity(activityLogDTO);

			} else {
				response.setStatus(ServiceResponse.FAILED_3);
				response.addMessage(MESSAGEBUNDLE
						.getMessage(MessageConstants.MSG_PASSWORD_CHANGE_INVALID_CURRENT_PASSWORD));

				activityLogDTO
						.setAction(MESSAGEBUNDLE
								.getMessage(MessageConstants.MSG_PASSWORD_CHANGE_FAILURE));
				activityLogService.addActivity(activityLogDTO);
			}
		}

		return response;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.difz.harbinger.user.service.AuthService#updatePassword(com.difz.harbinger
	 * .common.dto.ServiceRequest)
	 */
	@Override
	public ServiceResponse<String> updatePassword(
			ServiceRequest<AuthCredentials> request) {
		ServiceResponse<String> response = new ServiceResponse<String>();

		AuthCredentials credentials = request.getData();

		if (UserUtils.validateCredentials(response, credentials, true, false)) {

			String checkKey = DigestUtils.sha1(credentials.getPassword());

			authenticationDAO.updateCheckKeyByUserName(
					credentials.getUserName(), checkKey);

			// Update user password in OAuth system.
			LOGGER.info("Updating password for user: {} into OAuth system",
					credentials.getUserName());
			clientDetailsDao.modifyCredentials(credentials.getUserName(),
					credentials.getPassword());

			// sync new password to openfire server
			// OpenFireSyncUtil.syncUserInfo(credentials.getUserName(),
			// checkKey, OpenFireSyncUtil.EDIT_OPERATION);
			response.setStatus(ServiceResponse.SUCCESS);
			response.addMessage(MESSAGEBUNDLE
					.getMessage(MessageConstants.MSG_PASSWORD_CHANGE_SUCCESSFUL));
			// capturing this activity
			String action = MESSAGEBUNDLE
					.getMessage(MessageConstants.MSG_PASSWORD_CHANGE_SUCCESSFUL);
			Authorization authorization = authorizationDao
					.findByUserName(credentials.getUserName());
			String tenantId = userDao.getTenantIdByUserName(credentials
					.getUserName());
			String originHost = null;
			if (request.getData().getClientAgentDTO() != null) {
				originHost = request.getData().getClientAgentDTO().getHost();
			}
			ActivityLogDTO activityLogDTO = UserUtils.buildUserActivityLogDTO(
					action, credentials.getUserName(), credentials
							.getUserName(), credentials.getClientAgentDTO(),
					originHost, tenantId,
					((authorization != null) ? authorization.getRole() : ""));

			activityLogService.addActivity(activityLogDTO);
		}

		return response;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.difz.harbinger.user.service.AuthService#updateSecurityQuestionnaire
	 * (com.difz.harbinger.common.dto.ServiceRequest )
	 */
	@Override
	public ServiceResponse<String> updateSecurityQuestionnaire(
			ServiceRequest<AuthCredentials> request, String originHost,
			String authTicket) {
		ServiceResponse<String> response = new ServiceResponse<String>();

		AuthCredentials credentials = request.getData();

		if (UserUtils.validateCredentials(response, credentials, false, true)) {

			String securityAnswerSHA1 = DigestUtils.sha1(credentials
					.getSecurityAnswer());

			authenticationDAO.updateSecurityQuestionnaireByUserName(
					credentials.getUserName(),
					credentials.getSecurityQuestion(), securityAnswerSHA1);

			String updater = StringUtils.isNotBlank(credentials
					.getLastUpdatedBy()) ? credentials.getLastUpdatedBy()
					: credentials.getUserName();
			Authorization authorization = authorizationDao
					.findByUserName(updater);
			String tenantId = null;

			if (StringUtils.isNotBlank(authTicket)) {
				tenantId = getTenantIdFromTicket(authTicket);
			} else {
				tenantId = userDao.getTenantIdByUserName(credentials
						.getUserName());
			}

			String action = MESSAGEBUNDLE
					.getMessage(MessageConstants.MSG_USER_SECURITY_QUESTIONNAIRE_EDITED);
			ActivityLogDTO activityLogDTO = UserUtils.buildUserActivityLogDTO(
					action, request.getData().getUserName(), request.getData()
							.getUserName(), request.getData()
							.getClientAgentDTO(), originHost, tenantId,
					authorization.getRole());
			activityLogService.addActivity(activityLogDTO);

			response.setStatus(ServiceResponse.SUCCESS);
			response.addMessage(MESSAGEBUNDLE
					.getMessage(MessageConstants.MSG_SEC_QA_CHANGE_SUCCESSFUL));

		}

		return response;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.difz.harbinger.user.service.AuthService#
	 * updatePasswordAndSecurityQuestionnaire(com.difz.harbinger.common.
	 * dto.ServiceRequest)
	 */
	@Override
	public ServiceResponse<String> updatePasswordAndSecurityQuestionnaire(
			ServiceRequest<AuthCredentials> request) {
		ServiceResponse<String> response = new ServiceResponse<String>();

		AuthCredentials credentials = request.getData();

		if (UserUtils.validateCredentials(response, credentials, true, true)) {

			String checkKey = DigestUtils.sha1(credentials.getPassword());
			String securityAnswerSHA1 = DigestUtils.sha1(credentials
					.getSecurityAnswer());

			authenticationDAO.updateCheckKeyAndSecurityQuestionnaireByUserName(
					credentials.getUserName(), checkKey,
					credentials.getSecurityQuestion(), securityAnswerSHA1);

			// Update user password in OAuth system.
			LOGGER.info("Updating password for user: {} into OAuth system",
					credentials.getUserName());
			clientDetailsDao.modifyCredentials(credentials.getUserName(),
					credentials.getPassword());

			// sync new password to openfire server
			// OpenFireSyncUtil.syncUserInfo(credentials.getUserName(),
			// checkKey, OpenFireSyncUtil.EDIT_OPERATION);

			response.setStatus(ServiceResponse.SUCCESS);
			response.addMessage(MESSAGEBUNDLE
					.getMessage(MessageConstants.MSG_PASSWORD_SECQA_CHANGE_SUCCESSFUL));

		}

		return response;
	}

	// check security question and answer for user name
	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.difz.harbinger.user.service.AuthService#checkSecurityQuestionnaire
	 * (com.difz.harbinger.common.dto.ServiceRequest )
	 */
	@Override
	public ServiceResponse<Boolean> checkSecurityQuestionnaire(
			ServiceRequest<AuthCredentials> request, String originHost) {
		ServiceResponse<Boolean> response = new ServiceResponse<Boolean>();

		AuthCredentials credentials = request.getData();

		if (UserUtils.validateCredentials(response, credentials, false, true)) {
			String securityAnswerSHA1 = DigestUtils.sha1(credentials
					.getSecurityAnswer());

			Long match = authenticationDAO
					.checkSecurityQuestionnaireByUserName(
							credentials.getUserName(),
							credentials.getSecurityQuestion(),
							securityAnswerSHA1);

			Authorization authorization = authorizationDao
					.findByUserName(credentials.getUserName());
			String tenantId = userDao.getTenantIdByUserName(credentials
					.getUserName());

			String action = null;

			if (match == 1) {
				response.setStatus(ServiceResponse.SUCCESS);
				response.addMessage(MESSAGEBUNDLE
						.getMessage(MessageConstants.MSG_SECQA_VERIFICATION_SUCCESSFUL));
				action = MESSAGEBUNDLE
						.getMessage(MessageConstants.MSG_USER_FORGOT_PASSWORD_SECURITY_CHECK_SUCCESSFUL);

			} else {
				response.setStatus(ServiceResponse.FAILED);
				response.addMessage(MESSAGEBUNDLE
						.getMessage(MessageConstants.MSG_SECQA_VERIFICATION_FAILURE));
				action = MESSAGEBUNDLE
						.getMessage(MessageConstants.MSG_USER_FORGOT_PASSWORD_FAILURE);

			}

			ActivityLogDTO activityLogDTO = UserUtils.buildUserActivityLogDTO(
					action, request.getData().getUserName(), request.getData()
							.getUserName(), request.getData()
							.getClientAgentDTO(), originHost, tenantId,
					((authorization != null) ? authorization.getRole() : ""));
			if (StringUtils.isBlank(tenantId) && null == authorization) {
				activityLogDTO.setMessage(MESSAGEBUNDLE
						.getMessage(MessageConstants.MSG_USER_NOT_FOUND));
			}
			activityLogService.addActivity(activityLogDTO);

			response.setData(match == 1);
		}

		return response;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.difz.harbinger.user.service.AuthService#activate(com.difz.harbinger
	 * .common.dto.ServiceRequest)
	 */
	@Override
	public ServiceResponse<String> activate(
			ServiceRequest<AuthCredentials> request, String originHost,
			String authTicket) {

		ServiceResponse<String> response = new ServiceResponse<String>();

		AuthCredentials credentials = request.getData();

		if (UserUtils.validateCredentials(response, credentials, false, false)) {

			// load user entity.
			User user = userDao.findOne(request.getData().getUserName());

			if (null == user) {
				response.setStatus(ServiceResponse.ERROR);
				response.addMessage(MESSAGEBUNDLE
						.getMessage(MessageConstants.MSG_USER_NOT_FOUND));

			} else {

				// Check if status is already set to Active by other
				// Approver/Admin
				if (UserUtils.compareStatus(user.getAuthentication()
						.getStatus(), AccountStatus.ACTIVE.getId())) {

					response.setStatus(ServiceResponse.FAILED);
					response.addMessage(MESSAGEBUNDLE
							.getMessage(MessageConstants.MSG_ACCOUNT_ALREADY_ACTIVATED));

				} else {

					// update user account details
					user.getAuthentication().setStatus(
							AccountStatus.ACTIVE.getId());
					user.setLastUpdatedBy(request.getData().getLastUpdatedBy());
					user.setModifiedDateTime(DateTool.now());
					userDao.saveAndFlush(user);
					String updater = StringUtils.isNotBlank(credentials
							.getLastUpdatedBy()) ? credentials
							.getLastUpdatedBy() : credentials.getUserName();
					Authorization authorization = authorizationDao
							.findByUserName(updater);
					String tenantId = null;

					if (StringUtils.isNotBlank(authTicket)) {
						tenantId = getTenantIdFromTicket(authTicket);
					} else {
						tenantId = userDao.getTenantIdByUserName(credentials
								.getUserName());
					}

					String action = MESSAGEBUNDLE
							.getMessage(MessageConstants.MSG_USER_AUDIT_SERVICE_ACTION_REACTIVATE);
					ActivityLogDTO activityLogDTO = UserUtils
							.buildUserActivityLogDTO(action, request.getData()
									.getLastUpdatedBy(), request.getData()
									.getUserName(), request.getData()
									.getClientAgentDTO(), originHost, tenantId,
									authorization.getRole());
					activityLogService.addActivity(activityLogDTO);

					response.setStatus(ServiceResponse.SUCCESS);
					response.addMessage(MESSAGEBUNDLE
							.getMessage(MessageConstants.MSG_ACCOUNT_ACTIVATE_SUCCESSFUL));
				}

			}
		}

		return response;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.difz.harbinger.user.service.AuthService#deactivate(com.difz.harbinger
	 * .common.dto.ServiceRequest)
	 */
	@Override
	public ServiceResponse<String> deactivate(
			ServiceRequest<AuthCredentials> request, String originHost,
			String authTicket) {

		ServiceResponse<String> response = new ServiceResponse<String>();

		AuthCredentials credentials = request.getData();

		if (UserUtils.validateCredentials(response, credentials, false, false)) {

			// load user entity.
			User user = userDao.findOne(request.getData().getUserName());

			if (null == user) {
				response.setStatus(ServiceResponse.ERROR);
				response.addMessage(MESSAGEBUNDLE
						.getMessage(MessageConstants.MSG_USER_NOT_FOUND));

			} else {

				// Check if status is already set to inactive/deactivated by
				// other Approver/Admin
				if (UserUtils.compareStatus(user.getAuthentication()
						.getStatus(), AccountStatus.INACTIVE.getId())) {

					response.setStatus(ServiceResponse.FAILED);
					response.addMessage(MESSAGEBUNDLE
							.getMessage(MessageConstants.MSG_ACCOUNT_ALREADY_DEACTIVATED));

				} else {

					// update user account details
					user.getAuthentication().setStatus(
							AccountStatus.INACTIVE.getId());
					user.setLastUpdatedBy(request.getData().getLastUpdatedBy());
					user.setModifiedDateTime(DateTool.now());

					userDao.saveAndFlush(user);
					String updater = StringUtils.isNotBlank(credentials
							.getLastUpdatedBy()) ? credentials
							.getLastUpdatedBy() : credentials.getUserName();
					Authorization authorization = authorizationDao
							.findByUserName(updater);
					String tenantId = null;

					if (StringUtils.isNotBlank(authTicket)) {
						tenantId = getTenantIdFromTicket(authTicket);
					} else {
						tenantId = userDao.getTenantIdByUserName(credentials
								.getUserName());
					}

					String action = MESSAGEBUNDLE
							.getMessage(MessageConstants.MSG_USER_AUDIT_SERVICE_ACTION_DEACTIVATE);
					ActivityLogDTO activityLogDTO = UserUtils
							.buildUserActivityLogDTO(action, request.getData()
									.getLastUpdatedBy(), request.getData()
									.getUserName(), request.getData()
									.getClientAgentDTO(), originHost, tenantId,
									authorization.getRole());
					activityLogService.addActivity(activityLogDTO);

					response.setStatus(ServiceResponse.SUCCESS);
					response.addMessage(MESSAGEBUNDLE
							.getMessage(MessageConstants.MSG_ACCOUNT_DEACTIVATE_SUCCESSFUL));
				}
			}
		}

		return response;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.difz.harbinger.user.service.AuthService#unlock(com.difz.harbinger
	 * .common.dto.ServiceRequest)
	 */
	@Override
	public ServiceResponse<String> unlock(
			ServiceRequest<AuthCredentials> request) {

		ServiceResponse<String> response = new ServiceResponse<String>();

		AuthCredentials credentials = request.getData();

		if (UserUtils.validateCredentials(response, credentials, false, false)) {

			// load user entity.
			User user = userDao.findOne(request.getData().getUserName());

			if (null == user) {
				response.setStatus(ServiceResponse.ERROR);
				response.addMessage(MESSAGEBUNDLE
						.getMessage(MessageConstants.MSG_USER_NOT_FOUND));

			} else {

				// Check if status is already set to Unlock (i.e., Active state)
				// by other Approver/Admin
				if (UserUtils.compareStatus(user.getAuthentication()
						.getStatus(), AccountStatus.ACTIVE.getId())) {

					response.setStatus(ServiceResponse.FAILED);
					response.addMessage(MESSAGEBUNDLE
							.getMessage(MessageConstants.MSG_ACCOUNT_ALREADY_ACTIVATED));

				} else {

					// update user account details and activate account
					user.getAuthentication().setStatus(
							AccountStatus.ACTIVE.getId());
					user.getAuthentication().setFailedLoginAttempts(0);
					user.setLastUpdatedBy(request.getData().getLastUpdatedBy());
					user.setModifiedDateTime(DateTool.now());

					userDao.saveAndFlush(user);

					String action = MESSAGEBUNDLE
							.getMessage(MessageConstants.MSG_USER_AUDIT_SERVICE_ACTION_UNLOCK);
					ActivityLogDTO activityLogDTO = UserUtils
							.buildUserActivityLogDTO(action, request.getData()
									.getLastUpdatedBy(), request.getData()
									.getUserName());
					activityLogService.addActivity(activityLogDTO);

					response.setStatus(ServiceResponse.SUCCESS);
					response.addMessage(MESSAGEBUNDLE
							.getMessage(MessageConstants.MSG_ACCOUNT_UNLOCK_SUCCESSFUL));
				}
			}
		}
		return response;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.difz.harbinger.user.service.AuthService#generateAccessToken(com.difz
	 * .harbinger.common.dto.AuthorizationRequest )
	 */
	@Override
	public AuthorizationResponse generateAccessToken(
			AuthorizationRequest request) {
		Authentication authentication = authenticationDAO.findByTicket(request
				.getCode());
		AuthorizationResponse response = null;
		if (authentication != null) {
			response = new AuthorizationResponse();
			response.setAccessToken(request.getCode()
					+ System.currentTimeMillis());
			authentication.setTicket(response.getAccessToken());
			authenticationDAO.save(authentication);
		}
		return response;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.difz.harbinger.user.service.AuthService#generateAPIAccessCredentials
	 * (com.difz.harbinger.common.dto.ServiceRequest )
	 */
	@Override
	public ServiceResponse<APIAccessCredentials> generateAPIAccessCredentials(
			ServiceRequest<AuthCredentials> request) throws Exception {
		LOGGER.trace("Inside generateAPIAccessCredentials");
		ServiceResponse<APIAccessCredentials> response = new ServiceResponse<>();
		ServiceResponse<AuthResult> authenticationResult = null;
		try {
			authenticationResult = authenticate(request);
		} catch (BsveOAuthServiceException e) {
			LOGGER.error("Error while validating user authentication ", e);
			return null;
		}
		response.setStatus(authenticationResult.getStatus());
		response.setMessages(authenticationResult.getMessages());
		if (authenticationResult.getData() != null) {
			LOGGER.debug("generting access key and secret key for the user {}",
					authenticationResult.getData().getUserName());
			APIAccessCredentials accessCreds = new APIAccessCredentials();
			accessCreds.setUserName(authenticationResult.getData()
					.getUserName());
			accessCreds.setAccessKey(ACCESS_KEY_PREFIX
					+ UUID.randomUUID().toString());
			accessCreds.setSecretKey(SCRET_KEY_PREFIX
					+ UUID.randomUUID().toString());
			response.setData(accessCreds);
			Authentication authentication = authenticationDAO.findOne(request
					.getData().getUserName());
			authentication.setAccessKey(accessCreds.getAccessKey());
			authentication.setSecretKey(accessCreds.getSecretKey());
			LOGGER.debug(
					"updating user - {} Authentication entity with access "
							+ "credentials", request.getData().getUserName());
			authenticationDAO.save(authentication);
		}
		return response;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.difz.harbinger.user.service.AuthService#getUserDetails(com.difz.harbinger
	 * .common.dto.APIAccessCredentials)
	 */
	@Override
	public ServiceResponse<AuthResult> getUserDetails(
			APIAccessCredentials apiCredentials) {
		LOGGER.trace("Inside getUserDetails");
		ServiceResponse<AuthResult> response = new ServiceResponse<>();
		if (StringUtils.isEmpty(apiCredentials.getAccessKey())
				|| StringUtils.isEmpty(apiCredentials.getSecretKey())) {
			LOGGER.info("Access credentials by the user are empty");
			response.setStatus(ServiceResponse.FAILED);
			response.addMessage(MESSAGEBUNDLE
					.getMessage(MessageConstants.MSG_ACCESS_CREDENTIALS_EMPTY));
			return response;
		}
		User user = userDao.findByAccessCredentials(
				apiCredentials.getAccessKey(), apiCredentials.getSecretKey());
		if (user == null) {
			LOGGER.info("Access credentials by the user are Invalid");
			response.setStatus(ServiceResponse.FAILED_2);
			response.addMessage(MESSAGEBUNDLE
					.getMessage(MessageConstants.MSG_ACCESS_CREDENTIALS_INCORRECT));
			return response;
		}
		LOGGER.debug("Setting user details for the user {}", user.getUserName());
		AuthResult authResult = new AuthResult();
		// userDetails.setUserName(user.getUserName());
		// userDetails.setRole(user.getAuthorization().getRole());
		// userDetails.setTenancy(user.getTenantId());
		// userDetails.setFirstName(user.getFirstName());
		// userDetails.setLastName(user.getLastName());
		// userDetails.setMiddleName(user.getMiddleName());
		fillUserDetails(authResult, user);
		authResult.setTicket(user.getAuthentication().getTicket());
		response.setData(authResult);
		return response;

	}

	/**
	 * This method validates if the authTicket is valid by checking the expiry
	 * timestamp and extend the expiry time of the ticket.
	 * 
	 * @param authentication
	 *            The authentication object for validation
	 * @param extention
	 *            The time (in milliseconds) to which the ticket validity needs
	 *            to be extended. The extensded time is calculated from the
	 *            current system time.
	 * @return true if authTicket is valid(not expired) else false
	 */
	private boolean validateAndExtendAuthTicket(Authentication authentication,
			long extention) {
		// get the epoch time of expiry token
		long timeToLive = authentication.getTicketExpiry().getTime()
				- System.currentTimeMillis();

		if (timeToLive >= 0) {
			if (extention > 0 && timeToLive < AUTH_TICKET_RENEW_WINDOW) {
				extendTicketValidity(authentication, extention);
			}
			return true;
		} else {
			return false;
		}
	}

	/**
	 * Extends the validity of the ticket. The validation logic increases the
	 * expiry time by 'extension' milliseconds.
	 * 
	 * @param authentication
	 *            The {@link Authentication} object whose ticket expiry time in
	 *            milliseconds to be extended
	 * @param extention
	 *            the extension time in milliseconds
	 * @return The re validated {@link Authentication} object
	 */
	private Authentication extendTicketValidity(Authentication authentication,
			long extension) {

		// Do a fresh read, another call could have updated the object already
		Authentication entity = authenticationDAO.findOne(authentication
				.getUserName());

		// Increment the time. Use the current time as reference, not the time
		// read from db
		entity.setTicketExpiry(new Date(System.currentTimeMillis() + extension));

		authenticationDAO.save(entity);

		return entity;
	}

	/**
	 * Splits the Harbinger-Authentication header values to a map strings for
	 * further processing
	 * 
	 * @param header
	 *            The harbinger-Authentication header of the form
	 *            <token_name>=<value>;<token_name>=value
	 * @return A map of key value pairs
	 */
	private static Map<String, String> readAuthenticationHeader(String header) {
		Scanner scanner = new Scanner(header);
		scanner.useDelimiter("=|;");
		Map<String, String> result = new HashMap<>();
		while (scanner.hasNext()) {
			// JLS mandates that arguments are evaluated left to right
			result.put(scanner.next(), scanner.next());
		}
		scanner.close();
		return result;
	}

	/**
	 * Computes the signature from the signature parameters
	 * 
	 * @param authKey
	 *            The authorization key
	 * @param secretKey
	 *            The secret key
	 * @param userName
	 *            The user name
	 * @param timestamp
	 *            The timestamp of the request
	 * @param nonce
	 *            A one time value, to be set with all authentications
	 * @return The computed signature for the input parametsrs.
	 */
	private static String signature(String authKey, String secretKey,
			String userName, String timestamp, String nonce) {
		String key = authKey + ":" + secretKey;
		String message = authKey + timestamp + nonce + userName;
		return DigestUtils.hmacSha1(key, message);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.difz.harbinger.user.service.AuthService#generateAPISecurityDetails
	 * (java.lang.String)
	 */
	@Override
	public ServiceResponse<APIAccessCredentials> generateAPISecurityDetails(
			String userName) {
		LOGGER.trace("Inside generateAPISecurityDetails");
		ServiceResponse<APIAccessCredentials> response = new ServiceResponse<>();
		Authentication authentication = authenticationDAO.findOne(userName);
		if (authentication != null) {
			LOGGER.debug("generting access key and secret key for the user {}",
					userName);
			APIAccessCredentials accessCreds = new APIAccessCredentials();
			accessCreds.setUserName(authentication.getUserName());
			accessCreds.setAccessKey(ACCESS_KEY_PREFIX
					+ UUID.randomUUID().toString());
			accessCreds.setSecretKey(SCRET_KEY_PREFIX
					+ UUID.randomUUID().toString());
			response.setData(accessCreds);

			authentication.setAccessKey(accessCreds.getAccessKey());
			authentication.setSecretKey(accessCreds.getSecretKey());
			LOGGER.debug(
					"updating user - {} Authentication entity with access "
							+ "credentials", authentication.getUserName());
			authenticationDAO.save(authentication);
		}
		return response;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.difz.harbinger.user.service.AuthService#getAPISecurityDetails(java
	 * .lang.String)
	 */
	@Override
	public ServiceResponse<APIAccessCredentials> getAPISecurityDetails(
			String userName) {
		LOGGER.trace("Inside generateAPIAccessCredentials");
		ServiceResponse<APIAccessCredentials> response = new ServiceResponse<>();
		Authentication authentication = authenticationDAO.findOne(userName);
		if (authentication != null) {
			LOGGER.debug("getting key and secret key for the user {}", userName);
			APIAccessCredentials accessCreds = new APIAccessCredentials();
			accessCreds.setUserName(authentication.getUserName());
			accessCreds.setAccessKey(authentication.getAccessKey());
			accessCreds.setSecretKey(authentication.getSecretKey());
			response.setData(accessCreds);
		}
		return response;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.difz.harbinger.user.service.AuthService#validate(com.difz.harbinger
	 * .common.dto.ServiceRequest)
	 */
	@Override
	public ServiceResponse<Boolean> validate(ServiceRequest<AuthSession> request) {

		// String data[] = request.getData().split(",");
		// String userName = data[0];
		// String authTicket = data[1];

		String userName = request.getData().getUserName();
		String authTicket = request.getData().getAuthTicket();

		ServiceResponse<Boolean> response = new ServiceResponse<>();
		Authentication auth = authenticationDAO.findByUserName(userName);
		if ("AN".contains(auth.getStatus())
				&& authTicket.equals(auth.getTicket())
				&& auth.getTicketExpiry().getTime() >= System
						.currentTimeMillis()) {

			// Extend the session validity
			extendTicketValidity(auth, AUTH_TICKET_VALIDITY_TIME);

			response.setStatus(ServiceResponse.SUCCESS);
			response.addMessage(MESSAGEBUNDLE
					.getMessage(MessageConstants.MSG_SESSION_ACTIVE));
			response.setData(Boolean.TRUE);
		} else {
			response.setStatus(ServiceResponse.ERROR);
			response.addMessage(MESSAGEBUNDLE
					.getMessage(MessageConstants.MSG_SESSION_INACTIVE));
			response.setData(Boolean.FALSE);
		}

		return response;
	}
	/**
	 * Gets User record for the given userName.
	 * 
	 * @param userName - user name to find the UserAuthentication details
	 * @return response - {@link ServiceResponse} holds the response details.
	 */
	@Override
	public ServiceResponse<UserAuthenticationBO> getAuthUserDetails(
			String userName) {
		LOGGER.trace("Inside getAuthUserDetails");
		ServiceResponse<UserAuthenticationBO> response = new ServiceResponse<>();
		if (userName == null || userName.trim().isEmpty()) {

			response.setStatus(ServiceResponse.FAILED);
			response.addMessage(MESSAGEBUNDLE
					.getMessage(MessageConstants.MSG_USER_USERNAME_EMPTY));

		} else {
			UserAuthentication userAuthentication = userAuthenticationDAO
					.findByUserName(userName);
			if (userAuthentication == null) {

				response.setStatus(ServiceResponse.FAILED_2);
				response.addMessage(MESSAGEBUNDLE
						.getMessage(MessageConstants.MSG_USER_NOT_FOUND));

			} else {
				LOGGER.debug("getting userName for the user {}", userName);
				UserAuthenticationBO userAuthenticationBO = translateAuthDetails(userAuthentication);
				response.setStatus(ServiceResponse.SUCCESS);
				response.addMessage(MESSAGEBUNDLE
						.getMessage(MessageConstants.MSG_USER_RETRIEVE_SUCCESSFUL));
				response.setData(userAuthenticationBO);
			}
		}
		return response;

	}
	/**
	 * This method translates the userAuthentication object from UserAuthentication entity to UserAuthenticationBO.
	 * 
	 * @param UserAuthentication - User entity
	 * @return UserAuthenticationBO - transformed object
	 */

	private UserAuthenticationBO translateAuthDetails(
			UserAuthentication userAuthentication) {
		UserAuthenticationBO userAuthenticationBO = new UserAuthenticationBO();
		userAuthenticationBO.setUserName(userAuthentication.getUserName());
		userAuthenticationBO.setRole(userAuthentication.getRole());
		userAuthenticationBO.setCheckKey(userAuthentication.getCheckKey());
		userAuthenticationBO.setTicket(userAuthentication.getTicket());
		userAuthenticationBO.setTicketExpiry(userAuthentication
				.getTicketExpiry());
		userAuthenticationBO.setSecurityQuestion(userAuthentication
				.getSecurityQuestion());
		userAuthenticationBO.setSecurityAnswer(userAuthentication
				.getSecurityAnswer());
		userAuthenticationBO.setStatus(userAuthentication.getStatus());
		userAuthenticationBO.setFailedLoginAttempts(userAuthentication
				.getFailedLoginAttempts());
		userAuthenticationBO.setAccountExpiry(userAuthentication
				.getAccountExpiry());
		userAuthenticationBO.setAccessKey(userAuthentication.getAccessKey());
		userAuthenticationBO.setSecretKey(userAuthentication.getSecretKey());
		userAuthenticationBO.setLastLoginDateTime(userAuthentication
				.getLastLoginDateTime());
		userAuthenticationBO.setLastLogoutDateTime(userAuthentication
				.getLastLogoutDateTime());
		return userAuthenticationBO;

	}

	/**
	 * This method is used to save UserAuthentication details of new User
	 * 
	 * @return
	 */
	public ServiceResponse<String> saveUserAuthEntry(
			UserAuthenticationBO userAuthenticationBO) {
		ServiceResponse<String> response = new ServiceResponse<String>();
		if (userAuthenticationBO == null) {
			response.setStatus(ServiceResponse.FAILED);
			response.addMessage(MESSAGEBUNDLE
					.getMessage(MessageConstants.MSG_INVALID_REQUEST));
		} else {
			UserAuthentication userAuthentication = buildUserAuth(userAuthenticationBO);
			
			userAuthenticationDAO.save(userAuthentication);
			response.setStatus(ServiceResponse.SUCCESS);
			response.addMessage("Saved UserAuthentication Details Successfully");
		}
		return response;
	}

	/**
	 * This method is used to update UserAuthentication details
	 * 
	 * @return
	 */
	public ServiceResponse<String> updateAuthDetails(
			UserAuthenticationBO userAuthenticationBO) {
		ServiceResponse<String> response = new ServiceResponse<String>();
		UserAuthentication userAuthentication = userAuthenticationDAO
				.findByUserName(userAuthenticationBO.getUserName());
		if (userAuthentication == null) {

			response.setStatus(ServiceResponse.FAILED);
			response.addMessage(MESSAGEBUNDLE
					.getMessage(MessageConstants.MSG_USER_NOT_FOUND));
		} else {
			userAuthentication = buildUserAuth(userAuthenticationBO);
			if(validateUser(userAuthenticationBO, response)){	
			userAuthenticationDAO.saveAndFlush(userAuthentication);
			response.setStatus(ServiceResponse.SUCCESS);
			response.addMessage("Updated UserAuthentication Details Successfully");
			}
			else{
				LOGGER.info("userAuthDetails {} are not valid",
						userAuthenticationBO.getUserName());
			}
		}
		return response;

	}

	private UserAuthentication buildUserAuth(
			UserAuthenticationBO userAuthenticationBO) {
		UserAuthentication userAuthentication = new UserAuthentication();
		userAuthentication.setUserName(userAuthenticationBO.getUserName());
		userAuthentication.setRole(userAuthenticationBO.getRole());
		userAuthentication.setCheckKey(userAuthenticationBO.getCheckKey());
		userAuthentication.setTicket(userAuthenticationBO.getTicket());
		userAuthentication.setTicketExpiry(userAuthenticationBO
				.getTicketExpiry());
		userAuthentication.setSecurityQuestion(userAuthenticationBO
				.getSecurityQuestion());
		userAuthentication.setSecurityAnswer(userAuthenticationBO
				.getSecurityAnswer());
		userAuthentication.setStatus(userAuthenticationBO.getStatus());
		userAuthentication.setFailedLoginAttempts(userAuthenticationBO
				.getFailedLoginAttempts());
		userAuthentication.setAccountExpiry(userAuthenticationBO
				.getAccountExpiry());
		userAuthentication.setAccessKey(userAuthenticationBO.getAccessKey());
		userAuthentication.setSecretKey(userAuthenticationBO.getSecretKey());
		userAuthentication.setLastLoginDateTime(userAuthenticationBO
				.getLastLoginDateTime());
		userAuthentication.setLastLogoutDateTime(userAuthenticationBO
				.getLastLogoutDateTime());
		return userAuthentication;

	}

	/**
	 * Validates the UserAuthentication details.
	 * 
	 * @param userAuthenticationBO - {@link UserAuthenticationBO} holds the userAuthentication information.
	 * @param response - {@link ServiceResponse} holds the response details.
	 * @return boolean - validation result.
	 */
	private boolean validateUser(UserAuthenticationBO userAuthenticationBO, ServiceResponse<String> response) {
		boolean validate = true;
	
		 if(StringUtils.isBlank(userAuthenticationBO.getUserName()))
	     {
	    	 validate = false;
				response.setStatus(ServiceResponse.FAILED);
				response.addMessage(MESSAGEBUNDLE
				        .getMessage(MessageConstants.MSG_USER_NOT_FOUND));
			}
	     if(StringUtils.isBlank(userAuthenticationBO.getRole())) {
	    	 validate = false;
	    	 response.setStatus(ServiceResponse.FAILED);
	    	 response.addMessage(MESSAGEBUNDLE
				        .getMessage(MessageConstants.MSG_USER_ROLE_EMPTY));
	     }
	     
	     if(StringUtils.isBlank(userAuthenticationBO.getCheckKey())){
	    	 validate = false;
	    	 response.setStatus(ServiceResponse.FAILED);
	    	 response.addMessage(MESSAGEBUNDLE
				        .getMessage(MessageConstants.MSG_PASSWORD_NULL));
	     }
		
			return validate;
	     }

}

