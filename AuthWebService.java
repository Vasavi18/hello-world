package com.difz.bsve.oauth.api;

import java.util.HashMap;
import java.util.List;

import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.commons.beanutils.BeanUtils;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.difz.bsve.auth.data.model.UserAuthentication;
import com.difz.bsve.auth.data.model.UserDetail;
import com.difz.bsve.oauth.bsp.service.BSPOAuthService;
import com.difz.bsve.oauth.dto.BsveOAuthResponseBO;
import com.difz.bsve.oauth.dto.BsveUserBO;
import com.difz.bsve.oauth.util.BSPOAuthUtils;
import com.difz.bsve.oauth.util.BsveAuthConstants;
import com.difz.bsve.user.service.AuthService;
import com.difz.bsve.user.service.UserServiceImpl;
import com.difz.harbinger.common.dto.APIAccessCredentials;
import com.difz.harbinger.common.dto.AuthCredentials;
import com.difz.harbinger.common.dto.AuthResult;
import com.difz.harbinger.common.dto.AuthSession;
import com.difz.harbinger.common.dto.BsveAuthResult;
import com.difz.harbinger.common.dto.ClientAgentDTO;
import com.difz.harbinger.common.dto.ServiceRequest;
import com.difz.harbinger.common.dto.ServiceResponse;
import com.difz.harbinger.common.dto.UserAuthenticationBO;
import com.difz.harbinger.common.dto.UserBO;
import com.difz.harbinger.common.util.MessageBundle;
import com.difz.harbinger.common.util.MessageConstants;

/**
 * Webservice implementations for authentication/authorization functionalities.
 */
@Component
@Path("/auth")
public class AuthWebService extends AbstractAuthWebService {

	private static final Logger LOGGER = LoggerFactory
			.getLogger(AuthWebService.class);

	private static final MessageBundle MESSAGEBUNDLE = MessageBundle
			.getInstance();

	private static final String USER_NAME = "userName";

	@Autowired
	private AuthService authService;

	@Autowired
	private UserServiceImpl userService;

	@Autowired
	private BSPOAuthService bspOAuthService;

	@GET
	@Path("/echo/{input}")
	@Produces("text/plain")
	public String ping(@PathParam("input") String input) {

		LOGGER.trace("In ping()");

		return input + "   Auth service is up and running";
	}

	@POST
	@Path("/authenticate")
	@Produces(MediaType.APPLICATION_JSON)
	public Response authenticate(ServiceRequest<AuthCredentials> request) {

		LOGGER.trace("In authenticate()");

		try {
			request.getData().setClientAgentDTO(getUserAgentDetail());
			ServiceResponse<AuthResult> response = authService
					.authenticate(request);
			if (null != response && response.getData() != null) {
				AuthResult authResult = response.getData();
				// set the securityAgreement text to the response.
				BsveAuthResult bsveAuthResult = new BsveAuthResult();
				BeanUtils.copyProperties(bsveAuthResult, response.getData());
				bsveAuthResult.setSecurityAgreementText(userService
						.getAgreementContent(authResult.getUserName(),
								authResult.getTenantName()));
				ServiceResponse<AuthResult> responseWithSecurity = new ServiceResponse<>();
				responseWithSecurity.setMessages(response.getMessages());
				responseWithSecurity.setStatus(response.getStatus());
				responseWithSecurity.setData(bsveAuthResult);
				return Response.ok().entity(responseWithSecurity).build();
			}

			return Response.ok().entity(response).build();

		} catch (Exception e) {
			LOGGER.error("Unexpected error occurred trying to authenticate.", e);

			ServiceResponse<AuthResult> response = new ServiceResponse<AuthResult>();
			response.setStatus(ServiceResponse.ERROR);
			response.addMessage(MESSAGEBUNDLE
					.getMessage(MessageConstants.MSG_UNEXPECTED_ERROR));

			return Response.ok().entity(response).build();
		}
	}

	@POST
	@Path("/logout")
	@Produces(MediaType.APPLICATION_JSON)
	public Response logout(ServiceRequest<AuthSession> request,
			@QueryParam("message") String message) {

		LOGGER.trace("In logout()");

		try {
			request.getData().setClientAgentDTO(getUserAgentDetail());
			ServiceResponse<String> response = authService.logout(request,
					message);
			// Logging out from Keycloak once BSVE user logged out.
			if (request.getData().getAuthTicket()
					.indexOf(BSPOAuthUtils.THIRD_PARTY_TOKEN_IDENTIFIER) > 0) {
				ServiceResponse<String> bspLogoutResp = bspOAuthService
						.logoutBspUser(request.getData().getAuthTicket());
				if (bspLogoutResp != null) {
					response.setStatus(bspLogoutResp.getStatus());
				}
			}
			return Response.ok().entity(response).build();

		} catch (Exception e) {
			LOGGER.error("Unexpected error occurred trying to logout.", e);

			ServiceResponse<String> response = new ServiceResponse<String>();
			response.setStatus(ServiceResponse.ERROR);
			response.addMessage(MESSAGEBUNDLE
					.getMessage(MessageConstants.MSG_UNEXPECTED_ERROR));

			return Response.ok().entity(response).build();
		}
	}

	@POST
	@Path("/validate")
	@Produces(MediaType.APPLICATION_JSON)
	public Response isSessionActive(ServiceRequest<AuthSession> request) {

		LOGGER.trace("In logout()");

		try {
			return Response.ok().entity(authService.validate(request)).build();

		} catch (Exception e) {
			LOGGER.error(
					"Unexpected error occurred trying to check session status.",
					e);

			ServiceResponse<Boolean> response = new ServiceResponse<Boolean>();
			response.setStatus(ServiceResponse.ERROR);
			response.addMessage(MESSAGEBUNDLE
					.getMessage(MessageConstants.MSG_UNEXPECTED_ERROR));

			return Response.ok().entity(response).build();
		}
	}

	@POST
	@Path("/updatePasswordWithCurrentKeyCheck")
	@Produces(MediaType.APPLICATION_JSON)
	public Response updatePasswordWithCurrentKeyCheck(
			ServiceRequest<AuthCredentials> request,
			@Context HttpHeaders headers) {

		LOGGER.trace("In updatePasswordWithCurrentKeyCheck()");

		try {

			String originHost = null;
			List<String> requestOrigin = headers
					.getRequestHeader(BsveAuthConstants.HOST);
			if (null != requestOrigin && requestOrigin.size() > 0) {
				originHost = requestOrigin.get(0);
			}
			String authTicket = null;
			List<String> requestAuthTicket = headers
					.getRequestHeader(BsveAuthConstants.AUTH_TICKET);
			if (null != requestAuthTicket && requestAuthTicket.size() > 0) {
				authTicket = requestAuthTicket.get(0);
			}
			request.getData().setClientAgentDTO(getUserAgentDetail());
			ServiceResponse<String> response = authService
					.updatePasswordWithCurrentPasswordCheck(request,
							originHost, authTicket);

			return Response.ok().entity(response).build();

		} catch (Exception e) {
			LOGGER.error(
					"Unexpected error occurred trying to update password.", e);

			ServiceResponse<String> response = new ServiceResponse<String>();
			response.setStatus(ServiceResponse.ERROR);
			response.addMessage(MESSAGEBUNDLE
					.getMessage(MessageConstants.MSG_UNEXPECTED_ERROR));

			return Response.ok().entity(response).build();
		}
	}

	@POST
	@Path("/updatePassword")
	@Produces(MediaType.APPLICATION_JSON)
	public Response updatePassword(ServiceRequest<AuthCredentials> request) {

		LOGGER.trace("In updatePassword()");

		try {
			request.getData().setClientAgentDTO(getUserAgentDetail());
			ServiceResponse<String> response = authService
					.updatePassword(request);

			return Response.ok().entity(response).build();

		} catch (Exception e) {
			LOGGER.error(
					"Unexpected error occurred trying to update password.", e);

			ServiceResponse<String> response = new ServiceResponse<String>();
			response.setStatus(ServiceResponse.ERROR);
			response.addMessage(MESSAGEBUNDLE
					.getMessage(MessageConstants.MSG_UNEXPECTED_ERROR));

			return Response.ok().entity(response).build();
		}
	}

	@POST
	@Path("/updateSecurityQA")
	@Produces(MediaType.APPLICATION_JSON)
	public Response updateSecurityQuestionnaire(
			ServiceRequest<AuthCredentials> request,
			@Context HttpHeaders headers) {

		LOGGER.trace("In updateSecurityQuestionnaire()");

		try {
			String originHost = null;
			List<String> requestOrigin = headers
					.getRequestHeader(BsveAuthConstants.HOST);
			if (null != requestOrigin && requestOrigin.size() > 0) {
				originHost = requestOrigin.get(0);
			}
			String authTicket = null;
			List<String> requestAuthTicket = headers
					.getRequestHeader(BsveAuthConstants.AUTH_TICKET);
			if (null != requestAuthTicket && requestAuthTicket.size() > 0) {
				authTicket = requestAuthTicket.get(0);
			}
			request.getData().setClientAgentDTO(getUserAgentDetail());
			ServiceResponse<String> response = authService
					.updateSecurityQuestionnaire(request, originHost,
							authTicket);

			return Response.ok().entity(response).build();

		} catch (Exception e) {
			LOGGER.error(
					"Unexpected error occurred trying to update security questionnaire.",
					e);

			ServiceResponse<String> response = new ServiceResponse<String>();
			response.setStatus(ServiceResponse.ERROR);
			response.addMessage(MESSAGEBUNDLE
					.getMessage(MessageConstants.MSG_UNEXPECTED_ERROR));

			return Response.ok().entity(response).build();
		}
	}

	@POST
	@Path("/updatePasswordAndSecurityQA")
	@Produces(MediaType.APPLICATION_JSON)
	public Response updatePasswordAndSecurityQuestionnaire(
			ServiceRequest<AuthCredentials> request) {

		LOGGER.trace("In updatePasswordAndSecurityQuestionnaire()");

		try {
			ServiceResponse<String> response = authService
					.updatePasswordAndSecurityQuestionnaire(request);

			return Response.ok().entity(response).build();

		} catch (Exception e) {
			LOGGER.error(
					"Unexpected error occurred trying to update password and security questionnaire.",
					e);

			ServiceResponse<String> response = new ServiceResponse<String>();
			response.setStatus(ServiceResponse.ERROR);
			response.addMessage(MESSAGEBUNDLE
					.getMessage(MessageConstants.MSG_UNEXPECTED_ERROR));

			return Response.ok().entity(response).build();
		}
	}

	@POST
	@Path("/checkSecurityQuestionnaire")
	@Produces(MediaType.APPLICATION_JSON)
	public Response checkSecurityQuestionnaire(
			ServiceRequest<AuthCredentials> request,
			@Context HttpHeaders headers) {

		LOGGER.trace("In checkSecurityQuestionnaire ");

		try {

			String originHost = null;
			List<String> requestOrigin = headers
					.getRequestHeader(BsveAuthConstants.HOST);
			if (null != requestOrigin && requestOrigin.size() > 0) {
				originHost = requestOrigin.get(0);
			}
			request.getData().setClientAgentDTO(getUserAgentDetail());
			ServiceResponse<Boolean> response = authService
					.checkSecurityQuestionnaire(request, originHost);

			return Response.ok().entity(response).build();

		} catch (Exception e) {
			LOGGER.error(
					"Unexpected error occurred trying to verify security questionnaire.",
					e);

			ServiceResponse<Boolean> response = new ServiceResponse<Boolean>();
			response.setStatus(ServiceResponse.ERROR);
			response.addMessage(MESSAGEBUNDLE
					.getMessage(MessageConstants.MSG_UNEXPECTED_ERROR));

			return Response.ok().entity(response).build();
		}
	}

	@POST
	@Path("/activate")
	@Produces(MediaType.APPLICATION_JSON)
	public Response activate(ServiceRequest<AuthCredentials> request,
			@Context HttpHeaders headers) {

		LOGGER.trace("In activate()");

		try {

			String originHost = null;
			List<String> requestOrigin = headers
					.getRequestHeader(BsveAuthConstants.HOST);
			if (null != requestOrigin && requestOrigin.size() > 0) {
				originHost = requestOrigin.get(0);
			}
			String authTicket = null;
			List<String> requestAuthTicket = headers
					.getRequestHeader(BsveAuthConstants.AUTH_TICKET);
			if (null != requestAuthTicket && requestAuthTicket.size() > 0) {
				authTicket = requestAuthTicket.get(0);
			}
			request.getData().setClientAgentDTO(getUserAgentDetail());
			ServiceResponse<String> response = authService.activate(request,
					originHost, authTicket);

			return Response.ok().entity(response).build();

		} catch (Exception e) {
			LOGGER.error(
					"Unexpected error occurred trying to activate the user account.",
					e);

			ServiceResponse<String> response = new ServiceResponse<String>();
			response.setStatus(ServiceResponse.ERROR);
			response.addMessage(MESSAGEBUNDLE
					.getMessage(MessageConstants.MSG_UNEXPECTED_ERROR));

			return Response.ok().entity(response).build();
		}
	}

	@POST
	@Path("/deactivate")
	@Produces(MediaType.APPLICATION_JSON)
	public Response deactivate(ServiceRequest<AuthCredentials> request,
			@Context HttpHeaders headers) {

		LOGGER.trace("In deactivate()");

		try {

			String originHost = null;
			List<String> requestOrigin = headers
					.getRequestHeader(BsveAuthConstants.HOST);
			if (null != requestOrigin && requestOrigin.size() > 0) {
				originHost = requestOrigin.get(0);
			}
			String authTicket = null;
			List<String> requestAuthTicket = headers
					.getRequestHeader(BsveAuthConstants.AUTH_TICKET);
			if (null != requestAuthTicket && requestAuthTicket.size() > 0) {
				authTicket = requestAuthTicket.get(0);
			}
			request.getData().setClientAgentDTO(getUserAgentDetail());
			ServiceResponse<String> response = authService.deactivate(request,
					originHost, authTicket);

			return Response.ok().entity(response).build();

		} catch (Exception e) {
			LOGGER.error(
					"Unexpected error occurred trying to deactivate the user account.",
					e);

			ServiceResponse<String> response = new ServiceResponse<String>();
			response.setStatus(ServiceResponse.ERROR);
			response.addMessage(MESSAGEBUNDLE
					.getMessage(MessageConstants.MSG_UNEXPECTED_ERROR));

			return Response.ok().entity(response).build();
		}
	}

	@POST
	@Path("/unlock")
	@Produces(MediaType.APPLICATION_JSON)
	public Response unlock(ServiceRequest<AuthCredentials> request) {

		LOGGER.trace("In unlock()");

		try {
			ServiceResponse<String> response = authService.unlock(request);

			return Response.ok().entity(response).build();

		} catch (Exception e) {
			LOGGER.error(
					"Unexpected error occurred trying to unlock the user account.",
					e);

			ServiceResponse<String> response = new ServiceResponse<String>();
			response.setStatus(ServiceResponse.ERROR);
			response.addMessage(MESSAGEBUNDLE
					.getMessage(MessageConstants.MSG_UNEXPECTED_ERROR));

			return Response.ok().entity(response).build();
		}
	}

	@GET
	@Path("/getAPISecurityDetails/{userName}")
	@Produces(MediaType.APPLICATION_JSON)
	public Response getAPISecurityDetails(@PathParam(USER_NAME) String userName) {

		LOGGER.trace("In getAPISecurityDetails()");

		try {
			ServiceResponse<APIAccessCredentials> response = authService
					.getAPISecurityDetails(userName);
			if (response.getData() != null
					&& (StringUtils.isBlank(response.getData().getSecretKey()) || StringUtils
							.isBlank(response.getData().getAccessKey()))) {
				response = authService.generateAPISecurityDetails(userName);
			}
			response.setStatus(ServiceResponse.SUCCESS);
			return Response.ok().entity(response).build();

		} catch (Exception e) {
			LOGGER.error(
					"Unexpected error occurred trying to reset the user api credentials.",
					e);

			ServiceResponse<String> response = new ServiceResponse<String>();
			response.setStatus(ServiceResponse.ERROR);
			response.addMessage(MESSAGEBUNDLE
					.getMessage(MessageConstants.MSG_UNEXPECTED_ERROR));

			return Response.ok().entity(response).build();
		}
	}

	/**
	 * This service is used to get the System Attributes for the given source
	 * 
	 * @param source
	 * @return HashMap<String, HashMap<String, String>>
	 */

	@GET
	@Path("/generateAPISecurityDetails/{userName}")
	@Produces(MediaType.APPLICATION_JSON)
	public Response generateAPISecurityDetails(
			@PathParam(USER_NAME) String userName) {

		LOGGER.trace("In generateAPISecurityDetails()");

		try {
			ServiceResponse<APIAccessCredentials> response = authService
					.generateAPISecurityDetails(userName);
			response.setStatus(ServiceResponse.SUCCESS);
			return Response.ok().entity(response).build();

		} catch (Exception e) {
			LOGGER.error(
					"Unexpected error occurred trying to reset the user api credentials.",
					e);

			ServiceResponse<String> response = new ServiceResponse<String>();
			response.setStatus(ServiceResponse.ERROR);

			response.addMessage(MESSAGEBUNDLE
					.getMessage(MessageConstants.MSG_UNEXPECTED_ERROR));

			return Response.ok().entity(response).build();
		}
	}

	/**
	 * This Service is used to get UserAuthentication Details for the given user name.
	 * If the user exists in the system it will return the user details other wise it will return empty results
	 * 
	 * @param userName
	 * @return
	 */
	@GET
	@Path("/userAuthDetails/{userName}")
	@Produces(MediaType.APPLICATION_JSON)
	public Response getUserAuthDetails(@PathParam(USER_NAME) String userName) {
		LOGGER.trace("In getUserAuthDetails()");
		try {
			ServiceResponse<UserAuthenticationBO> response = authService
					.getAuthUserDetails(userName);
			return Response.ok().entity(response).build();
		} catch (Exception e) {
			LOGGER.error("Error in getting user details", e);
			ServiceResponse<UserAuthenticationBO> response = new ServiceResponse<UserAuthenticationBO>();
			response.setStatus(ServiceResponse.ERROR);
			response.addMessage(MESSAGEBUNDLE
					.getMessage(MessageConstants.MSG_UNEXPECTED_ERROR));
			return Response.ok().entity(response).build();
		}

	}

	/**
	 * This Service is use to save UserAuthentication Details
	 * 
	 * @param request
	 * @return
	 */
	@POST
	@Path("/save/userAuthDetails")
	@Produces(MediaType.APPLICATION_JSON)
	@Consumes(MediaType.APPLICATION_JSON)
	public Response saveuserAuthDetails(ServiceRequest<UserAuthenticationBO> request) {
		LOGGER.trace("In saveUserAuthEntry()");
		ServiceResponse<String> response = null;
		try {
			UserAuthenticationBO userAuthenticationBO = request.getData();
			response = authService.saveUserAuthEntry(userAuthenticationBO);
		} catch (Exception e) {
			LOGGER.error("Error in saving userAuthDetails ", e);
			response = new ServiceResponse<String>();
			response.setStatus(ServiceResponse.ERROR);
			response.addMessage(MESSAGEBUNDLE
					.getMessage(MessageConstants.MSG_UNEXPECTED_ERROR));

		}
		return Response.ok().entity(response).build();
	}

	/**
	 * This Service is use to update UserAuthentication Details
	 * 
	 * @param request
	 * @return
	 */
	@PUT
	@Path("/update/userAuthDetails")
	@Produces(MediaType.APPLICATION_JSON)
	@Consumes(MediaType.APPLICATION_JSON)
	public Response updateUserAuthDetails(
			ServiceRequest<UserAuthenticationBO> request) {
		LOGGER.trace("In update UserAuthentication()");
		ServiceResponse<String> response;
		try {
			UserAuthenticationBO userAuthenticationBO = request.getData();
			response = authService.updateAuthDetails(userAuthenticationBO);
		} catch (Exception e) {
			LOGGER.error("Error in update userAuthDetails", e);
			response = new ServiceResponse<String>();
			response.setStatus(ServiceResponse.ERROR);
			response.addMessage(MESSAGEBUNDLE
					.getMessage(MessageConstants.MSG_UNEXPECTED_ERROR));

		}
		return Response.ok().entity(response).build();

	}
}
