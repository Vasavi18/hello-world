package com.exide.sfcrm.controller;

import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import com.exide.sfcrm.config.SmtpConfig;
import com.exide.sfcrm.constants.ApplicationConstants;
import com.exide.sfcrm.constants.MessageConstants;
import com.exide.sfcrm.constants.PropertyConstants;
import com.exide.sfcrm.model.ContestEditView;
import com.exide.sfcrm.model.ContestMaster;
import com.exide.sfcrm.model.ContestView;
import com.exide.sfcrm.model.ContestsDrpView;
import com.exide.sfcrm.model.LastUpdateView;
import com.exide.sfcrm.model.User;
import com.exide.sfcrm.pojo.ContestEditForm;
import com.exide.sfcrm.pojo.ContestRequestForm;
import com.exide.sfcrm.service.AuditLogService;
import com.exide.sfcrm.service.ContestMasterService;
import com.exide.sfcrm.util.CommonUtil;
import com.exide.sfcrm.util.JSONUtils;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * 
 * @author vasavivr
 *
 */

@Controller
public class ContestMasterController {

	@Autowired
	ContestMasterService contestMasterService;

	@Autowired
	ObjectMapper objectMapper;

	@Autowired
	PropertyConstants propertyConstants;

	@Autowired
	private AuditLogService activityLogService;

	@Autowired
	private CommonUtil commonUtil;

	@Autowired
	private SmtpConfig smtpConfig;

	@Autowired
	private JSONUtils jsonUtils;

	@Autowired
	private UserManagementController userManagementController;
	/**
	 * Logger.
	 */
	private static final Logger LOGGER = Logger
			.getLogger(ContestMasterController.class);

	/**
	 * This Service is used to get the ChannelList.
	 * 
	 * @param pageNumber
	 * @return
	 */
	@RequestMapping(value = { "/channelList" }, method = RequestMethod.GET)
	@ResponseBody
	public String getAdvancePayList(
			@RequestParam(value = "pageNumber") int pageNumber) {

		String response = null;
		try {
			String userName = commonUtil.getLoggedInUser().getUserName();
			Map<String, Object> data = contestMasterService.getChannelList(
					true, userName, commonUtil.getOffset(pageNumber),
					propertyConstants.PAGE_LIMIT);

			response = commonUtil.serviceResponse(
					MessageConstants.SUCCESS_RESPONSE,
					ApplicationConstants.TRUE, data);
			activityLogService.addActivity("Get  channel  list", "Success",
					"Get channel list request completed successfully",
					data.toString(), commonUtil.getUserName());
		} catch (Exception e) {
			LOGGER.error("Error occured while getting channel list details "
					+ e, e);

			try {
				response = commonUtil.serviceResponse(
						MessageConstants.EXCEPTION_RESPONSE,
						ApplicationConstants.FALSE, null);
			} catch (JsonProcessingException e1) {
				LOGGER.error(
						"Error occured while converting response object in catch block of get channel list details"
								+ e1, e1);
				activityLogService
						.addActivity(
								"get channel list details",
								"Success",
								"Get channel list details request completed successfully",
								"", commonUtil.getUserName());
			}
		}
		return response;

	}

	/**
	 * This Service is used to add the new Contest.
	 * 
	 * @param json
	 * @return
	 */

	@RequestMapping(value = { "/addContest" }, method = RequestMethod.PUT)
	@ResponseBody
	public String addContest(@RequestBody List<ContestRequestForm> json) {

		String response = null;
		try {
			String userName = commonUtil.getLoggedInUser().getUserName();

			ContestRequestForm contestRequestForm = json.get(0);
			contestMasterService.addContest(contestRequestForm, userName);
			List<User> user = userManagementController
					.getUser(jsonUtils.ADMINISTRATOR);
			smtpConfig.sendMailtoGroup(user,
					propertyConstants.MAIL_CONTEST_CREATION,
					propertyConstants.MAIL_CONTEST_CREATION);
			response = commonUtil.serviceResponse(
					MessageConstants.SUCCESS_RESPONSE,
					ApplicationConstants.TRUE, "");
			activityLogService.addActivity("Get contest list", "Success",
					"Get contest list request completed successfully",
					"Contest Added", commonUtil.getUserName());

		} catch (Exception e) {
			LOGGER.error("Error occured while getting contest list details "
					+ e, e);

			try {
				response = commonUtil.serviceResponse(
						MessageConstants.EXCEPTION_RESPONSE,
						ApplicationConstants.FALSE, null);
			} catch (JsonProcessingException e1) {
				LOGGER.error(
						"Error occured while converting response object in catch block of get contest list details"
								+ e1, e1);
				activityLogService
						.addActivity(
								"get contest list details",
								"Success",
								"Get contest list details request completed successfully",
								"", commonUtil.getUserName());
			}
		}
		return response;
	}

	/**
	 * This Service is used to get all Contests.
	 * 
	 * @return
	 */
	@RequestMapping(value = { "/allContests" }, method = RequestMethod.GET)
	@ResponseBody
	public String getAllContests() {

		String response = null;
		try {

			List<ContestView> contests = contestMasterService.getAllContests();
			response = commonUtil.serviceResponse(MessageConstants.SUCCESS,
					ApplicationConstants.TRUE, contests);
			activityLogService.addActivity("Get contests details", "Success",
					"Get contests details request completed successfully",
					contests.toString(), commonUtil.getUserName());
		} catch (Exception e) {
			LOGGER.error("Error occured while getting contests list  details "
					+ e, e);

			try {
				response = commonUtil.serviceResponse(
						MessageConstants.EXCEPTION_RESPONSE,
						ApplicationConstants.FALSE, null);
			} catch (JsonProcessingException e1) {
				LOGGER.error(
						"Error occured while converting response object in catch block of get contests list details"
								+ e1, e1);
				activityLogService.addActivity("get contests list details",
						"Success",
						"Get contests details request completed successfully",
						"", commonUtil.getUserName());
			}
		}
		return response;

	}

	/**
	 * This Service is used to get all the contests for the dropdown.
	 * 
	 * @return
	 */

	@RequestMapping(value = { "/allContestsDrp" }, method = RequestMethod.GET)
	@ResponseBody
	public String getAllContestsDrp() {

		String response = null;
		try {

			List<ContestsDrpView> contestsdrp = contestMasterService
					.getAllContestsDrp();
			response = commonUtil.serviceResponse(MessageConstants.SUCCESS,
					ApplicationConstants.TRUE, contestsdrp);
			activityLogService.addActivity("Get contests details", "Success",
					"Get contests details request completed successfully",
					contestsdrp.toString(), commonUtil.getUserName());
		} catch (Exception e) {
			LOGGER.error("Error occured while getting contests list  details "
					+ e, e);

			try {
				response = commonUtil.serviceResponse(
						MessageConstants.EXCEPTION_RESPONSE,
						ApplicationConstants.FALSE, null);
			} catch (JsonProcessingException e1) {
				LOGGER.error(
						"Error occured while converting response object in catch block of get contests list details"
								+ e1, e1);
				activityLogService.addActivity("get contests list details",
						"Success",
						"Get contests details request completed successfully",
						"", commonUtil.getUserName());
			}
		}
		return response;

	}

	/**
	 * This Service is used to filter Contests list basd on the searchValue.
	 * 
	 * @param searchvalue
	 * @return
	 */
	@RequestMapping(value = { "/filterContests" }, method = RequestMethod.GET)
	@ResponseBody
	public String getFilteredContests(
			@RequestParam(value = "searchValue") String searchvalue) {

		String response = null;

		try {
			String userName = commonUtil.getLoggedInUser().getUserName();
			List<ContestsDrpView> contestsdrp = contestMasterService
					.getFilteredContests(userName, searchvalue);
			response = commonUtil.serviceResponse(MessageConstants.SUCCESS,
					ApplicationConstants.TRUE, contestsdrp);
			activityLogService.addActivity("Get contests details", "Success",
					"Get contests details request completed successfully",
					contestsdrp.toString(), commonUtil.getUserName());
		} catch (Exception e) {
			LOGGER.error("Error occured while getting contests list  details "
					+ e, e);

			try {
				response = commonUtil.serviceResponse(
						MessageConstants.EXCEPTION_RESPONSE,
						ApplicationConstants.FALSE, null);
			} catch (JsonProcessingException e1) {
				LOGGER.error(
						"Error occured while converting response object in catch block of get contests list details"
								+ e1, e1);
				activityLogService.addActivity("get contests list details",
						"Success",
						"Get contests details request completed successfully",
						"", commonUtil.getUserName());
			}
		}
		return response;

	}

	/**
	 * This Service returns the last updated date.
	 * 
	 * @return
	 */
	@RequestMapping(value = { "/lastUpdateDate" }, method = RequestMethod.GET)
	@ResponseBody
	public String getlastUpdateDate() {

		String response = null;
		try {

			List<LastUpdateView> lastUpdateDate = contestMasterService
					.getlastUpdateDate();
			response = commonUtil.serviceResponse(MessageConstants.SUCCESS,
					ApplicationConstants.TRUE, lastUpdateDate);
			activityLogService.addActivity("Get contests details", "Success",
					"Get contests details request completed successfully",
					lastUpdateDate.toString(), commonUtil.getUserName());
		} catch (Exception e) {
			LOGGER.error("Error occured while getting contests list  details "
					+ e, e);

			try {
				response = commonUtil.serviceResponse(
						MessageConstants.EXCEPTION_RESPONSE,
						ApplicationConstants.FALSE, null);
			} catch (JsonProcessingException e1) {
				LOGGER.error(
						"Error occured while converting response object in catch block of get contests list details"
								+ e1, e1);
				activityLogService.addActivity("get contests list details",
						"Success",
						"Get contests details request completed successfully",
						"", commonUtil.getUserName());
			}
		}
		return response;

	}

	/**
	 * This Service is used to get all Contests.
	 * 
	 * @return
	 */
	@RequestMapping(value = { "/editContestList" }, method = RequestMethod.GET)
	@ResponseBody
	public String editContestList(@RequestParam("contestId") Integer contestId) {

		String response = null;
		try {

			List<ContestEditView> contests = contestMasterService
					.getEditContestList(contestId);
			response = commonUtil.serviceResponse(MessageConstants.SUCCESS,
					ApplicationConstants.TRUE, contests);
			activityLogService.addActivity("Get edit contests details",
					"Success",
					"Get edit contests details request completed successfully",
					contests.toString(), commonUtil.getUserName());
		} catch (Exception e) {
			LOGGER.error(
					"Error occured while getting edit contests list  details "
							+ e, e);

			try {
				response = commonUtil.serviceResponse(
						MessageConstants.EXCEPTION_RESPONSE,
						ApplicationConstants.FALSE, null);
			} catch (JsonProcessingException e1) {
				LOGGER.error(
						"Error occured while converting response object in catch block of get edit contests list details"
								+ e1, e1);
				activityLogService
						.addActivity(
								"get edit contests list details",
								"Success",
								"Get edit contests details request completed successfully",
								"", commonUtil.getUserName());
			}
		}
		return response;

	}

	@RequestMapping(value = { "/getContest" }, method = RequestMethod.GET)
	@ResponseBody
	public String getContests(@RequestParam("contestId") Integer contestId) {

		String response = null;
		try {
			String userName = commonUtil.getLoggedInUser().getUserName();
			Map<String, Object> contestMasters = contestMasterService
					.getContest(contestId, userName);
			response = commonUtil.serviceResponse(
					MessageConstants.SUCCESS_RESPONSE,
					ApplicationConstants.TRUE, contestMasters);
			activityLogService.addActivity("Get contest list", "Success",
					"Get contest list request completed successfully",
					"Contest Added", commonUtil.getUserName());

		} catch (Exception e) {
			LOGGER.error("Error occured while getting contest list details "
					+ e, e);

			try {
				response = commonUtil.serviceResponse(
						MessageConstants.EXCEPTION_RESPONSE,
						ApplicationConstants.FALSE, null);
			} catch (JsonProcessingException e1) {
				LOGGER.error(
						"Error occured while converting response object in catch block of get contest list details"
								+ e1, e1);
				activityLogService
						.addActivity(
								"get contest list details",
								"Success",
								"Get contest list details request completed successfully",
								"", commonUtil.getUserName());
			}
		}
		return response;
	}
/**
 * This Service is used to EditContest Details.
 * @param json
 * @return
 */
	@RequestMapping(value = { "/editContest" }, method = RequestMethod.PUT)
	@ResponseBody
	public String editContest(@RequestBody List<ContestEditForm> json) {

		String response = null;
		try {
			String userName = commonUtil.getLoggedInUser().getUserName();

			ContestEditForm contestEditForm = json.get(0);
			contestMasterService.editContest(contestEditForm,userName);
			response = commonUtil.serviceResponse(
					MessageConstants.SUCCESS_RESPONSE,
					ApplicationConstants.TRUE, "");
			activityLogService.addActivity("Get contest list", "Success",
					"Get contest list request completed successfully",
					"Contest Added", commonUtil.getUserName());

		} catch (Exception e) {
			LOGGER.error("Error occured while getting contest list details "
					+ e, e);

			try {
				response = commonUtil.serviceResponse(
						MessageConstants.EXCEPTION_RESPONSE,
						ApplicationConstants.FALSE, null);
			} catch (JsonProcessingException e1) {
				LOGGER.error(
						"Error occured while converting response object in catch block of get contest list details"
								+ e1, e1);
				activityLogService
						.addActivity(
								"get contest list details",
								"Success",
								"Get contest list details request completed successfully",
								"", commonUtil.getUserName());
			}
		}
		return response;
	}

}
