package com.exide.sfcrm.controller;

import java.util.List;

import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import com.exide.sfcrm.constants.ApplicationConstants;
import com.exide.sfcrm.constants.MessageConstants;

import com.exide.sfcrm.model.Vendor;
import com.exide.sfcrm.service.AuditLogService;
import com.exide.sfcrm.service.VendorService;
import com.exide.sfcrm.util.CommonUtil;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
/**
 * 
 * @author vasavivr
 *
 */
@Controller
public class VendorController {
	/**
	 * Logger.
	 */
	private static final Logger LOGGER = Logger
			.getLogger(VendorController.class);
	@Autowired
	VendorService vendorService;

	@Autowired
	private ObjectMapper objectMapper;

	@Autowired
	private AuditLogService activityLogService;

	@Autowired
	private CommonUtil commonUtil;

	/**
	 * This Service is used to get vendorList.
	 * @return
	 */
	@RequestMapping(value = { "/vendorList" }, method = RequestMethod.GET)
	@ResponseBody
	public String getAllUsers() {

		LOGGER.info("Inside Get all users method");

		String response = null;

		try {

			List<Vendor> vendor = vendorService.getVendorList();
			response = commonUtil.serviceResponse(
					MessageConstants.SUCCESS_RESPONSE,
					ApplicationConstants.TRUE, vendor);

			activityLogService.addActivity("Get All Vendor", "Success",
					"Get Vendor request completed successfully",
					vendor.toString(), commonUtil.getUserName());
		} catch (Exception e) {

			LOGGER.error("Error occured while getting vendor details " + e, e);
			try {
				response = commonUtil.serviceResponse(
						MessageConstants.EXCEPTION_RESPONSE,
						ApplicationConstants.FALSE, null);
			} catch (JsonProcessingException e1) {
				LOGGER.error(
						"Error occured while converting response object in catch block of get vendor details"
								+ e, e);
			}

			activityLogService.addActivity("Get All Vendor", "Failure",
					"Get Vendor request failed", "", commonUtil.getUserName());
		}

		return response;
	}

	/**
	 * This Service is used to create new vendor.
	 * @param vendor
	 * @return
	 */
	@RequestMapping(value = { "/createVendor" }, method = RequestMethod.POST)
	@ResponseBody
	public String addAllData(@RequestBody Vendor vendor) {
		LOGGER.info("Inside create user method");

		String response = null;

		try {

			Vendor code = vendorService.createVendor(vendor);

			if (null != code) {

				response = commonUtil.serviceResponse(
						MessageConstants.SUCCESS_RESPONSE,
						ApplicationConstants.TRUE, code);
			} else {

				response = commonUtil.serviceResponse(
						MessageConstants.ERROR_RESPONSE,
						ApplicationConstants.FALSE, null);
			}

		} catch (Exception e) {

			LOGGER.error("Error occured while creating vendor " + e, e);
			try {
				response = commonUtil.serviceResponse(
						MessageConstants.EXCEPTION_RESPONSE,
						ApplicationConstants.FALSE, null);
			} catch (JsonProcessingException e1) {
				LOGGER.error(
						"Error occured while converting response object in catch block of create vendor "
								+ e1, e1);
			}
		}

		return response;
	}
/**
 * This Service is used to edit vendor list.
 * @param vendor
 * @return
 */
	@RequestMapping(value = { "/editVendor" }, method = RequestMethod.PUT)
	@ResponseBody
	public String updateVendor(@RequestBody Vendor vendor) {
		LOGGER.info("Inside create user method");

		String response = null;

		try {

			Vendor code = vendorService.updateVendor(vendor);

			if (null != code) {

				response = commonUtil.serviceResponse(
						MessageConstants.SUCCESS_RESPONSE,
						ApplicationConstants.TRUE, code);
			} else {

				response = commonUtil.serviceResponse(
						MessageConstants.ERROR_RESPONSE,
						ApplicationConstants.FALSE, null);
			}

		} catch (Exception e) {

			LOGGER.error("Error occured while creating vendor " + e, e);
			try {
				response = commonUtil.serviceResponse(
						MessageConstants.EXCEPTION_RESPONSE,
						ApplicationConstants.FALSE, null);
			} catch (JsonProcessingException e1) {
				LOGGER.error(
						"Error occured while converting response object in catch block of create vendor "
								+ e1, e1);
			}
		}

		return response;
	}
}
