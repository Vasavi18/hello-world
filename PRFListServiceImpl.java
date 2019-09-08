/**
 * 
 */
package com.exide.sfcrm.service.impl;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigDecimal;
import java.net.HttpURLConnection;
import java.net.URL;
import java.sql.Date;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.exide.sfcrm.constants.ApplicationConstants;
import com.exide.sfcrm.constants.PropertyConstants;
import com.exide.sfcrm.dao.PRFListDao;
import com.exide.sfcrm.model.PRFListCashAdvanceView;
import com.exide.sfcrm.model.PRFListCashView;
import com.exide.sfcrm.model.PrfCashDetailsView;
import com.exide.sfcrm.model.PrfCashSummaryView;
import com.exide.sfcrm.model.PrfListTicketView;
import com.exide.sfcrm.model.TblPRFGeneratedCashView;
import com.exide.sfcrm.model.TblPRFGeneratedTicketView;
import com.exide.sfcrm.model.TblPrfGeneratedPrintView;
import com.exide.sfcrm.repository.AgentListRepository;
import com.exide.sfcrm.repository.PRFListCashAdvanceRepository;
import com.exide.sfcrm.repository.PRFListCashRepository;
import com.exide.sfcrm.repository.PrfCashDetailsRepository;
import com.exide.sfcrm.repository.PrfCashSummaryRepository;
import com.exide.sfcrm.repository.PrfListTicketRepository;
import com.exide.sfcrm.repository.TblPRFGeneartedTicketsRepository;
import com.exide.sfcrm.repository.TblPRFGeneratedCashViewRepository;
import com.exide.sfcrm.repository.TblPRFGeneratedPrintRepository;
import com.exide.sfcrm.repository.TblPRFGeneratedTicketViewRepository;
import com.exide.sfcrm.repository.TblPRFGenratedCashRepository;
import com.exide.sfcrm.repository.TblTransactionCashRepository;
import com.exide.sfcrm.service.PRFListService;
import com.exide.sfcrm.util.CommonUtil;
import com.exide.sfcrm.util.DateUtils;

/**
 * @author neethub
 *
 */
@Service
public class PRFListServiceImpl implements PRFListService {

	@Autowired
	private PRFListCashRepository prfListCashRepository;

	@Autowired
	private PRFListCashAdvanceRepository prfListCashAdvanceRepository;

	@Autowired
	private PrfListTicketRepository prfListTicketRepository;

	@Autowired
	private TblPRFGeneartedTicketsRepository tblPRFGeneartedTicketsRepository;

	@Autowired
	private TblPRFGeneratedTicketViewRepository tblPRFGeneratedTicketViewRepository;

	@Autowired
	private TblPRFGeneratedCashViewRepository tblPRFGeneratedCashViewRepository;

	@Autowired
	private PRFListDao prfListDao;

	@Autowired
	private TblTransactionCashRepository tblTransactionCashRepository;

	@Autowired
	private AgentListRepository agentListRepository;

	@Autowired
	private CommonUtil commonUtil;

	@Autowired
	private TblPRFGenratedCashRepository tblPRFGenratedCashRepository;

	@Autowired
	private TblPRFGeneratedPrintRepository tblPRFGeneratedPrintRepository;

	@Autowired
	private PropertyConstants propertyConstants;

	@Autowired
	private ApplicationConstants applicationConstants;

	@Autowired
	private PrfCashSummaryRepository prfCashSummaryRepository;
	

	@Autowired
	private PrfCashDetailsRepository prfCashDetailsRepository;

	@Override
	public List<PRFListCashView> getPRFListCash(String agentTypes,
			String userId, int offset, int limit, String sessionId) {
		Set<PRFListCashView> cashList = new HashSet<PRFListCashView>();
		String[] agentTypeArray = agentTypes.split(",");
		prfListCashRepository.deleteTmptblPRFListCashAll(userId);
		for (String agType : agentTypeArray) {
			BigDecimal id = getAgentTypeId(agType);
			List<PRFListCashView> tempList = prfListCashRepository
					.getPRFListCash(userId, Integer.parseInt(id.toString()));
			if (tempList != null && !tempList.isEmpty()) {
				deleteTempTables(userId, id);
				insertTmpPFRCashData(tempList, sessionId, userId);
				cashList.addAll(tempList);
			}
		}
		List<PRFListCashView> list = convertSetToList(cashList);
		return list;
	}

	private List<PRFListCashView> convertSetToList(Set<PRFListCashView> cashList) {
		List<PRFListCashView> list = new ArrayList<PRFListCashView>();
		for (PRFListCashView prfListCashView : cashList) {
			list.add(prfListCashView);
		}
		return list;
	}

	@Override
	public BigDecimal getAgentTypeId(String agentTypeName) {
		return prfListCashRepository.getAgentTypeId(agentTypeName);
	}

	@Override
	public List<PRFListCashAdvanceView> getPRFListCashAdvance(String userId) {
		return prfListCashAdvanceRepository.getPRFListCashAdvance(userId);
	}

	@Override
	public void insertTmpPFRCashData(List<PRFListCashView> prfCashList,
			String sessionId, String userId) {
		prfListDao.insertTmpPFRCashData(prfCashList, sessionId, userId);
	}

	@Override
	public Integer getprfNoGen() {
		return prfListCashRepository.getprfNoGenREF();
	}

	@Override
	public String getPrfPreText() {
		return prfListCashRepository.getprfPreText();
	}

	@Override
	public String getPrfNo(String agType, Integer prfGenRef) {

		String prfpretext = getPrfPreText();
		String formatted = String.format("%04d", prfGenRef);
		String AGTYPE = null;
		if (agType != null) {
			AGTYPE = agType;
		} else {
			AGTYPE = ApplicationConstants.DEFAULT_AGENT_TYPE;
		}
		Calendar now = Calendar.getInstance();
		int year = now.get(Calendar.YEAR);
		StringBuilder sb = new StringBuilder();
		sb.append(prfpretext).append(AGTYPE).append("/").append(year)
				.append("/").append(formatted);
		return sb.toString();

	}

	@Override
	public List<Double> getNetPayout(String flag, String userId,
			String sessionId, Integer agentTypeId) {
		if (flag.equals("positive")) {
			return prfListCashRepository.getNetPayoutForPositiveTransaction(
					userId, sessionId, agentTypeId);
		} else if (flag.equals("negative")) {
			return prfListCashRepository.getNetPayoutForNegativeTransaction(
					userId, sessionId, agentTypeId);
		} else {
			return prfListCashRepository
					.getNetPayoutForPositiveTransactionType9(userId, sessionId,
							agentTypeId);
		}
	}

	public Double getPrfAmount(String flag, String userId, String sessionId,
			Integer agentTypeId) {
		List<Double> netpayout = getNetPayout(flag, userId, sessionId,
				agentTypeId);
		Double sum = 0.0;
		for (Double netPay : netpayout) {
			sum += netPay;
		}
		if (flag.equals("positive") || flag.equals("")) {
			return sum;
		} else if (flag.equals("negative")) {
			return -1 * sum;
		} else {
			return sum;
		}

	}

	@Override
	public List<String> getAgentTypes() {
		List<String> agentTypes = prfListCashRepository.getAgentTypes();
		return agentTypes;
	}

	@Override
	public void generatePRF(Map<String, Object> json, String userId,
			String sessionId) {

		String[] agentTypeArray = json.get("agentTypes").toString().split(",");
		List<Map<String, Object>> recordMap = (List<Map<String, Object>>) json
				.get("selectedRecords");
		/*
		 * for (Map<String, Object> map : recordMap) { String agentNo = (String)
		 * map.get("agentNo"); String comment = (String) map.get("prfComment");
		 * Integer agentId = (Integer) map.get("agId"); Integer transAutoId =
		 * (Integer) map.get("transAutoId");
		 * //markSelectedRecordTblTransactionCash(transAutoId, userId,
		 * sessionId);
		 */
		callSP(userId, agentTypeArray, sessionId);

		/* } */
	}

	private void markSelectedRecordTblTransactionCash(Integer transAutoId,
			String userId, String sessionId) {
		prfListCashRepository
				.updateTblTransactionCashForSelectedRecord(transAutoId);
		prfListCashRepository.updatetmptblPRFListCashSelectRecord(transAutoId,
				userId, sessionId);
	}

	private void markUnSelectRecordTblTransactionCash(Integer transAutoId) {
		prfListCashRepository
				.updateTblTransactionCashForUnSelectRecord(transAutoId);
	}

	private void markUnSelectedRecordtblPrfListCash(Integer transAutoId) {
		prfListCashRepository
				.updatetmptblPRFListCashUnSelectRecord(transAutoId);
	}

	private void callPrfRecoverableCash(String userId, String agentType,
			String prfNumber, String prfGenRef, String prfComment,
			Float prfAmount, String sessionId) {
		prfListCashRepository.executePrfRecoverbleCash(userId, agentType,
				prfNumber, String.valueOf(prfGenRef), prfComment,
				prfAmount.floatValue(), sessionId);
	}

	@Override
	public void deleteTempTables(String userId, BigDecimal id) {
		prfListCashRepository.deleteTmptblPRFListCash(userId, id);
		// prfListCashRepository.deleteTbltmpPRFGenSupportTbl();

	}

	private void callSP(String userId, String[] agentTypeArray, String sessionId) {
		if (agentTypeArray != null && agentTypeArray.length > 0) {

			for (String agentType : agentTypeArray) {
				Integer prfGenRef = getprfNoGen();
				Double prfAmount = 0.0;
				String pfrNumber = getPrfNo(agentType, prfGenRef);
				Integer agentTypeId = getAgentTypeId(agentType).intValue();
				if (agentTypeId != 9) {
					if (prfListCashRepository.getCountOfPositiveNetAmount(
							userId, sessionId, agentTypeId) > 0) {
						prfAmount = getPrfAmount("positive", userId, sessionId,
								agentTypeId);
						prfListCashRepository.executePrfCompleteCashPositive(
								pfrNumber, String.valueOf(prfGenRef), "",
								agentType, prfAmount.floatValue(), userId,
								sessionId);
						callPrfRecoverableCash(userId, agentType, pfrNumber,
								String.valueOf(prfGenRef), "",
								prfAmount.floatValue(), sessionId);
						prfListCashRepository
								.updateTblPrfGeneratedCash(agentListRepository
										.getCidFromAgType(agentType), userId,
										sessionId);
						// markUnSelectRecordTblTransactionCash(transAutoId);
					} else if (prfListCashRepository
							.getCountOfNegativeNetAmount(userId, sessionId,
									agentTypeId) > 0) {
						prfAmount = getPrfAmount("negative", userId, sessionId,
								agentTypeId);
						prfListCashRepository.executePrfCompleteCashNegative(
								userId, agentType, pfrNumber,
								String.valueOf(prfGenRef), "",
								prfAmount.floatValue(), sessionId);
						callPrfRecoverableCash(userId, agentType, pfrNumber,
								String.valueOf(prfGenRef), "",
								prfAmount.floatValue(), sessionId);
						// markUnSelectRecordTblTransactionCash(transAutoId);
					}
				} else if (agentTypeId == 9) {
					prfAmount = getPrfAmount("", userId, sessionId, agentTypeId);
					prfListCashRepository.executeAdvancePaymentCash(pfrNumber,
							String.valueOf(prfGenRef), "",
							prfAmount.floatValue(), userId, sessionId,
							agentType);
					Integer cid = agentListRepository
							.getCidFromAgType(agentType);
					prfListCashRepository.executePRFTypeAdvance(pfrNumber,
							String.valueOf(prfGenRef), "",
							String.valueOf(agentType), cid,
							prfAmount.floatValue(), userId, sessionId);
					// markUnSelectedRecordtblPrfListCash(transAutoId);
				}
				deleteTempTables(userId, new BigDecimal(agentTypeId));
			}
		}
	}

	@Override
	public void generatePRFTicket(Map<String, Object> json, String userId,
			String sessionId) {

		String[] agentTypeArray = json.get("agentTypes").toString().split(",");
		for (String agentType : agentTypeArray) {
			prfListTicketRepository.generatePrfForTickets(agentType, userId,
					sessionId);
		}

	}

	@Override
	public List<PrfListTicketView> getPRFListTicket(String agentTypes,
			String userId, int offset, int limit, String sessionId) {
		List<PrfListTicketView> listAll = new ArrayList<PrfListTicketView>();
		String[] agentTypeArray = agentTypes.split(",");
		prfListTicketRepository.deleteAlltmptblPRFListTicket(userId);
		for (String agType : agentTypeArray) {
			BigDecimal id = getAgentTypeId(agType);
			List<PrfListTicketView> list = prfListTicketRepository
					.getPRFListTicket(userId, Integer.parseInt(id.toString()),
							sessionId);
			if (list != null && !list.isEmpty()) {
				listAll.addAll(list);
			}
		}
		return listAll;
	}

	@Override
	public List<TblPrfGeneratedPrintView> getPrfPrintList(String prfGENDate,
			String uid) {
		Integer id = getCid(uid);
		String prfGENDates = prfGENDate.replace("/", "");
		List<TblPrfGeneratedPrintView> prfListByprfgenDate = tblPRFGeneratedPrintRepository
				.findByPrfGENDate(Integer.valueOf(prfGENDates), id);

		return prfListByprfgenDate;
	}

	private Integer getCid(String uid) {

		return tblPRFGeneratedCashViewRepository.findByCid(uid);
	}

	@Override
	public List<TblPrfGeneratedPrintView> getPrfPrintListByNo(String prfNo,
			String uid) {
		Integer id = getCid(uid);

		List<TblPrfGeneratedPrintView> prfListByprfgenNo = tblPRFGeneratedPrintRepository
				.findByPrfNo(prfNo, id);

		return prfListByprfgenNo;
	}

	@Override
	public List<TblPrfGeneratedPrintView> getPrfPrintListByDate(
			String startDate, String endDate, String uid) {
		String startDates = startDate.replace("/", "");
		String endDates = endDate.replace("/", "");
		Integer id = getCid(uid);
		List<TblPrfGeneratedPrintView> prfListByDate = tblPRFGeneratedPrintRepository
				.findByDate(Integer.valueOf(startDates),
						Integer.valueOf(endDates), id);
		return prfListByDate;
	}

	@Override
	public Integer updateUtrNo(List<Map<String, String>> json)
			throws ParseException {
		Integer response = 0;
		String agentNo = null;
		String prfNoGenREF = null;
		String utrNo = null;
		String transferDate = null;
		for (Map<String, String> rows : json) {
			agentNo = rows.get("agentNo");
			prfNoGenREF = rows.get("prfNoGenREF");
			utrNo = rows.get("utrNo");
			transferDate = rows.get("transferDate");
			String dates = getDateFormats(transferDate);
			response = tblPRFGenratedCashRepository.updateUtrNo(utrNo,
					Date.valueOf(dates), Integer.valueOf(prfNoGenREF), agentNo);

		}
		return response;
	}

	@Override
	public List<String> getPrfPrintListGenerated() {
		List<String> prfList = tblPRFGenratedCashRepository.findByprfNo();
		return prfList;
	}

	@Override
	public List<String> getPrfTicketListGenerated() {
		List<String> prfList = tblPRFGeneartedTicketsRepository.findByprfNo();
		return prfList;
	}

	@Override
	public List<TblPRFGeneratedTicketView> getPrfTicketPrintList(
			String prfGENDate, String uid) {
		Integer id = getCid(uid);
		String prfGENDates = prfGENDate.replace("/", "");
		List<TblPRFGeneratedTicketView> prfListByprfTicketgenDate = tblPRFGeneratedTicketViewRepository
				.findByPrfGENDate(Integer.valueOf(prfGENDates), id);
		return prfListByprfTicketgenDate;
	}

	@Override
	public List<TblPRFGeneratedTicketView> getPrfTicketPrintListByNo(
			String prfNo, String uid) {
		Integer id = getCid(uid);
		List<TblPRFGeneratedTicketView> prfListByprfgenNo = tblPRFGeneratedTicketViewRepository
				.findByPrfNo(prfNo, id);
		return prfListByprfgenNo;
	}

	@Override
	public List<TblPRFGeneratedTicketView> getPrfTicketPrintListByDate(
			String startDate, String endDate, String uid) {
		String startDates = startDate.replace("/", "");
		String endDates = endDate.replace("/", "");
		Integer id = getCid(uid);
		List<TblPRFGeneratedTicketView> prfListByDate = tblPRFGeneratedTicketViewRepository
				.findByDate(Integer.valueOf(startDates),
						Integer.valueOf(endDates), id);
		return prfListByDate;
	}

	@Override
	public List<TblPRFGeneratedCashView> getUtrListByNo(String prfNo, String uid) {
		{
			Integer id = getCid(uid);

			List<TblPRFGeneratedCashView> utrList = tblPRFGeneratedCashViewRepository
					.findByPrfNo(prfNo, id);
			return utrList;
		}

	}

	@Override
	public void unSelectPrfCashListByNetAmount(String userName,
			String sessionId, Float minVal, Float maxVal) {
		prfListCashRepository.updateByAmountTmptblPRFListCashSelection(
				userName, sessionId, minVal, maxVal);
	}

	@Override
	public void updateAllPrfCashListSelection(String userName,
			String sessionId, String selectRecord) {
		prfListCashRepository.updateAlltmptblPRFListCashSelection(selectRecord,
				userName, sessionId);

	}

	@Override
	public void updateByIdPrfCashListSelection(String selectRecord,
			String userName, String sessionId, Integer selectId) {
		prfListCashRepository.updateByIdtmptblPRFListCashSelection(
				selectRecord, selectId, userName, sessionId);
	}

	@Override
	public void updateAllPrfTicketListSelection(String userName,
			String sessionId, String selectRecord) {
		prfListTicketRepository.updateAlltmptblPRFListTicketSelection(
				selectRecord, userName, sessionId);

	}

	@Override
	public void updateByIdPrfTicketListSelection(String selectRecord,
			String userName, String sessionId, Integer selectId) {
		prfListTicketRepository.updateByIdtmptblPRFListTicketSelection(
				selectRecord, selectId, userName, sessionId);
	}

	@Override
	public void rejectPrfTicket(List<Map<String, String>> json, String userId) {

		String agentType = null;
		String agentNo = null;

		for (Map<String, String> rows : json) {
			agentType = rows.get("agentType");
			agentNo = rows.get("agentNo");
			prfListTicketRepository.rejectPrfTickets(
					Integer.valueOf(agentType), userId, agentNo);

		}

	}

	@Override
	public void rejectPrfCash(List<Map<String, String>> json, String userId) {

		String agentNo = null;
		String agentType = null;

		for (Map<String, String> rows : json) {
			agentNo = rows.get("agentNo");
			agentType = rows.get("agentType");
			prfListCashRepository.rejectPrfCash(agentNo,
					Integer.valueOf(agentType), userId);
		}

	}

	@Override
	public byte[] downloadFile(String fileURL) throws IOException {
		URL url = new URL(fileURL);
		HttpURLConnection httpConn = (HttpURLConnection) url.openConnection();
		int responseCode = httpConn.getResponseCode();
		// always check HTTP response code first
		if (responseCode == HttpURLConnection.HTTP_OK) {
			String fileName = "";
			String disposition = httpConn.getHeaderField("Content-Disposition");

			if (disposition != null) {
				// extracts file name from header field
				int index = disposition.indexOf("filename=");
				if (index > 0) {
					fileName = disposition.substring(index + 10,
							disposition.length() - 1);
				}
			} else {
				// extracts file name from URL
				fileName = fileURL.substring(fileURL.lastIndexOf("/") + 1,
						fileURL.length());
			}

			// opens input stream from the HTTP connection
			InputStream inputStream = httpConn.getInputStream();

			byte[] out = DateUtils.toByteArray(inputStream);
			inputStream.close();
			System.out.println("File Served as Byte Array");
			httpConn.disconnect();
			return out;
		} else {
			System.out
					.println("No file to download. Server replied HTTP code: "
							+ responseCode);
		}
		httpConn.disconnect();
		return null;
	}

	@Override
	public byte[] downloadFileTicket(String fileURL) throws IOException {
 		URL url = new URL(fileURL);
		HttpURLConnection httpConn = (HttpURLConnection) url.openConnection();
		int responseCode = httpConn.getResponseCode();
		// always check HTTP response code first
		if (responseCode == HttpURLConnection.HTTP_OK) {
			String fileName = "";
			String disposition = httpConn.getHeaderField("Content-Disposition");

			if (disposition != null) {
				// extracts file name from header field
				int index = disposition.indexOf("filename=");
				if (index > 0) {
					fileName = disposition.substring(index + 10,
							disposition.length() - 1);
				}
			} else {
				// extracts file name from URL
				fileName = fileURL.substring(fileURL.lastIndexOf("/") + 1,
						fileURL.length());
			}

			// opens input stream from the HTTP connection
			InputStream inputStream = httpConn.getInputStream();

			byte[] out = DateUtils.toByteArray(inputStream);
			inputStream.close();
			System.out.println("File Served as Byte Array");
			httpConn.disconnect();
			return out;
		} else {
			System.out
					.println("No file to download. Server replied HTTP code: "
							+ responseCode);
		}
		httpConn.disconnect();
		return null;
	}

	public String getDateFormats(String str_date) throws ParseException {
		java.util.Date date1 = new SimpleDateFormat("dd-MMM-yyyy")
				.parse(str_date);
		SimpleDateFormat target = new SimpleDateFormat("yyyy-MM-dd");
		String newDate = target.format(date1);
		return newDate;

	}

	@Override
	public List<PrfCashSummaryView> getPrfListSummary(String prfNo) {
		List<PrfCashSummaryView> data = prfCashSummaryRepository
				.getPrfCashSummary(prfNo);
		return data;
	}

	@Override
	public List<PrfCashDetailsView> getPrfListDetails(String prfNo) {
		List<PrfCashDetailsView> data = prfCashDetailsRepository
				.getPrfCashDetails(prfNo);
		return data;
	}
}
