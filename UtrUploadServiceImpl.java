package com.exide.sfcrm.service.impl;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Iterator;
import java.util.List;

import org.apache.log4j.Logger;
import org.apache.poi.EncryptedDocumentException;
import org.apache.poi.openxml4j.exceptions.InvalidFormatException;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.CellStyle;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.ss.usermodel.WorkbookFactory;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import com.exide.sfcrm.constants.PropertyConstants;
import com.exide.sfcrm.model.TblPRFGeneratedCashView;
import com.exide.sfcrm.pojo.UtrCashExcelPojo;
import com.exide.sfcrm.repository.TblPRFGeneratedCashViewRepository;
import com.exide.sfcrm.repository.TblPRFGenratedCashRepository;
import com.exide.sfcrm.service.UtrUploadService;
import com.exide.sfcrm.util.CommonUtil;

/**
 * 
 * @author vasavivr
 *
 */

@Service
public class UtrUploadServiceImpl implements UtrUploadService {

	@Autowired
	UtrCashExcelPojo utrCashExcelPojo;

	@Autowired
	TblPRFGenratedCashRepository tblPRFGenratedCashRepository;

	@Autowired
	TblPRFGeneratedCashViewRepository tblPRFGeneratedCashViewRepository;
	
	@Autowired
	CommonUtil commonUtil;
	/**
	 * Logger.
	 */
	private static final Logger LOGGER = Logger
			.getLogger(UtrUploadServiceImpl.class);

	@Autowired
	private PropertyConstants propertyConstants;

	@Override
	public List<TblPRFGeneratedCashView> downloadUtrExcel(String prfNo,
			String uid) throws IOException {
		Integer id = getCid(uid);
		List<TblPRFGeneratedCashView> utrCashList = tblPRFGeneratedCashViewRepository
				.findByPrfNo(prfNo, id);
		String excelFilePath = propertyConstants.UTR_DOWNLOAD_FOLDER;
		String timestamp = LocalDateTime.now().format(
				DateTimeFormatter.ofPattern("yyyyMMddHHmmss"));
		File filePath = Paths.get(excelFilePath,
				"TestingUtr" + timestamp + ".xlsx").toFile();
		writeExcel(utrCashList, filePath);
		return utrCashList;
	}

	private Integer getCid(String uid) {

		return tblPRFGeneratedCashViewRepository.findByCid(uid);
	}

	public void writeExcel(List<TblPRFGeneratedCashView> utrCashList,
			File filePath) throws IOException {
		Workbook workbook = new XSSFWorkbook();

		Sheet sheet = workbook.createSheet("Utr");

		sheet.setColumnWidth(0, 7500);
		sheet.setColumnWidth(1, 7500);
		sheet.setColumnWidth(2, 7500);
		sheet.setColumnWidth(3, 7500);
		sheet.setColumnWidth(4, 7500);
		sheet.setColumnWidth(5, 7500);

		CellStyle style = workbook.createCellStyle();
		Row header = sheet.createRow(0);

		header.createCell(0).setCellValue("PrfNo");
		header.getCell(0).setCellStyle(style);

		header.createCell(1).setCellValue("AgentNo");
		header.getCell(1).setCellStyle(style);

		header.createCell(2).setCellValue("AgentName");
		header.getCell(2).setCellStyle(style);

		header.createCell(3).setCellValue("NetPayout");
		header.getCell(3).setCellStyle(style);

		header.createCell(4).setCellValue("UtrNo");
		header.getCell(4).setCellStyle(style);

		header.createCell(5).setCellValue("TransferDate");
		header.getCell(5).setCellStyle(style);

		int rowCount = 0;
		for (TblPRFGeneratedCashView utrCashListData : utrCashList) {
			Row row = sheet.createRow(++rowCount);
			writeUtrList(utrCashListData, row);
		}

		try (FileOutputStream outputStream = new FileOutputStream(filePath)) {
			workbook.write(outputStream);
			outputStream.close();
			workbook.close();
		}
	}

	private void writeUtrList(TblPRFGeneratedCashView utrCashListData, Row row) {

		Cell cell = row.createCell(0);
		cell.setCellValue(utrCashListData.getPrfNo());

		cell = row.createCell(1);
		cell.setCellValue(utrCashListData.getAgentNo());

		cell = row.createCell(2);
		cell.setCellValue(utrCashListData.getAgentName());

		cell = row.createCell(3);
		cell.setCellValue(Float.valueOf(utrCashListData.getSumOfNetPayout()));

		cell = row.createCell(4);
		cell.setCellValue(utrCashListData.getUtrNo());

		cell = row.createCell(5);
		if (utrCashListData.getTransferDate() == null) {
			cell.setCellValue(" ");
		} else {

			cell.setCellValue((String.valueOf(utrCashListData.getTransferDate())));

		}

	}

	@Override
	public String uploadUtrDetails(MultipartFile file)
			throws EncryptedDocumentException, InvalidFormatException,
			IOException {
		String response = "";
		String localFilePath = propertyConstants.UTR_UPLOAD_FOLDER
				+ File.separator + file.getOriginalFilename();
		copyFileToLocalFolder(file, localFilePath);
		readExcel(file, localFilePath);
		return response;

	}

	private void readExcel(MultipartFile filePath, String localFilePath)
			throws EncryptedDocumentException, InvalidFormatException,
			IOException {
		try {
			File file = new File(localFilePath);
			Workbook workbook = WorkbookFactory.create(file);

			// Get first sheet from the workbook
			Sheet sheet = workbook.getSheetAt(0);
			Iterator<Row> rowIterator = sheet.iterator();
			boolean flag = true;
			while (rowIterator.hasNext()) {
				Row row = rowIterator.next();
				if (checkIfRowIsEmpty(row)) {
					LOGGER.info("Empty row found");
					break;
				} else {
					if (flag) {
						row = rowIterator.next();
						flag = false;
					}
					
					utrCashExcelPojo.setPrfNo(row.getCell(1)
							.getStringCellValue());
					utrCashExcelPojo.setAgentNo(String.valueOf((int)row.getCell(2)
							.getNumericCellValue()));
					utrCashExcelPojo.setAgentName(row.getCell(3)
							.getStringCellValue());
					utrCashExcelPojo.setNetPayout(row.getCell(4)
							.getNumericCellValue());
					if(row.getCell(5).getCellType() == 0){
						utrCashExcelPojo.setUtrNo(row.getCell(5)
								.getNumericCellValue()+ "");
					}else if(row.getCell(5).getCellType() == 1){
						utrCashExcelPojo.setUtrNo(row.getCell(5)
								.getStringCellValue());
					}
					
					if(row.getCell(6).getCellType() == 0){
						SimpleDateFormat sdf = new SimpleDateFormat("dd-MMM-yyyy");
						utrCashExcelPojo.setTransferDate(sdf.format(row.getCell(6).getDateCellValue()));
					}else if(row.getCell(6).getCellType() == 1){
						utrCashExcelPojo.setTransferDate(row.getCell(6)
								.getStringCellValue());
					}
				/*	utrCashExcelPojo.setTransferDate(row.getCell(6)
							.getStringCellValue());*/
					System.out.println(utrCashExcelPojo.getTransferDate());

					tblPRFGenratedCashRepository.executeUpdateUtrCash(
							utrCashExcelPojo.getPrfNo(),
							utrCashExcelPojo.getAgentNo(),
							utrCashExcelPojo.getUtrNo(),
							commonUtil.getDateFormatting(utrCashExcelPojo.getTransferDate())); 

				}

			}
		} catch (Exception ex) {
			LOGGER.error("Error occoured while updating utrDetails");
		}

	}

	private String copyFileToLocalFolder(MultipartFile file,
			String localFilePath) {
		Boolean tempFileDelete=false;
		if (file.isEmpty()) {
			LOGGER.info("Empty file ");
			return "Fail";

		} else {
			try {

				File localDir = new File(propertyConstants.UTR_UPLOAD_FOLDER);

				if (!localDir.exists()) {
					localDir.mkdir();
				}
				if (localDir.list().length > 0) {
					String[] files = localDir.list();
					for (int i = 0; i < localDir.list().length; i++) {
						File tempFile = new File(
								propertyConstants.UTR_UPLOAD_FOLDER
										+ File.separator + files[i]);
						tempFileDelete=tempFile.delete();
					}
				}

				try {
					byte[] bytes = file.getBytes();
					Path path = Paths.get(localFilePath);
					LOGGER.info("Copying uploaded file to local directory");
					Files.write(path, bytes);
				} catch (IOException ex) {

					LOGGER.error(
							"Exception while converting  : " + ex.getMessage(),
							ex);
					return "Fail";
				}

				LOGGER.info("File uploaded successfully");

			} catch (Exception e) {
				LOGGER.error("File upload failed : " + e.getMessage(), e);
				return "Fail";
			}

		}
		return "Success";

	}

	/**
	 * Method to check and return if row is empty or null.
	 * 
	 * @param row
	 *            object to check
	 * @return True if empty and False if not empty
	 */
	private Boolean checkIfRowIsEmpty(Row row) {
		if (row == null) {
			return true;
		}
		Iterator<Cell> iterator = row.iterator();
		while (iterator.hasNext()) {
			Cell cell = iterator.next();
			if (cell.getCellType() != Cell.CELL_TYPE_BLANK) {
				return false;
			}
		}
		return true;
	}

}