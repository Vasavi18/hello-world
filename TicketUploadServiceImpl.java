package com.exide.sfcrm.service.impl;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;
import org.apache.poi.EncryptedDocumentException;
import org.apache.poi.hssf.usermodel.HSSFWorkbook;
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
import com.exide.sfcrm.model.TicketExcelView;
import com.exide.sfcrm.pojo.TicketExcelPojo;
import com.exide.sfcrm.repository.TblTransactionTicketsRepository;
import com.exide.sfcrm.repository.TicketExcelRepository;
import com.exide.sfcrm.service.TicketUploadService;
/**
 * 
 * @author vasavivr
 *
 */
@Service
public class TicketUploadServiceImpl implements TicketUploadService {

	/**
	 * Logger.
	 */
	private static final Logger LOGGER = Logger
			.getLogger(TicketUploadServiceImpl.class);

	@Autowired
	private PropertyConstants propertyConstants;

	@Autowired
	private TicketExcelPojo ticketExcelPojo;

	@Autowired
	private TblTransactionTicketsRepository tblTransactionTicketsRepository;

	@Autowired
	private TicketExcelRepository ticketExcelRepository;

	@Override
	public String uploadTicketDetails(MultipartFile file)
			throws EncryptedDocumentException, InvalidFormatException,
			IOException {
		String response = "";
		String localFilePath = propertyConstants.TICKET_UPLOAD_FOLDER
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
					setCellTypeToString(row);
					ticketExcelPojo.setContestId(row.getCell(0)
							.getStringCellValue());
					ticketExcelPojo.setContestName(row.getCell(1)
							.getStringCellValue());
					ticketExcelPojo.setStartDate(row.getCell(2)
							.getStringCellValue());
					ticketExcelPojo.setEndDate(row.getCell(3)
							.getStringCellValue());
					ticketExcelPojo.setAgentNo(row.getCell(4)
							.getStringCellValue());
					ticketExcelPojo.setLoadDate(row.getCell(5)
							.getStringCellValue());
					ticketExcelPojo.setTicketLists(row.getCell(6)
							.getStringCellValue());
					ticketExcelPojo.setRuleName(row.getCell(9)
							.getStringCellValue());
					ticketExcelPojo.setSeq(row.getCell(10).getStringCellValue());
					ticketExcelPojo.setDestId(row.getCell(8)
							.getStringCellValue());
					ticketExcelPojo.setOption(row.getCell(7)
							.getStringCellValue());
					ticketExcelPojo.setTotalCount(row.getCell(11)
							.getStringCellValue());
					ticketExcelPojo.setTotalQualified(row.getCell(12)
							.getStringCellValue());
					ticketExcelPojo.setQualified(row.getCell(13)
							.getStringCellValue());

					tblTransactionTicketsRepository
							.executeUpdateAgentOptionsForTicket(
									ticketExcelPojo.getOption(),
									Integer.parseInt(ticketExcelPojo.getContestId()),
									ticketExcelPojo.getAgentNo(), 
									Integer.parseInt(ticketExcelPojo.getTicketLists()), 
									Integer.parseInt(ticketExcelPojo.getDestId()));
				}

			}
		} catch (Exception ex) {
			LOGGER.error("Error occoured while updating TblTransactionTicket");
		}

	}

	private String copyFileToLocalFolder(MultipartFile file,
			String localFilePath) {
		if (file.isEmpty()) {
			LOGGER.info("Empty file ");
			return "Fail";

		} else {
			try {

				File localDir = new File(propertyConstants.TICKET_UPLOAD_FOLDER);
				Boolean tempFileDelete = false;
				if (!localDir.exists()) {
					localDir.mkdir();
				}
				if (localDir.list().length > 0) {
					String[] files = localDir.list();
					for (int i = 0; i < localDir.list().length; i++) {
						File tempFile = new File(
								propertyConstants.TICKET_UPLOAD_FOLDER
										+ File.separator + files[i]);
						tempFileDelete = tempFile.delete();
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

	/**
	 * This method is used to set the cell type as String
	 * 
	 * @param row
	 */
	private void setCellTypeToString(Row row) {
		for (int i = 0; i <= 13; i++) {
			row.getCell(i).setCellType(Cell.CELL_TYPE_STRING);
		}
	}

	@Override
	public List<TicketExcelView> downloadExcel(String userId)
			throws IOException {

		List<TicketExcelView> ticketData = ticketExcelRepository
				.executeTicketData(userId);
		
		/*String excelFilePath = propertyConstants.TICKET_DOWNLOAD_FOLDER;
		  String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMddHHmmss"));
		    File filePath = Paths.get(excelFilePath, "Testing" + timestamp + ".xlsx").toFile();
		writeExcel(ticketData, filePath);*/
		return ticketData;
	}

	public void writeExcel(List<TicketExcelView> ticketData,
			File filePath) throws IOException {
		Workbook workbook = new XSSFWorkbook();
		Sheet sheet = workbook.createSheet("tickets");
		sheet.setColumnWidth(0, 7500);
		sheet.setColumnWidth(1, 7500);
		sheet.setColumnWidth(2, 7500);
		
		   CellStyle style = workbook.createCellStyle();
		Row header = sheet.createRow(0);
	
		  
		header.createCell(0).setCellValue("ContestID");
		  header.getCell(0).setCellStyle(style);
		  
		header.createCell(1).setCellValue("ContestName");
		  header.getCell(1).setCellStyle(style);
		  
		header.createCell(2).setCellValue("StartDate");
		  header.getCell(2).setCellStyle(style);
		  
		header.createCell(3).setCellValue("EndDate");
		  header.getCell(3).setCellStyle(style);
		  
		header.createCell(4).setCellValue("AgentNo");
		  header.getCell(4).setCellStyle(style);
		  
		header.createCell(5).setCellValue("LoadDate");
		  header.getCell(5).setCellStyle(style);
		  
		header.createCell(6).setCellValue("TicketLists");
		  header.getCell(6).setCellStyle(style);
		  
		header.createCell(7).setCellValue("RuleName");
		  header.getCell(7).setCellStyle(style);
		  
		header.createCell(8).setCellValue("Seq");
		  header.getCell(8).setCellStyle(style);
		  
		header.createCell(9).setCellValue("DestID");
		  header.getCell(9).setCellStyle(style);
		  
		header.createCell(10).setCellValue("Option");
		  header.getCell(10).setCellStyle(style);
		  
		header.createCell(11).setCellValue("TotalCount");
		  header.getCell(11).setCellStyle(style);
		  
		header.createCell(12).setCellValue("TotalQualified");
		  header.getCell(12).setCellStyle(style);
		  
		header.createCell(13).setCellValue("Qualified");
		  header.getCell(13).setCellStyle(style);
		  
		int rowCount = 0;
		for (TicketExcelView tickets : ticketData) {
			Row row = sheet.createRow(++rowCount);
			writeBook(tickets, row);
		}

		try (FileOutputStream outputStream = new FileOutputStream(filePath)) {
			workbook.write(outputStream);
			outputStream.close();
			workbook.close();
		}
	}
	
	private void writeBook(TicketExcelView tickets, Row row) {

		Cell cell = row.createCell(0);
		cell.setCellValue(String.valueOf(tickets.getContestID()));

		cell = row.createCell(1);
		cell.setCellValue(tickets.getContestName());

		cell = row.createCell(2);
		cell.setCellValue(tickets.getStartDate());

		cell = row.createCell(3);
		cell.setCellValue(tickets.getEndDate());

		cell = row.createCell(4);
		cell.setCellValue(tickets.getAgentNo());

		cell = row.createCell(5);
		cell.setCellValue(tickets.getLoadDate());

		cell = row.createCell(6);
		cell.setCellValue(String.valueOf(tickets.getTicketLists()));

		cell = row.createCell(7);
		cell.setCellValue(tickets.getRuleName());

		cell = row.createCell(8);
		cell.setCellValue(tickets.getSeq());

		cell = row.createCell(9);
		cell.setCellValue(String.valueOf(tickets.getDestId()));

		cell = row.createCell(10);
		cell.setCellValue(tickets.getOption());

		cell = row.createCell(11);
		cell.setCellValue(tickets.getTotalCount());

		cell = row.createCell(12);
		cell.setCellValue(tickets.getTotalQualified());

		cell = row.createCell(13);
		cell.setCellValue(tickets.getQualified());

	}
	
	
}
