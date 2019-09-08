package com.exide.sfcrm.dto;

public class VendorTransactionDto {

	private Integer vendorTransactionId;

	private Integer costCenterId;

	private String channelType;

	private String vendorName;

	private Double amount;

	private String tax;

	private Double netPayable;

	private String amountInWords;

	private String modeOfPayment;

	private String date;

	public Integer getVendorTransactionId() {
		return vendorTransactionId;
	}

	public void setVendorTransactionId(Integer vendorTransactionId) {
		this.vendorTransactionId = vendorTransactionId;
	}

	public Integer getCostCenterId() {
		return costCenterId;
	}

	public void setCostCenterId(Integer costCenterId) {
		this.costCenterId = costCenterId;
	}

	public String getChannelType() {
		return channelType;
	}

	public void setChannelType(String channelType) {
		this.channelType = channelType;
	}

	public String getVendorName() {
		return vendorName;
	}

	public void setVendorName(String vendorName) {
		this.vendorName = vendorName;
	}

	public Double getAmount() {
		return amount;
	}

	public void setAmount(Double amount) {
		this.amount = amount;
	}

	public String getTax() {
		return tax;
	}

	public void setTax(String tax) {
		this.tax = tax;
	}

	public Double getNetPayable() {
		return netPayable;
	}

	public void setNetPayable(Double netPayable) {
		this.netPayable = netPayable;
	}

	public String getAmountInWords() {
		return amountInWords;
	}

	public void setAmountInWords(String amountInWords) {
		this.amountInWords = amountInWords;
	}

	public String getModeOfPayment() {
		return modeOfPayment;
	}

	public void setModeOfPayment(String modeOfPayment) {
		this.modeOfPayment = modeOfPayment;
	}

	public String getDate() {
		return date;
	}

	public void setDate(String date) {
		this.date = date;
	}

}
