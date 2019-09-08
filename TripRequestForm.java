package com.exide.sfcrm.pojo;

import java.sql.Date;
import java.util.List;

public class TripRequestForm {

	private String tripAmount ;
	private String destPlace ;
	private String cashAmount ;
	
	public TripRequestForm() {
		// TODO Auto-generated constructor stub
	}
	
	public TripRequestForm(String tripAmount, String destPlace, String cashAmount) {
		this.tripAmount = tripAmount;
		this.destPlace = destPlace;
		this.cashAmount = cashAmount;
	}
	
	public String getTripAmount() {
		return tripAmount;
	}
	public void setTripAmount(String tripAmount) {
		this.tripAmount = tripAmount;
	}
	public String getDestPlace() {
		return destPlace;
	}
	public void setDestPlace(String destPlace) {
		this.destPlace = destPlace;
	}
	public String getCashAmount() {
		return cashAmount;
	}
	public void setCashAmount(String cashAmount) {
		this.cashAmount = cashAmount;
	}
	
}