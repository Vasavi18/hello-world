package com.difz.harbinger.common.dto;

import java.io.Serializable;
import java.util.Date;

public class UserAuthenticationBO implements Serializable {

	private static final long serialVersionUID = 334534354341L;
	private String userName;
	private String role;
	private String checkKey;
	private String ticket;
	private Date ticketExpiry;
	private Date accountExpiry;
	private String securityQuestion;
	private String securityAnswer;
	private String status;
	private String accessKey;
	private String secretKey;
	private Date lastLoginDateTime;
	private Date lastLogoutDateTime;
	private int failedLoginAttempts;
	
	/**
	 * @return the userName
	 */
	public String getUserName() {
		return userName;
	}
	/**
	 * @param userName the userName to set
	 */
	public void setUserName(String userName) {
		this.userName = userName;
	}
	/**
	 * @return the role
	 */
	public String getRole() {
		return role;
	}
	/**
	 * @param role the role to set
	 */
	public void setRole(String role) {
		this.role = role;
	}
	/**
	 * @return the checkKey
	 */
	public String getCheckKey() {
		return checkKey;
	}
	/**
	 * @param checkKey the checkKey to set
	 */
	public void setCheckKey(String checkKey) {
		this.checkKey = checkKey;
	}
	/**
	 * @return the ticket
	 */
	public String getTicket() {
		return ticket;
	}
	/**
	 * @param ticket the ticket to set
	 */
	public void setTicket(String ticket) {
		this.ticket = ticket;
	}
	/**
	 * @return the ticketExpiry
	 */
	public Date getTicketExpiry() {
		return ticketExpiry;
	}
	/**
	 * @param ticketExpiry the ticketExpiry to set
	 */
	public void setTicketExpiry(Date ticketExpiry) {
		this.ticketExpiry = ticketExpiry;
	}
	/**
	 * @return the accountExpiry
	 */
	public Date getAccountExpiry() {
		return accountExpiry;
	}
	/**
	 * @param accountExpiry the accountExpiry to set
	 */
	public void setAccountExpiry(Date accountExpiry) {
		this.accountExpiry = accountExpiry;
	}
	/**
	 * @return the securityQuestion
	 */
	public String getSecurityQuestion() {
		return securityQuestion;
	}
	/**
	 * @param securityQuestion the securityQuestion to set
	 */
	public void setSecurityQuestion(String securityQuestion) {
		this.securityQuestion = securityQuestion;
	}
	/**
	 * @return the securityAnswer
	 */
	public String getSecurityAnswer() {
		return securityAnswer;
	}
	/**
	 * @param securityAnswer the securityAnswer to set
	 */
	public void setSecurityAnswer(String securityAnswer) {
		this.securityAnswer = securityAnswer;
	}
	/**
	 * @return the status
	 */
	public String getStatus() {
		return status;
	}
	/**
	 * @param status the status to set
	 */
	public void setStatus(String status) {
		this.status = status;
	}
	/**
	 * @return the accessKey
	 */
	public String getAccessKey() {
		return accessKey;
	}
	/**
	 * @param accessKey the accessKey to set
	 */
	public void setAccessKey(String accessKey) {
		this.accessKey = accessKey;
	}
	/**
	 * @return the secretKey
	 */
	public String getSecretKey() {
		return secretKey;
	}
	/**
	 * @param secretKey the secretKey to set
	 */
	public void setSecretKey(String secretKey) {
		this.secretKey = secretKey;
	}
	/**
	 * @return the lastLoginDateTime
	 */
	public Date getLastLoginDateTime() {
		return lastLoginDateTime;
	}
	/**
	 * @param lastLoginDateTime the lastLoginDateTime to set
	 */
	public void setLastLoginDateTime(Date lastLoginDateTime) {
		this.lastLoginDateTime = lastLoginDateTime;
	}
	/**
	 * @return the lastLogoutDateTime
	 */
	public Date getLastLogoutDateTime() {
		return lastLogoutDateTime;
	}
	/**
	 * @param lastLogoutDateTime the lastLogoutDateTime to set
	 */
	public void setLastLogoutDateTime(Date lastLogoutDateTime) {
		this.lastLogoutDateTime = lastLogoutDateTime;
	}
	/**
	 * @return the failedLoginAttempts
	 */
	public int getFailedLoginAttempts() {
		return failedLoginAttempts;
	}
	/**
	 * @param failedLoginAttempts the failedLoginAttempts to set
	 */
	public void setFailedLoginAttempts(int failedLoginAttempts) {
		this.failedLoginAttempts = failedLoginAttempts;
	}
	@Override
	public String toString() {
		return String.format("UserAuthenticationBO [userName=%s,role=%s,checkKey=%s,ticket=%s,ticketExpiry=%s,accountExpiry=%s,securityQuestion=%s,securityAnswer=%s,status=%s,accessKey=%s,secretKey=%s,lastLoginDateTime=%s,lastLogoutDateTime=%s,failedLoginAttempts=%s]",userName,role,checkKey,ticket,ticketExpiry,accountExpiry,securityQuestion,securityAnswer,status,accessKey,secretKey,lastLoginDateTime,lastLogoutDateTime,failedLoginAttempts);
	}
}
