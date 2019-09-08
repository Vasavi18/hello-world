package com.difz.bsve.auth.data.model;

import java.io.Serializable;
import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;

	/**
	 * The persistent class for the UserAuthentication database table.
	 */
	@Entity
	@Table(name = "UserAuthentication")
	public class UserAuthentication implements Serializable {
		private static final long serialVersionUID = 1L;

		@Id
		@Column(unique = true, nullable = false, length = 50)
		private String userName;
		
		@Column(nullable = false, length = 10)
		private String role;


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

		@Column(nullable = false, length = 50)
		private String checkKey;

		@Column(length = 50)
		private String ticket;

		@Temporal(TemporalType.TIMESTAMP)
		private Date ticketExpiry;
		
		@Temporal(TemporalType.DATE)
		private Date accountExpiry;

		@Column(length = 128)
		private String securityQuestion;

		@Column(length = 64)
		private String securityAnswer;

		@Column(length = 1)
		private String status;
		
		/**
		 * 
		 */
		@Column(length=50)
		private String accessKey;
		/**
		 * 
		 */
		@Column(length=50)
		private String secretKey;
		
		@Temporal(TemporalType.TIMESTAMP)
		private Date lastLoginDateTime;
		
		@Temporal(TemporalType.TIMESTAMP)
		private Date lastLogoutDateTime;

		private int failedLoginAttempts;

		public UserAuthentication() {
		}

		public String getUserName() {
			return this.userName;
		}

		public void setUserName(String userName) {
			this.userName = userName;
		}

		public String getCheckKey() {
			return checkKey;
		}

		public void setCheckKey(String checkKey) {
			this.checkKey = checkKey;
		}

		public String getTicket() {
			return ticket;
		}

		public void setTicket(String ticket) {
			this.ticket = ticket;
		}

		public Date getTicketExpiry() {
			return ticketExpiry;
		}

		public void setTicketExpiry(Date ticketExpiry) {
			this.ticketExpiry = ticketExpiry;
		}
		
		public Date getAccountExpiry() {
			return accountExpiry;
		}

		public void setAccountExpiry(Date accountExpiry) {
			this.accountExpiry = accountExpiry;
		}

		public String getSecurityQuestion() {
			return securityQuestion;
		}

		public void setSecurityQuestion(String securityQuestion) {
			this.securityQuestion = securityQuestion;
		}

		public String getSecurityAnswer() {
			return securityAnswer;
		}

		public void setSecurityAnswer(String securityAnswer) {
			this.securityAnswer = securityAnswer;
		}

		public String getStatus() {
			return this.status;
		}

		public void setStatus(String status) {
			this.status = status;
		}

		public int getFailedLoginAttempts() {
			return this.failedLoginAttempts;
		}

		public void setFailedLoginAttempts(int failedLoginAttempts) {
			this.failedLoginAttempts = failedLoginAttempts;
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
		

}
