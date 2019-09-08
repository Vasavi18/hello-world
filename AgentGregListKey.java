package com.exide.sfcrm.model;

import java.io.Serializable;
import java.sql.Date;

import javax.persistence.Column;
import javax.persistence.Embeddable;

@Embeddable
public class AgentGregListKey implements Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = 6491030295378753848L;

	/**
	 * 
	 */

	@Column(name = "agentno")
	private String agentNo;

	@Column(name = "agenttype")
	private String agentType;

	@Column(name = "startdate")
	private String startDate;

	@Column(name = "enddate")
	private String endDate;
	
	

	/**
	 * @return the agentNo
	 */
	public String getAgentNo() {
		return agentNo;
	}

	/**
	 * @param agentNo
	 *            the agentNo to set
	 */
	public void setAgentNo(String agentNo) {
		this.agentNo = agentNo;
	}

	/**
	 * @return the agentType
	 */
	public String getAgentType() {
		return agentType;
	}

	/**
	 * @param agentType
	 *            the agentType to set
	 */
	public void setAgentType(String agentType) {
		this.agentType = agentType;
	}

	/**
	 * @return the startDate
	 */
	public String getStartDate() {
		return startDate;
	}

	/**
	 * @param startDate the startDate to set
	 */
	public void setStartDate(String startDate) {
		this.startDate = startDate;
	}

	/**
	 * @return the endDate
	 */
	public String getEndDate() {
		return endDate;
	}

	/**
	 * @param endDate the endDate to set
	 */
	public void setEndDate(String endDate) {
		this.endDate = endDate;
	}



}
