/**
 * 
 */
package com.exide.sfcrm.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import com.exide.sfcrm.model.ApproverOneContestView;

/**
 * @author neethub
 *
 */
public interface ApproverOneContestListRepository extends JpaRepository<ApproverOneContestView, Long>{
	
	@Query(value="SELECT PRFNoGenREF, PRFNo, PRFGENDate, PRFAmount, Status FROM (select * from TVFCashApprove1List (?1) ORDER by prfgendate OFFSET (?2)  ROWS FETCH NEXT (?3) ROWS ONLY) QryTVFCashApprove1List GROUP BY PRFNoGenREF, PRFNo, PRFGENDate, PRFAmount, Status  " , nativeQuery = true)
	public List<ApproverOneContestView> getApproverOneContestList(String userId , int offSet , int limit);
	
	@Query(value="SELECT  count (*) from [TVFCashApprove1List] (?1)", nativeQuery = true)
	public Integer getCashApprove1List(String userId);
	

}
