package com.exide.sfcrm.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import com.exide.sfcrm.model.PrfCashDetailsView;

@Repository
public interface PrfCashDetailsRepository extends JpaRepository<PrfCashDetailsView, Integer> {
	
	@Query(value="EXEC PRFCashDetails ?1",nativeQuery=true)
	public List<PrfCashDetailsView> getPrfCashDetails(String prfNo);

}
