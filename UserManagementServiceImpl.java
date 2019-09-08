/**
 * 
 */
package com.exide.sfcrm.service.impl;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.exide.sfcrm.dao.UserManagementDao;
import com.exide.sfcrm.model.User;
import com.exide.sfcrm.model.UserGroup;
import com.exide.sfcrm.model.UserGroupPermission;
import com.exide.sfcrm.repository.UserGroupPermissionsRepository;
import com.exide.sfcrm.repository.UserGroupRepository;
import com.exide.sfcrm.repository.UserManagementRepository;
import com.exide.sfcrm.service.UserManagementService;

/**
 * @author saurabhp
 *
 */
@Service
public class UserManagementServiceImpl implements UserManagementService{

	
	@Autowired
	private UserManagementDao userManagementDao;
	
    @Autowired
    UserManagementRepository userManagementRepository;
    
    @Autowired
    UserGroupRepository userGroupRepository;
    
    @Autowired
    UserGroupPermissionsRepository userGroupPermissionRepository;
	//@Autowired
	//private CommonUtil commonUtil;
	
	
	/**
	 * Get user list.
	 */
	@Override
	public List<User> getUserList() throws Exception {

		List<User> users = new ArrayList<>();
		users = userManagementRepository.findAll();
		
		return users;
	}

	/***change user status.
	 * 
	 */
	@Override
	public void userStatus(String[] userNames, boolean status) throws Exception {
		
		List<String> userNameList = new ArrayList<String>();
		for(String userName : userNames){
			userNameList.add(userName);
		}
		
		userManagementRepository.updateUserStatus(userNameList, status);
		
	}

	/**
	 * create user.
	 */
	@Override
	public Integer createOrUpdateUser(User user) throws Exception{
		
		
		user.setCreatedDate(new Date());
		User createdUser = userManagementDao.createOrUpdateUser(user);
		
		userManagementDao.insertIntoCuMap(user);
		
		return createdUser.getId();
	}
	
	@Override
	public Set<UserGroup> getAllUserGroupBasedOnId(Integer id) throws Exception {
		return userGroupRepository.getAllUserGroup(id);
	}

	@Override
	public boolean checkUser(String userName) throws Exception {

		boolean status = false;
		User user = userManagementRepository.findByUserName(userName);
		
		if(null == user){
			status = true;
		}
		
		return status;
	}

	@Override
	public User getUser(Integer userId) throws Exception {
		
		User user = userManagementRepository.findByUserId(userId);
		return user;
	}

	@Override
	public User getUserByName(String userName) throws Exception {
		
		return userManagementRepository.findByUserName(userName);
	}

	@Override
	public List<User> getRoleBasedUserList(String role) throws Exception {

		
		List<User> users = new ArrayList<>();
		userManagementRepository.findRoleBasedUsers(role).forEach(e -> users.add(e));
		
		return users;
	}

	@Override
	public List<UserGroup> getAllUserGroup() throws Exception {
		
		
		List<UserGroup> userGroup = new ArrayList<>();
		userGroupRepository.findAll().forEach(e -> userGroup.add(e));
		
		return userGroup;
	}

	@Override
	public List<UserGroupPermission> getAllUserGroupPermission(List<Integer> id)
			throws Exception {
		
		List<UserGroupPermission> userGroupPermissions = userGroupPermissionRepository.getUserGroupPermissionBasedOnId(id);
		return userGroupPermissions;
	}

	

}
