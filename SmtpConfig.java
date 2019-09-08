/**
 * 
 */
package com.exide.sfcrm.config;

import java.util.List;
import java.util.Properties;

import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.task.TaskExecutor;
import org.springframework.stereotype.Component;

import com.exide.sfcrm.constants.PropertyConstants;
import com.exide.sfcrm.model.User;

/**
 * @author saurabhp
 *
 */
@Component
public class SmtpConfig {
	
	/**
	 * LOGGER.
	 */
	private static final Logger LOGGER = Logger.getLogger(SmtpConfig.class);
	
	@Autowired
	private PropertyConstants propertyConstants;
	
	@Autowired
    private TaskExecutor taskExecutor;
	
	/**
	 * Send mails to different users based on roles
	 * @param emailIds
	 * @param subject
	 * @param body
	 */
	
	public void smtpService(String[] emailIds, String subject, String body) {
			
			
			Properties props = new Properties();
			props.put("mail.smtp.host", propertyConstants.SMTP_SERVER_URL);
			props.put("mail.smtp.socketFactory.port", propertyConstants.SMTP_SERVER_PORT);
			props.put("mail.smtp.socketFactory.class","javax.net.ssl.SSLSocketFactory");
			props.put("mail.smtp.auth", propertyConstants.SMTP_SERVER_AUTH);
			props.put("mail.smtp.port", propertyConstants.SMTP_SERVER_PORT);

			Session session = Session.getInstance(props,new javax.mail.Authenticator() {
					protected PasswordAuthentication getPasswordAuthentication() {
						return new PasswordAuthentication(propertyConstants.SMTP_SERVER_USERNAME,propertyConstants.SMTP_SERVER_PASSWORD);
					}
				});
			try {

				Message message = new MimeMessage(session);
				message.setFrom(new InternetAddress(propertyConstants.SMTP_SERVER_USERNAME));
				  InternetAddress[] address = new InternetAddress[emailIds.length];
				  for(int i =0; i< emailIds.length; i++)
				  {
				      address[i] = new InternetAddress(emailIds[i]);
				  }
				message.setRecipients(Message.RecipientType.TO,address);
				message.setSubject(subject);
				message.setText(body);
		        Transport.send(message);
				LOGGER.debug("Email Send Successfully to : "+emailIds.toString());
			} catch (MessagingException e) {
				LOGGER.error("Exception occured while sending the email"+e);
				throw new RuntimeException(e);
			}
		}
		
		/**
		 *  Fetch all email id of the users.
		 * @param users
		 */
	
		public void sendMailtoGroup(List<User> users, String subject, String body) throws Exception{
			System.out.println(subject);
			String[] emailIds = new String[users.size()];
			int i=0;
			for(User user : users){
				emailIds[i] = user.getEmailId();
				i++;
			}
			taskExecutor.execute(new Runnable() {
				public void run() {
				try {
					smtpService(emailIds,subject,body);
			}catch (Exception e) {
			     e.printStackTrace();
			     LOGGER.error("Failed to send email to: " + emailIds + " reason: "+e.getMessage());
			    }
				}
			});
			LOGGER.debug("Send mail to group executed");
		}
		
}
