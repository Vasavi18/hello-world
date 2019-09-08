/**
 * 
 */
package com.exide.sfcrm.authentication;

import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapContext;
import javax.security.auth.login.LoginException;

import org.apache.log4j.Logger;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;

import com.exide.sfcrm.constants.MessageConstants;

/**
 * @author saurabhp
 *
 */
@Component
@Configuration
public class ActiveDirectoryUser {

	static DirContext ldapContext;

	private static final String CONTEXT_FACTORY_CLASS = "com.sun.jndi.ldap.LdapCtxFactory";

	private static String ldapServerUrls[];

	private static int lastLdapUrlIndex;

	@Value("${ldap.server}")
	private String ldapServer;

	@Value("${ldap.domain.name}")
	private String ldapDomainName;

	@Value("${ldap.base.search}")
	private String ldapBaseSearch;

	private static final Logger LOGGER = Logger
			.getLogger(ActiveDirectoryUser.class);

	public JSONObject userDetails(String username, String password)
			throws LoginException, JSONException {

		JSONObject ldapUser = null;

		try {
			Hashtable<Object, Object> env = new Hashtable<Object, Object>();
			env.put(Context.INITIAL_CONTEXT_FACTORY, CONTEXT_FACTORY_CLASS);
			env.put(Context.PROVIDER_URL, ldapServer);
			env.put(Context.SECURITY_PRINCIPAL, username + "@" + ldapDomainName);
			env.put(Context.SECURITY_CREDENTIALS, password);
			DirContext ctx = null;
			try {
				ctx = new InitialDirContext(env);
				System.out.println(ctx.getEnvironment());
			} catch (Exception e) {

				LOGGER.error("Exception while connecting LDAP : " + e);
			}

			ldapUser = getMultiSearchResult(
					ctx,
					"(&(objectCategory=user)(samaccountname=" + username + "))",
					ldapBaseSearch);

			ctx.close();
		} catch (Exception exp) {
            
			LOGGER.error("Error while fetting details frm ldap server : " + exp);
		}

		return ldapUser;
	}

	public JSONObject userDetails(String username, String defaultLdapUsername,
			String defaultLdapPassword) throws LoginException {

		JSONObject ldapUser = null;

		try {
			Hashtable<Object, Object> env = new Hashtable<Object, Object>();
			env.put(Context.INITIAL_CONTEXT_FACTORY, CONTEXT_FACTORY_CLASS);
			env.put(Context.PROVIDER_URL, ldapServer);
			env.put(Context.SECURITY_PRINCIPAL, defaultLdapUsername + "@"
					+ ldapDomainName);
			env.put(Context.SECURITY_CREDENTIALS, defaultLdapPassword);
			DirContext ctx = null;
			try {
				ctx = new InitialDirContext(env);
				LOGGER.debug(ctx.getEnvironment());
			} catch (Exception e) {
				LOGGER.error("Exception while connecting LDAP : " + e);
				ldapUser = new JSONObject();
				ldapUser.put("error", "connectionFaliure");
				return ldapUser;
			}

			ldapUser = getMultiSearchResult(
					ctx,
					"(&(objectCategory=user)(samaccountname=" + username + "))",
					ldapBaseSearch);

			if (ldapUser.length() == 0) {
				ldapUser.put("error", "userNotFound");
				ldapUser.put("message", "User does not exist.");
			}

			ctx.close();
		} catch (Exception exp) {

			LOGGER.error("Error while fetting details frm ldap server : " + exp);
			ldapUser = new JSONObject();
			try {
				ldapUser.put("error", "userNotFound");
				ldapUser.put("message", "User does not exist.");
			} catch (JSONException e) {
				LOGGER.error("Error while adding value to JSON " + e);
			}
		}
		return ldapUser;
	}

	private static String[] nsLookup(String argDomain) throws Exception {
		try {
			Hashtable<Object, Object> env = new Hashtable<Object, Object>();
			env.put(Context.INITIAL_CONTEXT_FACTORY,
					"com.sun.jndi.dns.DnsContextFactory");
			env.put("java.naming.provider.url", "dns:");
			DirContext ctx = new InitialDirContext(env);
			Attributes attributes = ctx.getAttributes(
					String.format("_ldap._tcp.%s", argDomain),
					new String[] { "srv" });
			// try thrice to get the KDC servers before throwing error
			for (int i = 0; i < 3; i++) {
				Attribute a = attributes.get("srv");
				if (a != null) {
					List<String> domainServers = new ArrayList<String>();
					NamingEnumeration<?> enumeration = a.getAll();
					while (enumeration.hasMoreElements()) {
						String srvAttr = (String) enumeration.next();
						// the value are in space separated 0) priority 1)
						// weight 2) port 3) server
						String values[] = srvAttr.toString().split(" ");
						domainServers.add(String.format("ldap://%s:%s",
								values[3], values[2]));
					}
					String domainServersArray[] = new String[domainServers
							.size()];
					domainServers.toArray(domainServersArray);
					return domainServersArray;
				}
			}
			throw new Exception("Unable to find srv attribute for the domain "
					+ argDomain);
		} catch (NamingException exp) {
			throw new Exception("Error while performing nslookup. Root Cause: "
					+ exp.getMessage(), exp);
		}
	}

	/**
	 * This method is used to search an entry in LDAP using Novell API
	 * 
	 * @param dirContext
	 * @param searchFilter
	 * @param searchBase
	 * @return {@link Boolean}
	 * @throws NamingException
	 * @throws JSONException
	 */
	private static final JSONObject getMultiSearchResult(
			final DirContext dirContext, final String searchFilter,
			final String searchBase) throws NamingException, JSONException {

		final SearchControls constraints = new SearchControls();
		JSONObject ldapUser = new JSONObject();

		constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
		final NamingEnumeration<?> searchResults = dirContext.search(
				searchBase, searchFilter, constraints);
		while (searchResults != null && searchResults.hasMoreElements()) {

			final SearchResult searchResult = (SearchResult) searchResults
					.next();

			ldapUser.put(
					"samAccountName",
					displayAttribute("sAMAccountName",
							searchResult.getAttributes()));
			ldapUser.put("givenName",
					displayAttribute("givenName", searchResult.getAttributes()));
			if (searchResult.getAttributes().get("sn") != null) {
				ldapUser.put("surName",
						displayAttribute("sn", searchResult.getAttributes()));
			} else {
				ldapUser.put(
						"surName",
						displayAttribute("initials",
								searchResult.getAttributes()));
			}
			ldapUser.put("mail",
					displayAttribute("mail", searchResult.getAttributes()));
			// displayAttribute("memberOf", searchResult.getAttributes());
		}

		return ldapUser;

	}

	/**
	 * This method used to display the Attribute Values
	 * 
	 * @param attributes
	 * @throws NamingException
	 */
	private static String displayAttribute(String attrName,
			final Attributes attributes) throws NamingException {

		if (attributes == null) {
			LOGGER.debug("*** No attributes ***");
		} else {
			for (@SuppressWarnings("rawtypes")
			NamingEnumeration enums = attributes.getAll(); enums.hasMore();) {
				final Attribute attribute = (Attribute) enums.next();
				if (attribute.getID().equals(attrName)) {
					for (@SuppressWarnings("rawtypes")
					NamingEnumeration namingEnu = attribute.getAll(); namingEnu
							.hasMore();) {

						String value = namingEnu.next().toString();
						LOGGER.debug("\t        = " + value);
						return value;
					}

				}
			}

		}

		return null;
	}

	public static String getUserMailByDomainWithUser(LdapContext ctx,
			String searchBase, String domainWithUser) throws Exception {

		ldapServerUrls = nsLookup("nousinfo.com");
		int currentLdapUrlIndex = lastLdapUrlIndex;
		Hashtable<String, String> environment = new Hashtable<String, String>();
		environment.put(Context.INITIAL_CONTEXT_FACTORY,
				"com.sun.jndi.ldap.LdapCtxFactory");
		environment.put(Context.PROVIDER_URL,
				ldapServerUrls[currentLdapUrlIndex]);
		/*
		 * logger.debug("trying to get email of domainWithUser " +
		 * domainWithUser + " using baseDN " + searchBase);
		 */
		String userName = domainWithUser
				.substring(domainWithUser.indexOf('\\') + 1);
		try {
			NamingEnumeration<SearchResult> userDataBysAMAccountName = getUserDataBysAMAccountName(
					ctx, searchBase, userName);
			return getUserMailFromSearchResults(userDataBysAMAccountName);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	private static NamingEnumeration<SearchResult> getUserDataBysAMAccountName(
			LdapContext ctx, String searchBase, String username)
			throws Exception {
		String filter = "(&(&(objectClass=person)(objectCategory=user))(sAMAccountName="
				+ username + "))";
		SearchControls searchCtls = new SearchControls();
		searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
		NamingEnumeration<SearchResult> answer = null;
		try {
			answer = ctx.search(searchBase, filter, searchCtls);
		} catch (Exception e) {
			// logger.error("Error searching Active directory for " + filter);
			throw e;
		}

		return answer;
	}

	private static String getUserMailFromSearchResults(
			NamingEnumeration<SearchResult> userData) throws Exception {
		try {
			String mail = null;
			// getting only the first result if we have more than one
			if (userData.hasMoreElements()) {
				// SearchResult sr = userData.nextElement();
				// Attributes attributes = sr.getAttributes();
				/*
				 * mail =
				 * attributes.get(AD_ATTR_NAME_USER_EMAIL).get().toString();
				 * logger.debug("found email " + mail);
				 */
			}

			return mail;
		} catch (Exception e) {
			// logger.error("Error fetching attribute from object");
			throw e;
		}
	}

	/*
	 * public static void main(String args[]){
	 * //getUserMailByDomainWithUser(ldapServerUrls);
	 * //ActiveDirectoryAuthentication authentication = new
	 * ActiveDirectoryAuthentication("nousinfo.com"); try { boolean authResult =
	 * authenticate("saurabhp", "qwert`123");
	 * System.out.println("Result :"+authResult); } catch (LoginException e) {
	 * System.out.println(e); e.printStackTrace(); } }
	 */

	/*
	 * public static String windowADAuth() {
	 * 
	 * // initialize a security context on the client IWindowsSecurityContext
	 * clientContext = WindowsSecurityContextImpl .getCurrent("Negotiate",
	 * "localhost");
	 * 
	 * // create an auth provider and a security context for the client // on
	 * the server WindowsAuthProviderImpl provider = new
	 * WindowsAuthProviderImpl(); IWindowsSecurityContext serverContext = null;
	 * 
	 * // now you would send the byte[] token to the server and the server will
	 * // response with another byte[] token, which the client needs to answer
	 * // again do {
	 * 
	 * // Step 2: If you have already build an initial security context for //
	 * the client // on the server, send a token back to the client, which the
	 * client // needs to // accept and send back to the server again (a
	 * handshake) if (serverContext != null) { byte[]
	 * tokenForTheClientOnTheServer = serverContext.getToken(); SecBufferDesc
	 * continueToken = new SecBufferDesc( Sspi.SECBUFFER_TOKEN,
	 * tokenForTheClientOnTheServer);
	 * clientContext.initialize(clientContext.getHandle(), continueToken,
	 * "localhost"); }
	 * 
	 * // Step 1: accept the token on the server and build a security // context
	 * // representing the client on the server byte[]
	 * tokenForTheServerOnTheClient = clientContext.getToken(); serverContext =
	 * provider.acceptSecurityToken("server-connection",
	 * tokenForTheServerOnTheClient, "Negotiate");
	 * 
	 * } while (clientContext.isContinue());
	 * 
	 * // at the end of this handshake, we know on the server side who the //
	 * client is, only by exchanging byte[] arrays
	 * System.out.println(serverContext.getIdentity().getFqn()); if (null !=
	 * serverContext.getIdentity().getFqn()) {
	 * 
	 * 
	 * String username = Advapi32Util.getUserName();
	 * System.out.println("username :"+username); Advapi32Util.Account account =
	 * Advapi32Util.getAccountByName(username);
	 * System.out.println(" Acount Type : "+account.accountType);
	 * System.out.println("Domain : "+account.domain);
	 * System.out.println("fqn : " + account.fqn); System.out.println("Name :"
	 * +account.name); System.out.println("Sid : "+account.sidString);
	 * 
	 * 
	 * return serverContext.getIdentity().getFqn(); } else { return null; } }
	 */

}
