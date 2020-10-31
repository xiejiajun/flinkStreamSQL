//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

package org.apache.hadoop.security;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.UndeclaredThrowableException;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.kerberos.KerberosTicket;
import javax.security.auth.kerberos.KeyTab;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag;
import javax.security.auth.spi.LoginModule;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.flink.hadoop.shaded.com.google.common.annotations.VisibleForTesting;
import org.apache.hadoop.classification.InterfaceAudience.LimitedPrivate;
import org.apache.hadoop.classification.InterfaceAudience.Private;
import org.apache.hadoop.classification.InterfaceAudience.Public;
import org.apache.hadoop.classification.InterfaceStability.Evolving;
import org.apache.hadoop.classification.InterfaceStability.Unstable;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.metrics2.annotation.Metric;
import org.apache.hadoop.metrics2.annotation.Metrics;
import org.apache.hadoop.metrics2.lib.DefaultMetricsSystem;
import org.apache.hadoop.metrics2.lib.MetricsRegistry;
import org.apache.hadoop.metrics2.lib.MutableQuantiles;
import org.apache.hadoop.metrics2.lib.MutableRate;
import org.apache.hadoop.security.SaslRpcServer.AuthMethod;
import org.apache.hadoop.security.authentication.util.KerberosUtil;
import org.apache.hadoop.security.token.Token;
import org.apache.hadoop.security.token.TokenIdentifier;
import org.apache.hadoop.security.token.Token.PrivateToken;
import org.apache.hadoop.util.PlatformName;
import org.apache.hadoop.util.Shell;
import org.apache.hadoop.util.Time;

import static org.apache.hadoop.util.PlatformName.IBM_JAVA;

@LimitedPrivate({"HDFS", "MapReduce", "HBase", "Hive", "Oozie"})
@Evolving
public class UserGroupInformation {
    private static final Log LOG = LogFactory.getLog(UserGroupInformation.class);
    private static final float TICKET_RENEW_WINDOW = 0.8F;
    private static boolean shouldRenewImmediatelyForTests = false;
    static final String HADOOP_USER_NAME = "HADOOP_USER_NAME";
    static final String HADOOP_PROXY_USER = "HADOOP_PROXY_USER";
    static UserGroupInformation.UgiMetrics metrics = UserGroupInformation.UgiMetrics.create();
    private static UserGroupInformation.AuthenticationMethod authenticationMethod;
    private static Groups groups;
    private static Configuration conf;
    private static final long MIN_TIME_BEFORE_RELOGIN = 600000L;
    public static final String HADOOP_TOKEN_FILE_LOCATION = "HADOOP_TOKEN_FILE_LOCATION";
    private static UserGroupInformation loginUser = null;
    private static String keytabPrincipal = null;
    private static String keytabFile = null;
    private final Subject subject;
    private final User user;
    private final boolean isKeytab;
    private final boolean isKrbTkt;
    private static String OS_LOGIN_MODULE_NAME = getOSLoginModuleName();
    private static Class<? extends Principal> OS_PRINCIPAL_CLASS = getOsPrincipalClass();
    private static final boolean windows = System.getProperty("os.name").startsWith("Windows");
    private static final boolean is64Bit = System.getProperty("os.arch").contains("64");
    private static final boolean aix = System.getProperty("os.name").equals("AIX");

    @VisibleForTesting
    static void setShouldRenewImmediatelyForTests(boolean immediate) {
        shouldRenewImmediatelyForTests = immediate;
    }

    private static void ensureInitialized() {
        if (conf == null) {
            Class var0 = UserGroupInformation.class;
            synchronized(UserGroupInformation.class) {
                if (conf == null) {
                    initialize(new Configuration(), false);
                }
            }
        }

    }

    private static synchronized void initialize(Configuration conf, boolean overrideNameRules) {
        authenticationMethod = SecurityUtil.getAuthenticationMethod(conf);
        if (overrideNameRules || !HadoopKerberosName.hasRulesBeenSet()) {
            try {
                HadoopKerberosName.setConfiguration(conf);
            } catch (IOException var6) {
                throw new RuntimeException("Problem with Kerberos auth_to_local name configuration", var6);
            }
        }

        if (!(groups instanceof UserGroupInformation.TestingGroups)) {
            groups = Groups.getUserToGroupsMappingService(conf);
        }

        UserGroupInformation.conf = conf;
        if (metrics.getGroupsQuantiles == null) {
            int[] intervals = conf.getInts("hadoop.user.group.metrics.percentiles.intervals");
            if (intervals != null && intervals.length > 0) {
                int length = intervals.length;
                MutableQuantiles[] getGroupsQuantiles = new MutableQuantiles[length];

                for(int i = 0; i < length; ++i) {
                    getGroupsQuantiles[i] = metrics.registry.newQuantiles("getGroups" + intervals[i] + "s", "Get groups", "ops", "latency", intervals[i]);
                }

                metrics.getGroupsQuantiles = getGroupsQuantiles;
            }
        }

    }

    @Public
    @Evolving
    public static void setConfiguration(Configuration conf) {
        initialize(conf, true);
    }

    @Private
    @VisibleForTesting
    public static void reset() {
        authenticationMethod = null;
        conf = null;
        groups = null;
        setLoginUser((UserGroupInformation)null);
        HadoopKerberosName.setRules((String)null);
    }

    public static boolean isSecurityEnabled() {
        return !isAuthenticationMethodEnabled(UserGroupInformation.AuthenticationMethod.SIMPLE);
    }

    @Private
    @Evolving
    private static boolean isAuthenticationMethodEnabled(UserGroupInformation.AuthenticationMethod method) {
        ensureInitialized();
        return authenticationMethod == method;
    }

    private static String getOSLoginModuleName() {
        if (PlatformName.IBM_JAVA) {
            if (windows) {
                return is64Bit ? "com.ibm.security.auth.module.Win64LoginModule" : "com.ibm.security.auth.module.NTLoginModule";
            } else if (aix) {
                return is64Bit ? "com.ibm.security.auth.module.AIX64LoginModule" : "com.ibm.security.auth.module.AIXLoginModule";
            } else {
                return "com.ibm.security.auth.module.LinuxLoginModule";
            }
        } else {
            return windows ? "com.sun.security.auth.module.NTLoginModule" : "com.sun.security.auth.module.UnixLoginModule";
        }
    }

    private static Class<? extends Principal> getOsPrincipalClass() {
        ClassLoader cl = ClassLoader.getSystemClassLoader();

        try {
            String principalClass = null;
            if (PlatformName.IBM_JAVA) {
                if (is64Bit) {
                    principalClass = "com.ibm.security.auth.UsernamePrincipal";
                } else if (windows) {
                    principalClass = "com.ibm.security.auth.NTUserPrincipal";
                } else if (aix) {
                    principalClass = "com.ibm.security.auth.AIXPrincipal";
                } else {
                    principalClass = "com.ibm.security.auth.LinuxPrincipal";
                }
            } else {
                principalClass = windows ? "com.sun.security.auth.NTUserPrincipal" : "com.sun.security.auth.UnixPrincipal";
            }

            return (Class<? extends Principal>) cl.loadClass(principalClass);
        } catch (ClassNotFoundException var2) {
            LOG.error("Unable to find JAAS classes:" + var2.getMessage());
            return null;
        }
    }


    private static String prependFileAuthority(String keytabPath) {
        return keytabPath.startsWith("file://") ? keytabPath : "file://" + keytabPath;
    }

    private static LoginContext newLoginContext(String appName, Subject subject, javax.security.auth.login.Configuration loginConf) throws LoginException {
        Thread t = Thread.currentThread();
        ClassLoader oldCCL = t.getContextClassLoader();
        t.setContextClassLoader(UserGroupInformation.HadoopLoginModule.class.getClassLoader());

        LoginContext var5;
        try {
            var5 = new LoginContext(appName, subject, (CallbackHandler)null, loginConf);
        } finally {
            t.setContextClassLoader(oldCCL);
        }

        return var5;
    }

    private LoginContext getLogin() {
        return this.user.getLogin();
    }

    private void setLogin(LoginContext login) {
        this.user.setLogin(login);
    }

    UserGroupInformation(Subject subject) {
        this(subject, false);
    }

    private UserGroupInformation(Subject subject, boolean externalKeyTab) {
        this.subject = subject;
        this.user = (User)subject.getPrincipals(User.class).iterator().next();
        if (externalKeyTab) {
            this.isKeytab = false;
        } else {
            this.isKeytab = !subject.getPrivateCredentials(KeyTab.class).isEmpty();
        }

        this.isKrbTkt = !subject.getPrivateCredentials(KerberosTicket.class).isEmpty();
    }

    public boolean hasKerberosCredentials() {
        return this.isKeytab || this.isKrbTkt;
    }

    @Public
    @Evolving
    public static synchronized UserGroupInformation getCurrentUser() throws IOException {
        AccessControlContext context = AccessController.getContext();
        Subject subject = Subject.getSubject(context);
        return subject != null && !subject.getPrincipals(User.class).isEmpty() ? new UserGroupInformation(subject) : getLoginUser();
    }

    public static UserGroupInformation getBestUGI(String ticketCachePath, String user) throws IOException {
        if (ticketCachePath != null) {
            return getUGIFromTicketCache(ticketCachePath, user);
        } else {
            return user == null ? getCurrentUser() : createRemoteUser(user);
        }
    }

    @Public
    @Evolving
    public static UserGroupInformation getUGIFromTicketCache(String ticketCache, String user) throws IOException {
        if (!isAuthenticationMethodEnabled(UserGroupInformation.AuthenticationMethod.KERBEROS)) {
            return getBestUGI((String)null, user);
        } else {
            try {
                Map<String, String> krbOptions = new HashMap();
                if (PlatformName.IBM_JAVA) {
                    krbOptions.put("useDefaultCcache", "true");
                    System.setProperty("KRB5CCNAME", ticketCache);
                } else {
                    krbOptions.put("doNotPrompt", "true");
                    krbOptions.put("useTicketCache", "true");
                    krbOptions.put("useKeyTab", "false");
                    krbOptions.put("ticketCache", ticketCache);
                }

                krbOptions.put("renewTGT", "false");
                krbOptions.putAll(UserGroupInformation.HadoopConfiguration.BASIC_JAAS_OPTIONS);
                AppConfigurationEntry ace = new AppConfigurationEntry(KerberosUtil.getKrb5LoginModuleName(), LoginModuleControlFlag.REQUIRED, krbOptions);
                UserGroupInformation.DynamicConfiguration dynConf = new UserGroupInformation.DynamicConfiguration(new AppConfigurationEntry[]{ace});
                LoginContext login = newLoginContext("hadoop-user-kerberos", (Subject)null, dynConf);
                login.login();
                Subject loginSubject = login.getSubject();
                Set<Principal> loginPrincipals = loginSubject.getPrincipals();
                if (loginPrincipals.isEmpty()) {
                    throw new RuntimeException("No login principals found!");
                } else {
                    if (loginPrincipals.size() != 1) {
                        LOG.warn("found more than one principal in the ticket cache file " + ticketCache);
                    }

                    User ugiUser = new User(((Principal)loginPrincipals.iterator().next()).getName(), UserGroupInformation.AuthenticationMethod.KERBEROS, login);
                    loginSubject.getPrincipals().add(ugiUser);
                    UserGroupInformation ugi = new UserGroupInformation(loginSubject);
                    ugi.setLogin(login);
                    ugi.setAuthenticationMethod(UserGroupInformation.AuthenticationMethod.KERBEROS);
                    return ugi;
                }
            } catch (LoginException var10) {
                throw new IOException("failure to login using ticket cache file " + ticketCache, var10);
            }
        }
    }

    public static UserGroupInformation getUGIFromSubject(Subject subject) throws IOException {
        if (subject == null) {
            throw new IOException("Subject must not be null");
        } else if (subject.getPrincipals(KerberosPrincipal.class).isEmpty()) {
            throw new IOException("Provided Subject must contain a KerberosPrincipal");
        } else {
            KerberosPrincipal principal = (KerberosPrincipal)subject.getPrincipals(KerberosPrincipal.class).iterator().next();
            User ugiUser = new User(principal.getName(), UserGroupInformation.AuthenticationMethod.KERBEROS, (LoginContext)null);
            subject.getPrincipals().add(ugiUser);
            UserGroupInformation ugi = new UserGroupInformation(subject);
            ugi.setLogin((LoginContext)null);
            ugi.setAuthenticationMethod(UserGroupInformation.AuthenticationMethod.KERBEROS);
            return ugi;
        }
    }

    @Public
    @Evolving
    public static synchronized UserGroupInformation getLoginUser() throws IOException {
        if (loginUser == null) {
            loginUserFromSubject((Subject)null);
        }

        return loginUser;
    }

    public static String trimLoginMethod(String userName) {
        int spaceIndex = userName.indexOf(32);
        if (spaceIndex >= 0) {
            userName = userName.substring(0, spaceIndex);
        }

        return userName;
    }

    @Public
    @Evolving
    public static synchronized void loginUserFromSubject(Subject subject) throws IOException {
        ensureInitialized();

        try {
            if (subject == null) {
                subject = new Subject();
            }

            LoginContext login = newLoginContext(authenticationMethod.getLoginAppName(), subject, new UserGroupInformation.HadoopConfiguration());
            login.login();
            LOG.debug("Assuming keytab is managed externally since logged in from subject.");
            UserGroupInformation realUser = new UserGroupInformation(subject, true);
            realUser.setLogin(login);
            realUser.setAuthenticationMethod(authenticationMethod);
            String proxyUser = System.getenv("HADOOP_PROXY_USER");
            if (proxyUser == null) {
                proxyUser = System.getProperty("HADOOP_PROXY_USER");
            }

            loginUser = proxyUser == null ? realUser : createProxyUser(proxyUser, realUser);
            String fileLocation = System.getenv("HADOOP_TOKEN_FILE_LOCATION");
            if (fileLocation != null) {
                Credentials cred = Credentials.readTokenStorageFile(new File(fileLocation), conf);
                loginUser.addCredentials(cred);
            }

            loginUser.spawnAutoRenewalThreadForUserCreds();
        } catch (LoginException var6) {
            LOG.debug("failure to login", var6);
            throw new IOException("failure to login", var6);
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("UGI loginUser:" + loginUser);
        }

    }

    @Private
    @Unstable
    @VisibleForTesting
    public static synchronized void setLoginUser(UserGroupInformation ugi) {
        loginUser = ugi;
    }

    public boolean isFromKeytab() {
        return this.isKeytab;
    }

    private synchronized KerberosTicket getTGT() {
        Set<KerberosTicket> tickets = this.subject.getPrivateCredentials(KerberosTicket.class);
        Iterator var2 = tickets.iterator();

        KerberosTicket ticket;
        do {
            if (!var2.hasNext()) {
                return null;
            }

            ticket = (KerberosTicket)var2.next();
        } while(!SecurityUtil.isOriginalTGT(ticket));

        if (LOG.isDebugEnabled()) {
            LOG.debug("Found tgt " + ticket);
        }

        return ticket;
    }

    private long getRefreshTime(KerberosTicket tgt) {
        long start = tgt.getStartTime().getTime();
        long end = tgt.getEndTime().getTime();
        return start + (long)((float)(end - start) * 0.8F);
    }

    private void spawnAutoRenewalThreadForUserCreds() {
        if (isSecurityEnabled() && this.user.getAuthenticationMethod() == UserGroupInformation.AuthenticationMethod.KERBEROS && !this.isKeytab) {
            Thread t = new Thread(new Runnable() {
                public void run() {
                    String cmd = UserGroupInformation.conf.get("hadoop.kerberos.kinit.command", "kinit");
                    KerberosTicket tgt = UserGroupInformation.this.getTGT();
                    if (tgt != null) {
                        long nextRefresh = UserGroupInformation.this.getRefreshTime(tgt);

                        while(true) {
                            try {
                                long now = Time.now();
                                if (UserGroupInformation.LOG.isDebugEnabled()) {
                                    UserGroupInformation.LOG.debug("Current time is " + now);
                                    UserGroupInformation.LOG.debug("Next refresh is " + nextRefresh);
                                }

                                if (now < nextRefresh) {
                                    Thread.sleep(nextRefresh - now);
                                }

                                Shell.execCommand(new String[]{cmd, "-R"});
                                if (UserGroupInformation.LOG.isDebugEnabled()) {
                                    UserGroupInformation.LOG.debug("renewed ticket");
                                }

                                UserGroupInformation.this.reloginFromTicketCache();
                                tgt = UserGroupInformation.this.getTGT();
                                if (tgt == null) {
                                    UserGroupInformation.LOG.warn("No TGT after renewal. Aborting renew thread for " + UserGroupInformation.this.getUserName());
                                    return;
                                }

                                nextRefresh = Math.max(UserGroupInformation.this.getRefreshTime(tgt), now + 600000L);
                            } catch (InterruptedException var8) {
                                UserGroupInformation.LOG.warn("Terminating renewal thread");
                                return;
                            } catch (IOException var9) {
                                UserGroupInformation.LOG.warn("Exception encountered while running the renewal command. Aborting renew thread. " + var9);
                                return;
                            }
                        }
                    }
                }
            });
            t.setDaemon(true);
            t.setName("TGT Renewer for " + this.getUserName());
            t.start();
        }

    }

    /**
     * Log a user in from a keytab file. Loads a user identity from a keytab
     * file and logs them in. They become the currently logged-in user.
     *  TODO 通过修改当前ugi的keytabFile和keytabPrincipal让指定keytabPrincipal变成当前用户，这在多租户场景下会造成用户错乱
     *    该方法和loginUserFromKeytabAndReturnUGI的区别在于后者是新建一个ugi并返回，不影响当前ugi，而前者是直接修改当前ugi
     * @param user the principal name to load from the keytab
     * @param path the path to the keytab file
     * @throws IOException if the keytab file can't be read
     */
    @Public
    @Evolving
    public static synchronized void loginUserFromKeytab(String user, String path) throws IOException {
        if (isSecurityEnabled()) {
            keytabFile = path;
            keytabPrincipal = user;
            Subject subject = new Subject();
            long start = 0L;

            try {
                LoginContext login = newLoginContext("hadoop-keytab-kerberos", subject, new UserGroupInformation.HadoopConfiguration());
                start = Time.now();
                login.login();
                metrics.loginSuccess.add(Time.now() - start);
                loginUser = new UserGroupInformation(subject);
                loginUser.setLogin(login);
                loginUser.setAuthenticationMethod(UserGroupInformation.AuthenticationMethod.KERBEROS);
            } catch (LoginException var7) {
                if (start > 0L) {
                    metrics.loginFailure.add(Time.now() - start);
                }

                throw new IOException("Login failure for " + user + " from keytab " + path + ": " + var7, var7);
            }

            LOG.info("Login successful for user " + keytabPrincipal + " using keytab file " + keytabFile);
        }
    }

    @Public
    @Evolving
    public void logoutUserFromKeytab() throws IOException {
        if (isSecurityEnabled() && this.user.getAuthenticationMethod() == UserGroupInformation.AuthenticationMethod.KERBEROS) {
            LoginContext login = this.getLogin();
            if (login != null && keytabFile != null) {
                try {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Initiating logout for " + this.getUserName());
                    }

                    Class var2 = UserGroupInformation.class;
                    synchronized(UserGroupInformation.class) {
                        login.logout();
                    }
                } catch (LoginException var5) {
                    throw new IOException("Logout failure for " + this.user + " from keytab " + keytabFile, var5);
                }

                LOG.info("Logout successful for user " + keytabPrincipal + " using keytab file " + keytabFile);
            } else {
                throw new IOException("loginUserFromKeytab must be done first");
            }
        }
    }

    public synchronized void checkTGTAndReloginFromKeytab() throws IOException {
        if (isSecurityEnabled() && this.user.getAuthenticationMethod() == UserGroupInformation.AuthenticationMethod.KERBEROS && this.isKeytab) {
            KerberosTicket tgt = this.getTGT();
            if (tgt == null || shouldRenewImmediatelyForTests || Time.now() >= this.getRefreshTime(tgt)) {
                this.reloginFromKeytab();
            }
        }
    }

    private void fixKerberosTicketOrder() {
        Set<Object> creds = this.getSubject().getPrivateCredentials();
        synchronized(creds) {
            Iterator iter = creds.iterator();

            while(iter.hasNext()) {
                Object cred = iter.next();
                if (cred instanceof KerberosTicket) {
                    KerberosTicket ticket = (KerberosTicket)cred;
                    if (ticket.getServer().getName().startsWith("krbtgt")) {
                        return;
                    }

                    LOG.warn("The first kerberos ticket is not TGT(the server principal is " + ticket.getServer() + "), remove" + " and destroy it.");
                    iter.remove();

                    try {
                        ticket.destroy();
                    } catch (DestroyFailedException var8) {
                        LOG.warn("destroy ticket failed", var8);
                    }
                }
            }
        }

        LOG.warn("Warning, no kerberos ticket found while attempting to renew ticket");
    }

    @Public
    @Evolving
    public synchronized void reloginFromKeytab() throws IOException {
        if (isSecurityEnabled() && this.user.getAuthenticationMethod() == UserGroupInformation.AuthenticationMethod.KERBEROS && this.isKeytab) {
            long now = Time.now();
            if (shouldRenewImmediatelyForTests || this.hasSufficientTimeElapsed(now)) {
                KerberosTicket tgt = this.getTGT();
                if (tgt == null || shouldRenewImmediatelyForTests || now >= this.getRefreshTime(tgt)) {
                    LoginContext login = this.getLogin();
                    if (login != null && keytabFile != null) {
                        long start = 0L;
                        this.user.setLastLogin(now);

                        try {
                            if (LOG.isDebugEnabled()) {
                                LOG.debug("Initiating logout for " + this.getUserName());
                            }

                            Class var7 = UserGroupInformation.class;
                            synchronized(UserGroupInformation.class) {
                                login.logout();
                                login = newLoginContext("hadoop-keytab-kerberos", this.getSubject(), new UserGroupInformation.HadoopConfiguration());
                                if (LOG.isDebugEnabled()) {
                                    LOG.debug("Initiating re-login for " + keytabPrincipal);
                                }

                                start = Time.now();
                                login.login();
                                this.fixKerberosTicketOrder();
                                metrics.loginSuccess.add(Time.now() - start);
                                this.setLogin(login);
                            }
                        } catch (LoginException var10) {
                            if (start > 0L) {
                                metrics.loginFailure.add(Time.now() - start);
                            }

                            throw new IOException("Login failure for " + keytabPrincipal + " from keytab " + keytabFile, var10);
                        }
                    } else {
                        throw new IOException("loginUserFromKeyTab must be done first");
                    }
                }
            }
        }
    }

    @Public
    @Evolving
    public synchronized void reloginFromTicketCache() throws IOException {
        if (isSecurityEnabled() && this.user.getAuthenticationMethod() == UserGroupInformation.AuthenticationMethod.KERBEROS && this.isKrbTkt) {
            LoginContext login = this.getLogin();
            if (login == null) {
                throw new IOException("login must be done first");
            } else {
                long now = Time.now();
                if (this.hasSufficientTimeElapsed(now)) {
                    this.user.setLastLogin(now);

                    try {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Initiating logout for " + this.getUserName());
                        }

                        login.logout();
                        login = newLoginContext("hadoop-user-kerberos", this.getSubject(), new UserGroupInformation.HadoopConfiguration());
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Initiating re-login for " + this.getUserName());
                        }

                        login.login();
                        this.fixKerberosTicketOrder();
                        this.setLogin(login);
                    } catch (LoginException var5) {
                        throw new IOException("Login failure for " + this.getUserName(), var5);
                    }
                }
            }
        }
    }

    /**
     * Log a user in from a keytab file. Loads a user identity from a keytab
     * file and login them in. This new user does not affect the currently
     * logged-in user.(TODO 注意这一句：新用户不影响当前登陆的用户(因为会还原过来)）
     * @param user the principal name to load from the keytab
     * @param path the path to the keytab file
     * @throws IOException if the keytab file can't be read
     */
    public static synchronized UserGroupInformation loginUserFromKeytabAndReturnUGI(String user, String path) throws IOException {
        if (!isSecurityEnabled()) {
            return getCurrentUser();
        } else {
            String oldKeytabFile = null;
            String oldKeytabPrincipal = null;
            long start = 0L;

            UserGroupInformation var9;
            try {
                // TODO 保存老的keytabFile
                oldKeytabFile = keytabFile;
                // TODO 保存老的 keytabPrincipal
                oldKeytabPrincipal = keytabPrincipal;
                keytabFile = path;
                keytabPrincipal = user;
                Subject subject = new Subject();
                LoginContext login = newLoginContext("hadoop-keytab-kerberos", subject, new UserGroupInformation.HadoopConfiguration());
                start = Time.now();
                login.login();
                metrics.loginSuccess.add(Time.now() - start);
                // TODO 基于新的keytabFile和keytabPrincipal构建新的ugi
                UserGroupInformation newLoginUser = new UserGroupInformation(subject);
                newLoginUser.setLogin(login);
                newLoginUser.setAuthenticationMethod(UserGroupInformation.AuthenticationMethod.KERBEROS);
                var9 = newLoginUser;
            } catch (LoginException var13) {
                if (start > 0L) {
                    metrics.loginFailure.add(Time.now() - start);
                }

                throw new IOException("Login failure for " + user + " from keytab " + path, var13);
            } finally {
                // TODO 还原老的keytabFile和keytabPrincipal，这样就保证类对歌ugi同时工作，满足多租户场景
                if (oldKeytabFile != null) {
                    keytabFile = oldKeytabFile;
                }

                if (oldKeytabPrincipal != null) {
                    keytabPrincipal = oldKeytabPrincipal;
                }

            }

            return var9;
        }
    }

    private boolean hasSufficientTimeElapsed(long now) {
        if (now - this.user.getLastLogin() < 600000L) {
            LOG.warn("Not attempting to re-login since the last re-login was attempted less than 600 seconds before. Last Login=" + this.user.getLastLogin());
            return false;
        } else {
            return true;
        }
    }

    @Public
    @Evolving
    public static synchronized boolean isLoginKeytabBased() throws IOException {
        return getLoginUser().isKeytab;
    }

    public static boolean isLoginTicketBased() throws IOException {
        return getLoginUser().isKrbTkt;
    }

    @Public
    @Evolving
    public static UserGroupInformation createRemoteUser(String user) {
        return createRemoteUser(user, AuthMethod.SIMPLE);
    }

    @Public
    @Evolving
    public static UserGroupInformation createRemoteUser(String user, AuthMethod authMethod) {
        if (user != null && !user.isEmpty()) {
            Subject subject = new Subject();
            subject.getPrincipals().add(new User(user));
            UserGroupInformation result = new UserGroupInformation(subject);
            result.setAuthenticationMethod(authMethod);
            return result;
        } else {
            throw new IllegalArgumentException("Null user");
        }
    }

    @Public
    @Evolving
    public static UserGroupInformation createProxyUser(String user, UserGroupInformation realUser) {
        if (user != null && !user.isEmpty()) {
            if (realUser == null) {
                throw new IllegalArgumentException("Null real user");
            } else {
                Subject subject = new Subject();
                Set<Principal> principals = subject.getPrincipals();
                principals.add(new User(user));
                principals.add(new UserGroupInformation.RealUser(realUser));
                UserGroupInformation result = new UserGroupInformation(subject);
                result.setAuthenticationMethod(UserGroupInformation.AuthenticationMethod.PROXY);
                return result;
            }
        } else {
            throw new IllegalArgumentException("Null user");
        }
    }

    @Public
    @Evolving
    public UserGroupInformation getRealUser() {
        Iterator var1 = this.subject.getPrincipals(UserGroupInformation.RealUser.class).iterator();
        if (var1.hasNext()) {
            UserGroupInformation.RealUser p = (UserGroupInformation.RealUser)var1.next();
            return p.getRealUser();
        } else {
            return null;
        }
    }

    @Public
    @Evolving
    public static UserGroupInformation createUserForTesting(String user, String[] userGroups) {
        ensureInitialized();
        UserGroupInformation ugi = createRemoteUser(user);
        if (!(groups instanceof UserGroupInformation.TestingGroups)) {
            groups = new UserGroupInformation.TestingGroups(groups);
        }

        ((UserGroupInformation.TestingGroups)groups).setUserGroups(ugi.getShortUserName(), userGroups);
        return ugi;
    }

    public static UserGroupInformation createProxyUserForTesting(String user, UserGroupInformation realUser, String[] userGroups) {
        ensureInitialized();
        UserGroupInformation ugi = createProxyUser(user, realUser);
        if (!(groups instanceof UserGroupInformation.TestingGroups)) {
            groups = new UserGroupInformation.TestingGroups(groups);
        }

        ((UserGroupInformation.TestingGroups)groups).setUserGroups(ugi.getShortUserName(), userGroups);
        return ugi;
    }

    public String getShortUserName() {
        Iterator var1 = this.subject.getPrincipals(User.class).iterator();
        if (var1.hasNext()) {
            User p = (User)var1.next();
            return p.getShortName();
        } else {
            return null;
        }
    }

    public String getPrimaryGroupName() throws IOException {
        List<String> groups = this.getGroups();
        if (groups.isEmpty()) {
            throw new IOException("There is no primary group for UGI " + this);
        } else {
            return (String)groups.get(0);
        }
    }

    @Public
    @Evolving
    public String getUserName() {
        return this.user.getName();
    }

    public synchronized boolean addTokenIdentifier(TokenIdentifier tokenId) {
        return this.subject.getPublicCredentials().add(tokenId);
    }

    public synchronized Set<TokenIdentifier> getTokenIdentifiers() {
        return this.subject.getPublicCredentials(TokenIdentifier.class);
    }

    public boolean addToken(Token<? extends TokenIdentifier> token) {
        return token != null ? this.addToken(token.getService(), token) : false;
    }

    public boolean addToken(Text alias, Token<? extends TokenIdentifier> token) {
        synchronized(this.subject) {
            this.getCredentialsInternal().addToken(alias, token);
            return true;
        }
    }

    public Collection<Token<? extends TokenIdentifier>> getTokens() {
        synchronized(this.subject) {
            return Collections.unmodifiableCollection(new ArrayList(this.getCredentialsInternal().getAllTokens()));
        }
    }

    public Credentials getCredentials() {
        synchronized(this.subject) {
            Credentials creds = new Credentials(this.getCredentialsInternal());
            Iterator iter = creds.getAllTokens().iterator();

            while(iter.hasNext()) {
                if (iter.next() instanceof PrivateToken) {
                    iter.remove();
                }
            }

            return creds;
        }
    }

    public void addCredentials(Credentials credentials) {
        synchronized(this.subject) {
            this.getCredentialsInternal().addAll(credentials);
        }
    }

    private synchronized Credentials getCredentialsInternal() {
        Set<Credentials> credentialsSet = this.subject.getPrivateCredentials(Credentials.class);
        Credentials credentials;
        if (!credentialsSet.isEmpty()) {
            credentials = (Credentials)credentialsSet.iterator().next();
        } else {
            credentials = new Credentials();
            this.subject.getPrivateCredentials().add(credentials);
        }

        return credentials;
    }

    public String[] getGroupNames() {
        List<String> groups = this.getGroups();
        return (String[])groups.toArray(new String[groups.size()]);
    }

    public List<String> getGroups() {
        ensureInitialized();

        try {
            return groups.getGroups(this.getShortUserName());
        } catch (IOException var2) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Failed to get groups for user " + this.getShortUserName() + " by " + var2);
                LOG.trace("TRACE", var2);
            }

            return Collections.emptyList();
        }
    }

    public String toString() {
        StringBuilder sb = new StringBuilder(this.getUserName());
        sb.append(" (auth:" + this.getAuthenticationMethod() + ")");
        if (this.getRealUser() != null) {
            sb.append(" via ").append(this.getRealUser().toString());
        }

        return sb.toString();
    }

    public synchronized void setAuthenticationMethod(UserGroupInformation.AuthenticationMethod authMethod) {
        this.user.setAuthenticationMethod(authMethod);
    }

    public void setAuthenticationMethod(AuthMethod authMethod) {
        this.user.setAuthenticationMethod(UserGroupInformation.AuthenticationMethod.valueOf(authMethod));
    }

    public synchronized UserGroupInformation.AuthenticationMethod getAuthenticationMethod() {
        return this.user.getAuthenticationMethod();
    }

    public synchronized UserGroupInformation.AuthenticationMethod getRealAuthenticationMethod() {
        UserGroupInformation ugi = this.getRealUser();
        if (ugi == null) {
            ugi = this;
        }

        return ugi.getAuthenticationMethod();
    }

    public static UserGroupInformation.AuthenticationMethod getRealAuthenticationMethod(UserGroupInformation ugi) {
        UserGroupInformation.AuthenticationMethod authMethod = ugi.getAuthenticationMethod();
        if (authMethod == UserGroupInformation.AuthenticationMethod.PROXY) {
            authMethod = ugi.getRealUser().getAuthenticationMethod();
        }

        return authMethod;
    }

    public boolean equals(Object o) {
        if (o == this) {
            return true;
        } else if (o != null && this.getClass() == o.getClass()) {
            return this.subject == ((UserGroupInformation)o).subject;
        } else {
            return false;
        }
    }

    public int hashCode() {
        return System.identityHashCode(this.subject);
    }

    protected Subject getSubject() {
        return this.subject;
    }

    @Public
    @Evolving
    public <T> T doAs(PrivilegedAction<T> action) {
        this.logPrivilegedAction(this.subject, action);
        return Subject.doAs(this.subject, action);
    }

    @Public
    @Evolving
    public <T> T doAs(PrivilegedExceptionAction<T> action) throws IOException, InterruptedException {
        try {
            this.logPrivilegedAction(this.subject, action);
            return Subject.doAs(this.subject, action);
        } catch (PrivilegedActionException var4) {
            Throwable cause = var4.getCause();
            if (LOG.isDebugEnabled()) {
                LOG.debug("PrivilegedActionException as:" + this + " cause:" + cause);
            }

            if (cause instanceof IOException) {
                throw (IOException)cause;
            } else if (cause instanceof Error) {
                throw (Error)cause;
            } else if (cause instanceof RuntimeException) {
                throw (RuntimeException)cause;
            } else if (cause instanceof InterruptedException) {
                throw (InterruptedException)cause;
            } else {
                throw new UndeclaredThrowableException(cause);
            }
        }
    }

    private void logPrivilegedAction(Subject subject, Object action) {
        if (LOG.isDebugEnabled()) {
            String where = (new Throwable()).getStackTrace()[2].toString();
            LOG.debug("PrivilegedAction as:" + this + " from:" + where);
        }

    }

    private void print() throws IOException {
        System.out.println("User: " + this.getUserName());
        System.out.print("Group Ids: ");
        System.out.println();
        String[] groups = this.getGroupNames();
        System.out.print("Groups: ");

        for(int i = 0; i < groups.length; ++i) {
            System.out.print(groups[i] + " ");
        }

        System.out.println();
    }

    public static void main(String[] args) throws Exception {
        System.out.println("Getting UGI for current user");
        UserGroupInformation ugi = getCurrentUser();
        ugi.print();
        System.out.println("UGI: " + ugi);
        System.out.println("Auth method " + ugi.user.getAuthenticationMethod());
        System.out.println("Keytab " + ugi.isKeytab);
        System.out.println("============================================================");
        if (args.length == 2) {
            System.out.println("Getting UGI from keytab....");
            loginUserFromKeytab(args[0], args[1]);
            getCurrentUser().print();
            System.out.println("Keytab: " + ugi);
            System.out.println("Auth method " + loginUser.user.getAuthenticationMethod());
            System.out.println("Keytab " + loginUser.isKeytab);
        }

    }

    private static class TestingGroups extends Groups {
        private final Map<String, List<String>> userToGroupsMapping;
        private Groups underlyingImplementation;

        private TestingGroups(Groups underlyingImplementation) {
            super(new Configuration());
            this.userToGroupsMapping = new HashMap();
            this.underlyingImplementation = underlyingImplementation;
        }

        public List<String> getGroups(String user) throws IOException {
            List<String> result = (List)this.userToGroupsMapping.get(user);
            if (result == null) {
                result = this.underlyingImplementation.getGroups(user);
            }

            return result;
        }

        private void setUserGroups(String user, String[] groups) {
            this.userToGroupsMapping.put(user, Arrays.asList(groups));
        }
    }

    @Public
    @Evolving
    public static enum AuthenticationMethod {
        SIMPLE(AuthMethod.SIMPLE, "hadoop-simple"),
        KERBEROS(AuthMethod.KERBEROS, "hadoop-user-kerberos"),
        TOKEN(AuthMethod.TOKEN),
        CERTIFICATE((AuthMethod)null),
        KERBEROS_SSL((AuthMethod)null),
        PROXY((AuthMethod)null);

        private final AuthMethod authMethod;
        private final String loginAppName;

        private AuthenticationMethod(AuthMethod authMethod) {
            this(authMethod, (String)null);
        }

        private AuthenticationMethod(AuthMethod authMethod, String loginAppName) {
            this.authMethod = authMethod;
            this.loginAppName = loginAppName;
        }

        public AuthMethod getAuthMethod() {
            return this.authMethod;
        }

        String getLoginAppName() {
            if (this.loginAppName == null) {
                throw new UnsupportedOperationException(this + " login authentication is not supported");
            } else {
                return this.loginAppName;
            }
        }

        public static UserGroupInformation.AuthenticationMethod valueOf(AuthMethod authMethod) {
            UserGroupInformation.AuthenticationMethod[] var1 = values();
            int var2 = var1.length;

            for(int var3 = 0; var3 < var2; ++var3) {
                UserGroupInformation.AuthenticationMethod value = var1[var3];
                if (value.getAuthMethod() == authMethod) {
                    return value;
                }
            }

            throw new IllegalArgumentException("no authentication method for " + authMethod);
        }
    }

    private static class DynamicConfiguration extends javax.security.auth.login.Configuration {
        private AppConfigurationEntry[] ace;

        DynamicConfiguration(AppConfigurationEntry[] ace) {
            this.ace = ace;
        }

        public AppConfigurationEntry[] getAppConfigurationEntry(String appName) {
            return this.ace;
        }
    }

    private static class HadoopConfiguration extends javax.security.auth.login.Configuration {
        private static final String SIMPLE_CONFIG_NAME = "hadoop-simple";
        private static final String USER_KERBEROS_CONFIG_NAME = "hadoop-user-kerberos";
        private static final String KEYTAB_KERBEROS_CONFIG_NAME = "hadoop-keytab-kerberos";
        private static final Map<String, String> BASIC_JAAS_OPTIONS = new HashMap();
        private static final AppConfigurationEntry OS_SPECIFIC_LOGIN;
        private static final AppConfigurationEntry HADOOP_LOGIN;
        private static final Map<String, String> USER_KERBEROS_OPTIONS;
        private static final AppConfigurationEntry USER_KERBEROS_LOGIN;
        private static final Map<String, String> KEYTAB_KERBEROS_OPTIONS;
        private static final AppConfigurationEntry KEYTAB_KERBEROS_LOGIN;
        private static final AppConfigurationEntry[] SIMPLE_CONF;
        private static final AppConfigurationEntry[] USER_KERBEROS_CONF;
        private static final AppConfigurationEntry[] KEYTAB_KERBEROS_CONF;

        private HadoopConfiguration() {
        }

        public AppConfigurationEntry[] getAppConfigurationEntry(String appName) {
            if ("hadoop-simple".equals(appName)) {
                return SIMPLE_CONF;
            } else if ("hadoop-user-kerberos".equals(appName)) {
                return USER_KERBEROS_CONF;
            } else if ("hadoop-keytab-kerberos".equals(appName)) {
                if (PlatformName.IBM_JAVA) {
                    KEYTAB_KERBEROS_OPTIONS.put("useKeytab", UserGroupInformation.prependFileAuthority(UserGroupInformation.keytabFile));
                } else {
                    KEYTAB_KERBEROS_OPTIONS.put("keyTab", UserGroupInformation.keytabFile);
                }

                KEYTAB_KERBEROS_OPTIONS.put("principal", UserGroupInformation.keytabPrincipal);
                return KEYTAB_KERBEROS_CONF;
            } else {
                return null;
            }
        }

        static {
            String ticketCache = System.getenv("HADOOP_JAAS_DEBUG");
            if (ticketCache != null && "true".equalsIgnoreCase(ticketCache)) {
                BASIC_JAAS_OPTIONS.put("debug", "true");
            }

            OS_SPECIFIC_LOGIN = new AppConfigurationEntry(UserGroupInformation.OS_LOGIN_MODULE_NAME, LoginModuleControlFlag.REQUIRED, BASIC_JAAS_OPTIONS);
            HADOOP_LOGIN = new AppConfigurationEntry(UserGroupInformation.HadoopLoginModule.class.getName(), LoginModuleControlFlag.REQUIRED, BASIC_JAAS_OPTIONS);
            USER_KERBEROS_OPTIONS = new HashMap();
            if (PlatformName.IBM_JAVA) {
                USER_KERBEROS_OPTIONS.put("useDefaultCcache", "true");
            } else {
                USER_KERBEROS_OPTIONS.put("doNotPrompt", "true");
                USER_KERBEROS_OPTIONS.put("useTicketCache", "true");
            }

            ticketCache = System.getenv("KRB5CCNAME");
            if (ticketCache != null) {
                if (PlatformName.IBM_JAVA) {
                    System.setProperty("KRB5CCNAME", ticketCache);
                } else {
                    USER_KERBEROS_OPTIONS.put("ticketCache", ticketCache);
                }
            }

            USER_KERBEROS_OPTIONS.put("renewTGT", "true");
            USER_KERBEROS_OPTIONS.putAll(BASIC_JAAS_OPTIONS);
            USER_KERBEROS_LOGIN = new AppConfigurationEntry(KerberosUtil.getKrb5LoginModuleName(), LoginModuleControlFlag.OPTIONAL, USER_KERBEROS_OPTIONS);
            KEYTAB_KERBEROS_OPTIONS = new HashMap();
            if (PlatformName.IBM_JAVA) {
                KEYTAB_KERBEROS_OPTIONS.put("credsType", "both");
            } else {
                KEYTAB_KERBEROS_OPTIONS.put("doNotPrompt", "true");
                KEYTAB_KERBEROS_OPTIONS.put("useKeyTab", "true");
                KEYTAB_KERBEROS_OPTIONS.put("storeKey", "true");
            }

            KEYTAB_KERBEROS_OPTIONS.put("refreshKrb5Config", "true");
            KEYTAB_KERBEROS_OPTIONS.putAll(BASIC_JAAS_OPTIONS);
            KEYTAB_KERBEROS_LOGIN = new AppConfigurationEntry(KerberosUtil.getKrb5LoginModuleName(), LoginModuleControlFlag.REQUIRED, KEYTAB_KERBEROS_OPTIONS);
            SIMPLE_CONF = new AppConfigurationEntry[]{OS_SPECIFIC_LOGIN, HADOOP_LOGIN};
            USER_KERBEROS_CONF = new AppConfigurationEntry[]{OS_SPECIFIC_LOGIN, USER_KERBEROS_LOGIN, HADOOP_LOGIN};
            KEYTAB_KERBEROS_CONF = new AppConfigurationEntry[]{KEYTAB_KERBEROS_LOGIN, HADOOP_LOGIN};
        }
    }

    private static class RealUser implements Principal {
        private final UserGroupInformation realUser;

        RealUser(UserGroupInformation realUser) {
            this.realUser = realUser;
        }

        public String getName() {
            return this.realUser.getUserName();
        }

        public UserGroupInformation getRealUser() {
            return this.realUser;
        }

        public boolean equals(Object o) {
            if (this == o) {
                return true;
            } else {
                return o != null && this.getClass() == o.getClass() ? this.realUser.equals(((UserGroupInformation.RealUser)o).realUser) : false;
            }
        }

        public int hashCode() {
            return this.realUser.hashCode();
        }

        public String toString() {
            return this.realUser.toString();
        }
    }

    @Private
    public static class HadoopLoginModule implements LoginModule {
        private Subject subject;

        public HadoopLoginModule() {
        }

        public boolean abort() throws LoginException {
            return true;
        }

        private <T extends Principal> T getCanonicalUser(Class<T> cls) {
            for(T user: subject.getPrincipals(cls)) {
                return user;
            }
            return null;
        }

        public boolean commit() throws LoginException {
            if (UserGroupInformation.LOG.isDebugEnabled()) {
                UserGroupInformation.LOG.debug("hadoop login commit");
            }

            if (!this.subject.getPrincipals(User.class).isEmpty()) {
                if (UserGroupInformation.LOG.isDebugEnabled()) {
                    UserGroupInformation.LOG.debug("using existing subject:" + this.subject.getPrincipals());
                }

                return true;
            } else {
                Principal user = null;
                if (UserGroupInformation.isAuthenticationMethodEnabled(UserGroupInformation.AuthenticationMethod.KERBEROS)) {
                    user = this.getCanonicalUser(KerberosPrincipal.class);
                    if (UserGroupInformation.LOG.isDebugEnabled()) {
                        UserGroupInformation.LOG.debug("using kerberos user:" + user);
                    }
                }

                String envUser;
                if (!UserGroupInformation.isSecurityEnabled() && user == null) {
                    envUser = System.getenv("HADOOP_USER_NAME");
                    if (envUser == null) {
                        envUser = System.getProperty("HADOOP_USER_NAME");
                    }

                    user = envUser == null ? null : new User(envUser);
                }

                if (user == null) {
                    user = this.getCanonicalUser(UserGroupInformation.OS_PRINCIPAL_CLASS);
                    if (UserGroupInformation.LOG.isDebugEnabled()) {
                        UserGroupInformation.LOG.debug("using local user:" + user);
                    }
                }

                if (user != null) {
                    if (UserGroupInformation.LOG.isDebugEnabled()) {
                        UserGroupInformation.LOG.debug("Using user: \"" + user + "\" with name " + ((Principal)user).getName());
                    }

                    envUser = null;

                    User userEntry;
                    try {
                        userEntry = new User(((Principal)user).getName());
                    } catch (Exception var4) {
                        throw (LoginException)((LoginException)(new LoginException(var4.toString())).initCause(var4));
                    }

                    if (UserGroupInformation.LOG.isDebugEnabled()) {
                        UserGroupInformation.LOG.debug("User entry: \"" + userEntry.toString() + "\"");
                    }

                    this.subject.getPrincipals().add(userEntry);
                    return true;
                } else {
                    UserGroupInformation.LOG.error("Can't find user in " + this.subject);
                    throw new LoginException("Can't find user name");
                }
            }
        }

        public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options) {
            this.subject = subject;
        }

        public boolean login() throws LoginException {
            if (UserGroupInformation.LOG.isDebugEnabled()) {
                UserGroupInformation.LOG.debug("hadoop login");
            }

            return true;
        }

        public boolean logout() throws LoginException {
            if (UserGroupInformation.LOG.isDebugEnabled()) {
                UserGroupInformation.LOG.debug("hadoop logout");
            }

            return true;
        }
    }

    @Metrics(
            about = "User and group related metrics",
            context = "ugi"
    )
    static class UgiMetrics {
        final MetricsRegistry registry = new MetricsRegistry("UgiMetrics");
        @Metric({"Rate of successful kerberos logins and latency (milliseconds)"})
        MutableRate loginSuccess;
        @Metric({"Rate of failed kerberos logins and latency (milliseconds)"})
        MutableRate loginFailure;
        @Metric({"GetGroups"})
        MutableRate getGroups;
        MutableQuantiles[] getGroupsQuantiles;

        UgiMetrics() {
        }

        static UserGroupInformation.UgiMetrics create() {
            return (UserGroupInformation.UgiMetrics)DefaultMetricsSystem.instance().register(new UserGroupInformation.UgiMetrics());
        }

        void addGetGroups(long latency) {
            this.getGroups.add(latency);
            if (this.getGroupsQuantiles != null) {
                MutableQuantiles[] var3 = this.getGroupsQuantiles;
                int var4 = var3.length;

                for(int var5 = 0; var5 < var4; ++var5) {
                    MutableQuantiles q = var3[var5];
                    q.add(latency);
                }
            }

        }
    }
}

